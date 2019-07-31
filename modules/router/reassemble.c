/*
 * Copyright 2019 Nippon Telegraph and Telephone Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <assert.h>
#include <time.h>

#include "reassemble.h"
#include "router.h"
#include "router_log.h"

#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>

#define IP_FRAG_TBL_BUCKET_ENTRIES 16

static int
reassemble_purge_expired_entry(struct rte_hash *hash) {
	time_t now = time(NULL);
	struct reassemble_key *key;
	time_t *data;
	uint32_t next = 0;
	int count = 0;

	while (rte_hash_iterate(hash, (const void **)&key, (void **)&data, &next) >= 0) {
		// entry is expired.
		if (*data < now) {
			if (rte_hash_del_key(hash, key) < 0) {
				ROUTER_ERROR("[REASSEMBLE] Failed to remove entry from hash.");
				// Don't break.
			}
			count++;
		}
	}

	ROUTER_DEBUG("[REASSEMBLE] Freed %d expired entries", count);
	return count;
}

static uint32_t
reassemble_hash_func(const void *key, uint32_t length, uint32_t initval) {
	uint32_t v;

	assert(length == 10);

	const struct reassemble_key *k = (struct reassemble_key *)key;
	v = rte_hash_crc_8byte(*(uint64_t *)k, initval);
	v = rte_hash_crc_2byte(k->packet_id, v);

	return v;
}

static inline void
create_key(struct rte_mbuf *mbuf, struct reassemble_key *key) {
	struct ipv4_hdr *ipv4 =
	    rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *, sizeof(struct ether_hdr));
	key->dst = ipv4->dst_addr;
	key->src = ipv4->src_addr;
	key->packet_id = ipv4->packet_id;
}

static bool
reassemble_delete_entry(struct rte_hash *hash, struct rte_mbuf *mbuf) {
	struct reassemble_key key;
	create_key(mbuf, &key);
	return (rte_hash_del_key(hash, &key) >= 0);
}

static bool
reassemble_add_entry(struct rte_hash *hash, struct rte_mbuf *mbuf) {
	struct reassemble_key key;
	create_key(mbuf, &key);
	struct vsw_packet_metadata *md = VSW_MBUF_METADATA(mbuf);
	struct router_mbuf_metadata *rmd = (struct router_mbuf_metadata *)&md->udata;
	// TODO: Should we set timer per RFC 791?
	rmd->reassemble_expire = time(NULL) + REASSEMBLE_AGING_TIME;
	int ret = rte_hash_add_key_data(hash, &key, &rmd->reassemble_expire);
	if (ret == -ENOSPC) {
		// If you do not have enough memory,
		// delete expired entries.
		if (reassemble_purge_expired_entry(hash) > 0) {
			ret = rte_hash_add_key(hash, &key);
			if (ret == -ENOSPC)
				return false;
		}
	}
	if (ret < 0) {
		ROUTER_ERROR("[REASSEMBLE] failed to add reassemble info(%d).", ret);
		return false;
	}
	return true;
}

/**
 * Get reassemble packet.
 */
static struct rte_mbuf *
reassemble_packet(struct rte_mbuf *in_mbuf, struct router_instance *ri) {
	struct rte_ip_frag_tbl *tbl = ri->frag_tbl;
	struct rte_ip_frag_death_row *dr = &ri->death_row;
	struct ipv4_hdr *ip =
	    rte_pktmbuf_mtod_offset(in_mbuf, struct ipv4_hdr *, sizeof(struct ether_hdr));

	// packet is fragmented, so try to reassemble.
	in_mbuf->l2_len = sizeof(struct ether_hdr);
	uint8_t header_len = ip->version_ihl & 0x0f;
	in_mbuf->l3_len = header_len * 4; // in 32 bit words

	uint64_t tms = rte_rdtsc();
	struct rte_mbuf *out_mbuf =
	    rte_ipv4_frag_reassemble_packet(tbl, dr, in_mbuf, tms, ip);
	if (out_mbuf == NULL) {
		// out_mbuf is NULL, fragments are not enough.
		ROUTER_DEBUG("[REASSEMBLE] no packet to send out(pkt len: %d).", in_mbuf->pkt_len);
		return NULL;
	}

	// reassemble success.
	ROUTER_DEBUG("[REASSEMBLE] packets are reassembled(pkt len: %d, segs; %d).",
		     in_mbuf->pkt_len, out_mbuf->nb_segs);

	out_mbuf->ol_flags &= ~PKT_TX_IP_CKSUM; // do not offload hw.

	rte_ip_frag_free_death_row(dr, 0); // no prefetch

	return out_mbuf;
}

/**
 * Reassemble fragmented packets.
 * If reassembly is successful, send it out.
 * If it can not be reassembled, wait for subsequent packets.
 */
void
reassemble_packet_process(struct router_instance *ri, struct rte_mbuf *mbuf) {
	struct reassemble_key key;
	create_key(mbuf, &key);
	time_t *expire;
	int ret = rte_hash_lookup_data(ri->reassemble_hash, (const void *)&key, (void **)&expire);

	if (unlikely(ret == -ENOENT)) {
		// We drop packets unless we received the first segment.
		ROUTER_DEBUG("Received subsequent fragment packets before the first one.");
		rte_pktmbuf_free(mbuf);
		return;
	}
	// Invalid parameter, assertion fail.
	assert(ret >= 0);

	time_t now = time(NULL);
	if (*expire < now) {
		// Do not delete expired entry.
		// If the timer runs out, the all reassembly resources
		// for this buffer identifier are released(RFP 791).
		ROUTER_DEBUG("Reassemble timed out.");
		rte_pktmbuf_free(mbuf);
		return;
	}
	// TODO: Should we update timer per RFC 791?

	struct rte_mbuf *rmbuf = reassemble_packet(mbuf, ri);

	// If reassemble_packet() returned NULL, then wait for
	// subsequent packet.
	if (!rmbuf)
		return;

	// A reassembly packet was generated,
	// delete first fragment information from hash.
	reassemble_delete_entry(ri->reassemble_hash, rmbuf);

	struct vsw_packet_metadata *md = VSW_MBUF_METADATA(rmbuf);
	struct router_mbuf_metadata *rmd = (struct router_mbuf_metadata *)&md->udata;

	mbuf_prepare_enqueue(rmd->rr, rmbuf);
}

bool
reassemble_packet_process_for_first_packet(struct router_instance *ri, struct rte_mbuf *mbuf) {
	// Waiting for subsequent packet.
	// Register first fragment to table.
	if (!reassemble_add_entry(ri->reassemble_hash, mbuf))
		return false;

	if (reassemble_packet(mbuf, ri)) {
		// Invalid case.
		// This function is called only at the first fragment.
		return false;
	}

	return true;
}

bool
reassemble_init(struct router_instance *ri) {
	char hash_name[RTE_HASH_NAMESIZE];
	// Interface information.
	int ret = snprintf(hash_name, sizeof(hash_name), "reassemble_%s", (const char *)ri->ctx->name);
	if (ret < 0)
		return false;
	ROUTER_DEBUG("[REASSEMBLE] (%s) interface table name: %s\n",
		     ri->ctx->name, hash_name);
	// Create hash table for reassemble packet
	struct rte_hash_parameters reassemble_hash_params = {
	    .name = hash_name,
	    .entries = REASSEMBLE_MAX_ENTRIES, // max_entries of rte_ip_frag_table_create()
	    .key_len = sizeof(struct reassemble_key),
	    .hash_func = reassemble_hash_func,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	if ((ri->reassemble_hash = rte_hash_create(&reassemble_hash_params)) == NULL) {
		ROUTER_ERROR("[REASSEMBLE] failed to create hash table.");
		return false;
	}

	uint64_t frag_cycles =
	    (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S * (REASSEMBLE_AGING_TIME * MS_PER_S);
	ri->frag_tbl = rte_ip_frag_table_create(REASSEMBLE_MAX_ENTRIES,
						IP_FRAG_TBL_BUCKET_ENTRIES,
						REASSEMBLE_MAX_ENTRIES,
						frag_cycles, rte_socket_id());
	if (ri->frag_tbl == NULL) {
		rte_hash_free(ri->reassemble_hash);
		ROUTER_ERROR("[REASSEMBLE] failed to create fragment table.");
		return false;
	}
	return true;
}

void
reassemble_fini(struct router_instance *ri) {
	rte_ip_frag_table_destroy(ri->frag_tbl);
}
