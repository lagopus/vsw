/*
 * Copyright 2017-2019 Nippon Telegraph and Telephone Corporation.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_errno.h>

#include "packet.h"
#include "logger.h"

#include "bridge.h"

static uint32_t bridge_log_id = 0;

#define BRIDGE_DEBUG(fmt, x...)		vsw_msg_debug(bridge_log_id, 0, fmt, ## x)
#define BRIDGE_INFO(fmt, x...)		vsw_msg_info(bridge_log_id, fmt, ## x)
#define BRIDGE_WARNING(fmt, x...)	vsw_msg_warning(bridge_log_id, fmt, ## x)
#define BRIDGE_ERROR(fmt, x...)		vsw_msg_error(bridge_log_id, fmt, ## x)
#define BRIDGE_FATAL(fmt, x...)		vsw_msg_fatal(bridge_log_id, fmt, ## x)

struct bridge_runtime {
	struct rte_hash		*bridge_hash;
	struct bridge_learn	*learning_data;
	struct rte_ring		*learn;
	struct rte_ring		*free;
};

#define ETHADDR_STRLEN 18

static inline bool
dispatch_packet(struct bridge_instance *b, struct rte_mbuf *mbuf)
{
	struct vsw_packet_metadata *md = VSW_MBUF_METADATA(mbuf);
	struct ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	struct ether_addr *daddr = &hdr->d_addr;
	struct rte_ring *ring = NULL;

	if (!is_unicast_ether_addr(daddr) ||
	    (!b->mac_hash) || (rte_hash_lookup_data(b->mac_hash, daddr, (void **)&ring) < 0)) {
		BRIDGE_DEBUG("%s: Flooding to %d VIFs", __func__, b->vif_count);

		// Update refcnt first
		int expect = b->vif_count - 1;
		if (expect > 1)
			rte_pktmbuf_refcnt_update(mbuf, (int16_t)(expect - 1));

		// flooding by split horizon
		vifindex_t in_vif = md->common.in_vif;
		int sent = 0;
		for (int n = 0; n < b->vif_count; n++) {
			if ((b->vifs[n].index != in_vif) &&
			    (rte_ring_enqueue(b->vifs[n].ring, mbuf) == 0)) {
				BRIDGE_DEBUG("%s: queing to %d @ %p", __func__, n, b->vifs[n].ring);
				sent++;
			}
		}

		// Adjust refcnt
		if (unlikely(sent == 0)) {
			if (expect > 1)
				rte_pktmbuf_refcnt_update(mbuf, (int16_t)(1 - expect));
			rte_pktmbuf_free(mbuf);
			return false;
		} else if (unlikely(sent < expect)) {
			rte_pktmbuf_refcnt_update(mbuf, (int16_t)(sent - expect));
		}

		return true;
	}

	// We now should have a ring to enqueue.
	if (rte_ring_enqueue(ring, mbuf) != 0) {
		rte_pktmbuf_free(mbuf);
		return false;
	}

	return true;
}

static uint32_t
bridge_domain_hash_func(const void *key, uint32_t length, uint32_t initval)
{
	const uint32_t *k = key;
	return rte_jhash_2words(k[0], k[1], initval);
}

static uint32_t
mac_entry_hash_func(const void *key, uint32_t length, uint32_t initval)
{
	const uint16_t *k = key;
	return rte_jhash_2words(k[0] << 16 | k[1], k[2], initval);
}

static struct rte_hash*
bridge_create_mac_hash(const char *name, int entries) {
	struct rte_hash *hash;
	char hash_name[128];

	// create MAC Hash
	snprintf(hash_name, sizeof(hash_name), "%s-MAC", name);
	struct rte_hash_parameters mac_hash_params = {
		.name = hash_name,
		.entries = entries,
		.key_len = sizeof(struct ether_addr),
		.hash_func = mac_entry_hash_func,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	if ((hash = rte_hash_create(&mac_hash_params)) == NULL) {
		BRIDGE_DEBUG("%s: Can't create a MAC hash (%s)\n",
				name, rte_strerror(rte_errno));
		return NULL;
	}

	return hash;
}

/* Bridge Domain Related */
static bool
bridge_register_instance(void *p, struct vsw_instance *base)
{
	struct bridge_runtime *r = p;
	struct bridge_instance *b = (struct bridge_instance*)base;

	b->max_mac_entries = 0;
	b->mac_hash = NULL;
	b->mat = NULL;
	b->mtu = 0;
	b->rif_count = 0;
	b->vif_count = 0;

	if (rte_hash_add_key_data(r->bridge_hash, &b->base.id, b) < 0) {
		BRIDGE_DEBUG("birdge: Can't add domain %s", b->base.name);
		return false;
	}

	return true;
}

static bool
bridge_unregister_instance(void *p, struct vsw_instance *base)
{
	struct bridge_runtime *r = p;
	struct bridge_instance *b = (struct bridge_instance*)base;

	if (rte_hash_del_key(r->bridge_hash, &b->base.id) < 0)
		return false;

	rte_hash_free(b->mac_hash);

	return true;
}

/* RIF Related */
static inline bool
bridge_rif_add(struct bridge_instance *b, struct bridge_control_param *bp) {
	if (b->rif_count == MAX_BRIDGE_RIFS)
		return false;

	if (rte_hash_add_key_data(b->mac_hash, &bp->mac, bp->ring) < 0) {
		return false;
	}

	b->rifs[b->rif_count].mac  = bp->mac;
	b->rifs[b->rif_count].ring = bp->ring;
	b->rif_count++;
	b->mtu = bp->mtu;
	return true;
}

static inline bool
bridge_rif_delete(struct bridge_instance *b, struct bridge_control_param *bp) {
	for (int n = 0; n < b->rif_count; n++) {
		if (is_same_ether_addr(&b->rifs[n].mac, &bp->mac)) {
			b->rif_count--;
			b->rifs[n] = b->rifs[b->rif_count];
			b->mtu = bp->mtu;
			return rte_hash_del_key(b->mac_hash, &bp->mac);
		}
	}
	return false;
}

/* VIF Related */
static inline bool
bridge_vif_add(struct bridge_instance *b, struct bridge_control_param *bp) {
	BRIDGE_DEBUG("%s: Adding VIF: %d @ %p (mtu=%d)", __func__, bp->index, bp->ring, bp->mtu);
	if (b->vif_count == MAX_BRIDGE_VIFS)
		return false;

	b->vifs[b->vif_count].index = bp->index;
	b->vifs[b->vif_count].ring  = bp->ring;
	b->vif_count++;
	b->mtu = bp->mtu;
	return true;
}

static inline bool
bridge_vif_delete(struct bridge_instance *b, struct bridge_control_param *bp) {
	for (int n = 0; n < b->vif_count; n++) {
		if (b->vifs[n].index == bp->index) {
			b->vif_count--;
			b->vifs[n] = b->vifs[b->vif_count]; 
			b->mtu = bp->mtu;
			return true;
		}
	}
	return false;
}

/* MAC Related */
static inline bool
bridge_mac_add(struct bridge_instance *b, struct bridge_control_param *bp) {
	return (rte_hash_add_key_data(b->mac_hash, &bp->mac, bp->ring) >= 0);
}

static inline bool
bridge_mac_delete(struct bridge_instance *b, struct bridge_control_param *bp) {
	return (rte_hash_del_key(b->mac_hash, &bp->mac) >= 0);
}

static inline bool
bridge_mac_recreate_hash(struct bridge_instance *b, int max_mac_entries) {
	if (max_mac_entries == b->max_mac_entries) {
		return true;
	}

	struct rte_hash *hash = NULL;
	if ((max_mac_entries > 0) &&
	    !(hash = bridge_create_mac_hash(b->base.name, max_mac_entries)))
		return false;

	if (b->mac_hash != NULL)
		rte_hash_free(b->mac_hash);
	b->mac_hash = hash;
	b->max_mac_entries = max_mac_entries;

	return true;
}

#define CMD_DEFS(NAME)	[BRIDGE_CMD_ ## NAME] = #NAME

static bool
bridge_control_instance(void *p, struct vsw_instance *base, void *param)
{
	struct bridge_instance *b = (struct bridge_instance*)base;
	struct bridge_control_param *bp = param;

	const char *cmds[] = {
		CMD_DEFS(RIF_ADD),
		CMD_DEFS(RIF_DELETE),
		CMD_DEFS(VIF_ADD),
		CMD_DEFS(VIF_DELETE),
		CMD_DEFS(MAC_ADD),
		CMD_DEFS(MAC_DELETE),
		CMD_DEFS(SET_MTU),
		CMD_DEFS(SET_MAX_ENTRIES),
		CMD_DEFS(SET_MAT),
	};

	BRIDGE_DEBUG("%s: %s domain: %s", __func__, cmds[bp->cmd], b->base.name);

	switch (bp->cmd) {
		case BRIDGE_CMD_RIF_ADD:
			return bridge_rif_add(b, bp);

		case BRIDGE_CMD_RIF_DELETE:
			return bridge_rif_delete(b, bp);

		case BRIDGE_CMD_VIF_ADD:
			return bridge_vif_add(b, bp);

		case BRIDGE_CMD_VIF_DELETE:
			return bridge_vif_delete(b, bp);

		case BRIDGE_CMD_MAC_ADD:
			{
				char mac[ETHADDR_STRLEN];
				ether_format_addr(mac, sizeof mac, &bp->mac);
				BRIDGE_DEBUG("%s: Adding %s", __func__, mac);
			}
			return bridge_mac_add(b, bp);

		case BRIDGE_CMD_MAC_DELETE:
			return bridge_mac_delete(b, bp);

		case BRIDGE_CMD_SET_MTU:
			b->mtu = bp->mtu;
			return true;

		case BRIDGE_CMD_SET_MAX_ENTRIES:
			return bridge_mac_recreate_hash(b, bp->max_mac_entries);

		case BRIDGE_CMD_SET_MAT:
			b->mat = bp->ring;
			return true;
	}

	return false;
}

static int
init_mac_learning(struct bridge_runtime *r, struct rte_ring *learn, struct rte_ring *free)
{
	unsigned count = rte_ring_free_count(learn);
	if (count == 0 || count != rte_ring_free_count(free)) {
		BRIDGE_DEBUG("bridge: Invalid ring sizes for learning.");
		return -1;
	}

	size_t size = sizeof(struct bridge_learn) * count;
	if (!(r->learning_data = rte_zmalloc(NULL, size, 0))) {
		BRIDGE_DEBUG("bridge: rte_zmalloc() failed. Can't alloc memory for learning (%d/%d).", size, count);
		return -1;
	}

	for (int i = 0; i < count; i++) {
		rte_ring_enqueue(free, &r->learning_data[i]);
	}

	return 0;
}

static void
update_logid()
{
	int id = vsw_log_getid("bridge");
	if (id >= 0)
		bridge_log_id = (uint32_t)id;
}

static void bridge_deinit(void*);

static void*
bridge_init(void *param)
{
	struct bridge_runtime *r;
	struct bridge_runtime_param *p = param;

	update_logid();

	if (!(r = rte_zmalloc(NULL, sizeof(struct bridge_runtime), 0))) {
		BRIDGE_DEBUG("%s: BE: rte_zmalloc() failed. Can't start.", __func__);
		return NULL;
	}

	// Create hash table for bridge domain
	struct rte_hash_parameters hash_params = {
		.name = "bridges",
		.entries = MAX_BRIDGE_DOMAINS,
		.key_len = sizeof(uint64_t),
		.hash_func = bridge_domain_hash_func,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	if ((r->bridge_hash = rte_hash_create(&hash_params)) == NULL) {
		rte_free(r);
		return NULL;
	}

	if (init_mac_learning(r, p->learn, p->free) != 0) {
		bridge_deinit(r);
		return NULL;
	}

	r->learn       = p->learn; // Mac learning containers sent to the frontend
	r->free	       = p->free;  // Mac learning containers available

	return r;
}

static bool
bridge_process(void *p)
{
	struct bridge_runtime *r = p;
	struct rte_mbuf *mbufs[MAX_BRIDGE_MBUFS];
	uint32_t next = 0;
	uint32_t *bridge_id;
	struct bridge_instance *b;
	struct rte_ring *learn_ring = r->learn;
	struct rte_ring *free_ring = r->free;

	while (rte_hash_iterate(r->bridge_hash, (const void **)&bridge_id, (void **)&b, &next) >= 0) {
		// Skip if the bridge domain is not ready yet.
		if (!b->base.enabled)
			continue;

		unsigned count = rte_ring_dequeue_burst(b->base.input, (void **)mbufs, MAX_BRIDGE_MBUFS, NULL);

		if (count > 0)
			BRIDGE_DEBUG("%s: name=%s count=%d", __func__, b->base.name, count);
		for (int i = 0; i < count; i++) {
			struct rte_mbuf *mbuf = mbufs[i];

			// Drop packets that exceeds the MTU
			if (mbuf->pkt_len > b->mtu) {
				rte_pktmbuf_free(mbuf);
				continue;
			}

			struct vsw_packet_metadata *md = VSW_MBUF_METADATA(mbuf);

			// Need to learn if the mbuf is not from MAT
			if (!(md->common.flags & VSW_MD_MAT)) {
				if ((b->mac_hash) && (md->common.out_vif == VIF_INVALID_INDEX)) {
					// Extract src mac from the packet
					struct bridge_learn *l;
					if (rte_ring_dequeue(free_ring, (void**)&l) == 0) {
						struct ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

						l->domain_id = b->domain_id;
						l->index = md->common.in_vif;
						ether_addr_copy(&hdr->s_addr, &l->mac);

						rte_ring_enqueue(learn_ring, (void*)l);
					}
				}

				if (b->mat) {
					// Forward to MAT
					md->common.flags |= VSW_MD_MAT;
					if (rte_ring_enqueue(b->mat, mbuf) != 0)
						rte_pktmbuf_free(mbuf);
					continue;
				}
			}

			// Forward to VIF
			md->common.flags &= ~VSW_MD_MAT;
			if (!dispatch_packet(b, mbufs[i]))
				BRIDGE_DEBUG("brdige: dispatch failed.");
		}
	}

	return true;
}

static void
bridge_deinit(void *p)
{
	struct bridge_runtime *r = p;
	uint32_t next = 0;
	uint32_t *bridge_id;
	struct bridge_instance *b;

	while (rte_hash_iterate(r->bridge_hash, (const void **)&bridge_id, (void **)&b, &next) >= 0) {
		rte_hash_free(b->mac_hash);
	}
	rte_hash_free(r->bridge_hash);

	if (r->learning_data)
		rte_free(r->learning_data);

	rte_free(r);
}

struct vsw_runtime_ops bridge_runtime_ops = {
	.init = bridge_init,
	.process = bridge_process,
	.deinit = bridge_deinit,
	.register_instance = bridge_register_instance,
	.unregister_instance = bridge_unregister_instance,
	.control_instance = bridge_control_instance,
};
