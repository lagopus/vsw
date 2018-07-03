/*
 * Copyright 2017 Nippon Telegraph and Telephone Corporation.
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
#include <inttypes.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <rte_malloc.h>
#include <rte_ether.h>

#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_cycles.h>
#include <rte_mempool.h>
#include <rte_ip_frag.h>
#include <rte_errno.h>

#include "packet.h"
#include "router_log.h"
#include "router.h"
#include "route.h"
#include "arp.h"
#include "interface.h"

#define IP_FRAG_TBL_BUCKET_ENTRIES	16
#define DEF_FLOW_NUM	0x1000
#define DEF_FLOW_TTL	3 * MS_PER_S

// fragmentation field check
#define IPV4_HDR_FRAG_MORE 0x2000
#define IPV4_HDR_FRAG_DF   0x4000
#define IS_FLAG_SET(v, f) (((v) & (f)) == (f))

typedef enum {
	ROUTER_ACTION_FORWARDING,	// send packet to vif.
	ROUTER_ACTION_TO_KERNEL,	// send packet to tap module.
	ROUTER_ACTION_TO_HOSTIF,	// TODO: send packet to hostif module.
	ROUTER_ACTION_TO_IPIP,		// send packet to ipip module.
	ROUTER_ACTION_TO_ESP,		// send packet to esp module.
	ROUTER_ACTION_TO_GRE,		// send packet to gre module.
	ROUTER_ACTION_DROP
} router_action_t;

struct router_runtime {
	struct rte_hash	*router_hash;
	bool		running;

	struct rte_ring	*notify;	// receive notification from frontend.

	struct router_mempools		mempools;	// for fragmentation.
	struct rte_ip_frag_tbl		*frag_tbl;	// for reassemble.
	struct rte_ip_frag_death_row	death_row;	// for reassemble.
};

static bool
init_tables(struct router_context *ctx) {
	// create tables.
	if (!(ctx->route = rte_zmalloc(NULL, sizeof(struct route_table), 0))) {
		lagopus_printf("router: %s: route table rte_zmalloc() failed.", ctx->name);
		goto err;
	}
	if (!(ctx->arp = rte_zmalloc(NULL, sizeof(struct arp_table), 0))) {
		lagopus_printf("router: %s: arp table rte_zmalloc() failed.", ctx->name);
		goto err;
	}
	if (!(ctx->vif = rte_zmalloc(NULL, sizeof(struct interface_table), 0))) {
		lagopus_printf("router: %s: interface table rte_zmalloc() failed.", ctx->name);
		goto err;
	}

	// initialize tables.
	if (!route_init(ctx->route, ctx->name)) {
		lagopus_printf("router: %s: route table initialize failed.", ctx->name);
		goto err;
	}
	if (!arp_init(ctx->arp, ctx->name)) {
		lagopus_printf("router: %s: arp table initialize failed.", ctx->name);
		goto err;
	}
	if (!interface_init(ctx->vif, ctx->name)) {
		lagopus_printf("router: %s: interface table initialize failed.", ctx->name);
		goto err;
	}

	return true;

err:
	if (ctx->route) rte_free(ctx->route);
	if (ctx->arp) rte_free(ctx->arp);
	if (ctx->vif) rte_free(ctx->vif);
	return false;
}

static void
free_context(struct router_context *ctx) {
	// free instance name.
	rte_free(ctx->name);

	// finilize tables.
	route_fini(ctx->route);
	arp_fini(ctx->arp);
	interface_fini(ctx->vif);

	// free tables.
	rte_free(ctx->route);
	rte_free(ctx->arp);
	rte_free(ctx->vif);

	// free context
	rte_free(ctx);
}

// manage ribs
static void
route_update(struct router_context *ctx, struct router_information *info) {
	struct route_table *rt = ctx->route;
	struct route_entry *re = &(info->route);
	if (!rt & !re) {
		lagopus_printf("router: %s: %s: invalid args.\n", ctx->name, __func__);
		return;
	}
	switch (info->cmd) {
	case ROUTER_CMD_ROUTE_ADD:
		if (route_entry_add(rt, re) < 0)
			lagopus_printf("router: %s: %s: Failed to add route.",
					ctx->name, __func__);
		break;
	case ROUTER_CMD_ROUTE_DELETE:
		if (!route_entry_delete(rt, re))
			lagopus_printf("router: %s: %s: Failed to delete route.",
					ctx->name, __func__);
		break;
	}
}

static void
arp_update(struct router_context *ctx, struct router_information *info) {
	struct arp_table *at = ctx->arp;
	struct arp_entry *ae = &(info->arp);
	if (!at & !ae) {
		lagopus_printf("router: %s: %s: invalid args.\n", ctx->name, __func__);
		return;
	}

	switch (info->cmd) {
	case ROUTER_CMD_ARP_ADD:
		if (!arp_entry_update(at, ae))
			lagopus_printf("router: %s: %s: Failed to add arp entry",
					ctx->name, __func__);
		break;
	case ROUTER_CMD_ARP_DELETE:
		if (!arp_entry_delete(at, ae))
			lagopus_printf("router: %s: %s: Failed to add arp entry",
					ctx->name, __func__);
		break;
	}
}

static void
interface_update(struct router_context *ctx, struct router_information *info) {
	struct interface_table *it = ctx->vif;
	struct interface_entry *ie = &(info->vif);
	struct interface_addr_entry *ia = &(info->addr);
	if (!it && !ie) {
		lagopus_printf("router: %s: %s: invalid args.\n", ctx->name, __func__);
		return;
	}
	switch (info->cmd) {
	case ROUTER_CMD_VIF_ADD:
		if (!interface_entry_add(it, ie))
			lagopus_printf("router: %s: %s: Failed to add interface.", ctx->name, __func__);
		break;
	case ROUTER_CMD_VIF_DELETE:
		if (!interface_entry_delete(it, ie))
			lagopus_printf("router: %s: %s: Failed to delete interface.",
					ctx->name, __func__);
		break;
	case ROUTER_CMD_VIF_ADD_IP:
		if (!interface_ip_add(it, ia))
			lagopus_printf("router: %s: %s: Failed to add interface.", ctx->name, __func__);
		break;
	case ROUTER_CMD_VIF_DELETE_IP:
		if (!interface_ip_delete(it, ia))
			lagopus_printf("router: %s: %s: Failed to delete interface.",
					ctx->name, __func__);
		break;
	}
}

//
// packet handling
//

/* RFC 791: Options field */
// for debug
const char *opt_types[] = {
			"End of List",
			"No Operation",
			"Security",
			"Loose Source Routing",
			"Internet Timestamp",
			"",
			"",
			"Record Route",
			"Stream ID",
			"Strict Source Routing"
};

//TODO: options field in ip header
// 1: modify header
// 0: success
// -1: invalid option
static int
parse_options(uint8_t *ipv4_hdr, uint16_t header_len, uint32_t src) {
	uint8_t *opt = ipv4_hdr + (sizeof(struct ipv4_hdr ));
	uint16_t opt_len = header_len - sizeof(struct ipv4_hdr);
	int ret = 0;
	int i = 0;
	int opt_type_max = sizeof(opt_types) / sizeof(opt_types[0]);
	while (i < opt_len) {
		uint8_t type = opt[i];
		if (type >= opt_type_max) {
			lagopus_printf("router: invalid option type(%u)", type);
			return -1;
		}
		LAGOPUS_DEBUG("router: %s(%u)\n", opt_types[type], type);

		// case 1
		switch (type) {
		case IPOPT_END:
			i++;
			return 0;
		case IPOPT_NOOP:
			i++;
			continue;
		}

		// TODO: case 2
		uint8_t len = opt[i+1];
		switch (type) {
		// Source Routing(LSRR: Loose, SSRR: Strict)
		case IPOPT_LSRR:
		case IPOPT_SSRR:
			break;
		// Record Route
		case IPOPT_RR:
		{
			uint8_t *rr_opt = &opt[i];
			// error
			if (rr_opt[1] < 3 || rr_opt[2] < 4 || rr_opt[2] % 4 != 0) {
				// invalid option
				return -1;
			}
			// full
			if (rr_opt[1] < rr_opt[2]) {
				// record route is full.
				break;
			}
			// set ip address of output physical interface.
			memcpy(&rr_opt[rr_opt[2] - 1], &src, 4);
			rr_opt[2] += 4;
#ifdef DEBUG
			LAGOPUS_DEBUG("\tlength: %d, pointer: %d\n",
					opt[i + 1], opt[i + 2]);
			for (int j = 3; j < rr_opt[1]; j += 4) {
				LAGOPUS_DEBUG("\t%d.%d.%d.%d\n",
						rr_opt[j], rr_opt[j + 1],
						rr_opt[j + 2], rr_opt[j + 3]);
			}
#endif
			ret = 1;
			break;
		}
		case IPOPT_TIMESTAMP:
			break;
		case IPOPT_SEC:
		case IPOPT_SID:
		default:
			// not supported.
			break;
		}
		i = i + len;
	}

	return ret;
}

/* recalcuration checksum. */
static uint16_t
recalc_cksum(struct ipv4_hdr *ipv4) {
	uint16_t checksum;

	ipv4->hdr_checksum = 0;
	checksum = rte_raw_cksum(ipv4, (ipv4->version_ihl & 0x0f) * 4);
	return ((checksum == 0xffff) ? checksum : ~checksum);
}

static inline bool
check_frag_field(struct ipv4_hdr *ipv4, bool *out_df) {
	// get frag field and offset
	uint16_t fragment_offset = rte_cpu_to_be_16(ipv4->fragment_offset);
	bool df   = IS_FLAG_SET(fragment_offset, IPV4_HDR_FRAG_DF);
	bool more = IS_FLAG_SET(fragment_offset, IPV4_HDR_FRAG_MORE);
	uint16_t offset = fragment_offset & 0x1FFF;

	LAGOPUS_DEBUG("router: fragment_offset = %04x, df = %s, more = %s\n",
			fragment_offset,
			df ? "true" : "false", more ? "true" : "false");

	// check list
	//         df | 0  0  0  0  1  1  1  1
	//       more | 0  0  1  1  0  0  1  1
	//     offset | 0 ~0  0 ~0  0 ~0  0 ~0
	// true/false | t  t  t  t  t  f  f  f
	if (!df || !more && !offset) {
		*out_df = df;
		return true;
	}

	LAGOPUS_DEBUG("router: fragment and offsest field is invalid.\n");
	return false;
}

/* check ipv4 header */
static struct ipv4_hdr *
check_ipv4_header(void *mbuf, bool *option_enable) {
	struct ipv4_hdr *ipv4 =
		rte_pktmbuf_mtod_offset((struct rte_mbuf *)mbuf,
			struct ipv4_hdr *, sizeof(struct ether_hdr));

	*option_enable = false;

	// check header length and version
	uint8_t header_len = ipv4->version_ihl & 0x0f;
	uint8_t version = (ipv4->version_ihl & 0xf0) >> 4;
	if (header_len < 5 || version != VERSION_IPV4) {
		// invalid data.
		LAGOPUS_DEBUG("router: %s(%d): invalid header (length = %d, version = %d)\n",
				__func__, __LINE__, header_len, version);
		return NULL;
	}

	// check packet length
	uint16_t length = rte_cpu_to_be_16(ipv4->total_length);
	if (unlikely(length < 20)) {
		LAGOPUS_DEBUG("router: %s(%d): invalid packet length(len = %d)\n",
				__func__, __LINE__, length);
		return NULL;
	}

	// check fragmentation field.
	struct lagopus_packet_metadata *md = LAGOPUS_MBUF_METADATA(mbuf);
	struct router_mbuf_metadata *rmd = (struct router_mbuf_metadata *) &md->udata;
	if (!check_frag_field(ipv4, &(rmd->df))) {
		return NULL;
	}

	// validation header checksum
	uint16_t in_csum = ipv4->hdr_checksum;
	uint16_t checksum = recalc_cksum(ipv4);
	if (unlikely(in_csum != checksum)) {
		LAGOPUS_DEBUG("router: %s(%d): invalid cehcksum(chksum = %u, calc chksum = %u)\n",
				__func__, __LINE__, in_csum, checksum);
		return NULL;
	}
	ipv4->hdr_checksum = in_csum; // reset checksum

	// check options field
	if (header_len > 5) {
		// option header, not supported now.
		LAGOPUS_DEBUG("router: %s(%d): option field(len: %d)\n",
				__func__, __LINE__, (header_len * 4 - sizeof(struct ipv4_hdr)));
		*option_enable = true;
	}

#ifdef DEBUG
	LAGOPUS_DEBUG("router: total len: %u, checksum: %u(hdr checksum: %u), version: %d, leader_len: %d\n",
			length, checksum, ipv4->hdr_checksum, version, header_len);
#endif

	return ipv4;
}

static int
rewrite_pkt_header(struct ether_hdr *eth, struct ipv4_hdr *ipv4,
		struct lagopus_packet_metadata *md,
		struct ether_addr *src, struct ether_addr *dst) {
	LAGOPUS_DEBUG("router: rewrite packet header \
src[%02x:%02x:%02x:%02x:%02x:%02x], dst[%02x:%02x:%02x:%02x:%02x:%02x]",
		src->addr_bytes[0], src->addr_bytes[1], src->addr_bytes[2],
		src->addr_bytes[3], src->addr_bytes[4], src->addr_bytes[5],
		dst->addr_bytes[0], dst->addr_bytes[1], dst->addr_bytes[2],
		dst->addr_bytes[3], dst->addr_bytes[4], dst->addr_bytes[5]);

	// check ttl and set checksum
	// A local flag is true, this packet was come from tunnel module,
	// at the time of encapsulation.
	if (likely(ipv4->time_to_live > 0) && !(md->md_vif.local)) {
		ipv4->time_to_live--;
	}

	// ttl is 0, stop forwarding and send to kernel.
	// expect to reply time exceeded.
	if (ipv4->time_to_live <= 0) {
		// recalc cehcksum before send to kernel.
		// modify ip header because decremented ttl.
		ipv4->hdr_checksum = recalc_cksum(ipv4);
		return -1;
	}

	// rewrite ether header. (pkt, src hw addr, dst hw addr).
	ether_addr_copy(src, &(eth->s_addr));
	ether_addr_copy(dst, &(eth->d_addr));

	// recalc checksum
	ipv4->hdr_checksum = recalc_cksum(ipv4);

	return 0;
}

static bool
check_tables(struct router_context *ctx) {
	if (ctx->route == NULL) {
		// not found table
		lagopus_printf("router: %s: routing table not found.\n", ctx->name);
		return false;
	} else if (ctx->arp == NULL) {
		// not found table
		lagopus_printf("router: %s: arp table not found.\n", ctx->name);
		return false;
	} else if (ctx->vif == NULL) {
		// not found table
		lagopus_printf("router: %s: interface table not found.\n", ctx->name);
		return false;
	}
	return true;
}

static int
fragment_packet(struct rte_mbuf *in_mbuf, struct rte_mbuf **out_mbufs, int *out_cnt,
		uint16_t frag_size, struct router_mempools *pools) {

	// backup ether header
	struct ether_hdr org_eth_hdr;
	rte_memcpy(&org_eth_hdr,
		   rte_pktmbuf_mtod((struct rte_mbuf *)in_mbuf, struct ether_hdr *),
		   sizeof(struct ether_hdr));
	if (rte_pktmbuf_adj(in_mbuf, (uint16_t)sizeof(struct ether_hdr)) == NULL) {
		lagopus_printf("router: packet mbuf adjust failed.\n");
		return -1;
	}

	LAGOPUS_DEBUG("router: [FRAG] pkt len: %"PRIu32"\n", in_mbuf->pkt_len);

	// fragmetation
	int frag_num = rte_ipv4_fragment_packet(in_mbuf, out_mbufs,
			(uint16_t)(RTE_LIBRTE_IP_FRAG_MAX_FRAG),
			frag_size, pools->direct_pool, pools->indirect_pool);

	if (frag_num < 0) {
		// fragmentation failed.
		LAGOPUS_DEBUG("router: [FRAG] fragmetation failed. ret(%d)", frag_num);
		return frag_num;
	}

	LAGOPUS_DEBUG("router: [FRAG] fragmentation successs, fragment size: %u, fragments: %d",
			frag_size, frag_num);

	struct lagopus_packet_metadata *md = LAGOPUS_MBUF_METADATA(in_mbuf);
	*out_cnt = frag_num;
	for (int i = 0; i < frag_num; i++) {
		struct rte_mbuf *out_mbuf = out_mbufs[i];

		// add ether header
		struct ether_hdr *new = (struct ether_hdr *)
			rte_pktmbuf_prepend(out_mbuf, (uint16_t)sizeof(struct ether_hdr));
		ether_addr_copy(&org_eth_hdr.s_addr, &(new->s_addr));
		ether_addr_copy(&org_eth_hdr.d_addr, &(new->d_addr));
		new->ether_type = rte_be_to_cpu_16(ETHER_TYPE_IPv4);

		// set len
		out_mbufs[i]->l2_len  = sizeof(struct ether_hdr);

		// copy VLAN TCI
		out_mbufs[i]->vlan_tci = in_mbuf->vlan_tci;

		// calc ip checksum
		out_mbufs[i]->ol_flags &= ~PKT_TX_IP_CKSUM; // do not offload hw.
		struct ipv4_hdr *ip =
			rte_pktmbuf_mtod_offset((struct rte_mbuf *)out_mbufs[i],
				struct ipv4_hdr *, sizeof(struct ether_hdr));
		ip->hdr_checksum = 0;
		ip->hdr_checksum = rte_ipv4_cksum(ip);
		LAGOPUS_DEBUG("router: [FRAG] new checksum = %x\n", ip->hdr_checksum);

		// copy packet metadata
		struct lagopus_packet_metadata *outmd = LAGOPUS_MBUF_METADATA(out_mbufs[i]);
		rte_memcpy(outmd, md, sizeof(struct vif_metadata) + sizeof(struct rte_ring*));

		LAGOPUS_DEBUG("router: [FRAG] OUT[%d]: pkt len: %"PRIu32", L2: %"PRIu32", ROUTER: %"PRIu32"\n",
				i, out_mbuf->pkt_len, out_mbuf->l2_len, out_mbuf->l3_len);
	}

	// free input mbuf.
	rte_pktmbuf_free(in_mbuf);

	return 0;
}

static struct rte_mbuf *
reassemble_packet(struct rte_mbuf *in_mbuf,
		struct ipv4_hdr *ip,
		struct rte_ip_frag_tbl *tbl,
		struct rte_ip_frag_death_row *dr) {
	int sid  = rte_socket_id();
	uint64_t tms = rte_rdtsc();
	// backup ether header
	struct ether_hdr org_eth_hdr;
	rte_memcpy(&org_eth_hdr,
			rte_pktmbuf_mtod((struct rte_mbuf *)in_mbuf,
			struct ether_hdr *),
			sizeof(struct ether_hdr));

	// packet is fragmented, so try to reassemble.
	in_mbuf->l2_len = sizeof(struct ether_hdr);
	in_mbuf->l3_len = sizeof(struct ipv4_hdr);
	struct rte_mbuf *out_mbuf =
		rte_ipv4_frag_reassemble_packet(tbl, dr, in_mbuf, tms, ip);
	if (out_mbuf == NULL) {
		LAGOPUS_DEBUG("router: [REASS] no packet to send out(pkt len: %d).", in_mbuf->pkt_len);
		return NULL;
	}
	if (out_mbuf != in_mbuf) {
		// reassemble success.
		LAGOPUS_DEBUG("router: [REASS] packets are reassembled(pkt len: %d).", in_mbuf->pkt_len);

		// set ether header
		struct ether_hdr *eth_hdr =
			rte_pktmbuf_mtod(out_mbuf, struct ether_hdr *);
		ether_addr_copy(&org_eth_hdr.s_addr,
				&(eth_hdr->s_addr));
		ether_addr_copy(&org_eth_hdr.d_addr,
				&(eth_hdr->d_addr));
		eth_hdr->ether_type =
			rte_be_to_cpu_16(ETHER_TYPE_IPv4);

		// calc ip checksum
		ip = rte_pktmbuf_mtod_offset((struct rte_mbuf *)out_mbuf,
				struct ipv4_hdr *, sizeof(struct ether_hdr));
		ip->hdr_checksum = 0;
		ip->hdr_checksum = rte_ipv4_cksum(ip);
	}
	return out_mbuf;
}

static inline uint16_t
get_frag_size(uint16_t mtu) {
	int header_size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
	uint16_t frag_size = ((mtu - header_size) & ~7) + sizeof(struct ipv4_hdr);
	return frag_size;
}

static inline uint32_t
get_networkaddr(uint32_t addr, uint8_t plen) {
	uint32_t mask = 0xFFFFFFFF << (32 - plen);
	addr = ntohl(addr);
	if (plen == 0)
		return 0;
	return htonl(addr & mask);
}

static int
lookup(void *mbuf, struct router_context *ctx, uint16_t *mtu) {
	uint32_t nhip, dstip;

	// ARP
	struct ether_hdr *hdr = rte_pktmbuf_mtod((struct rte_mbuf *)mbuf, struct ether_hdr *);
	if (hdr->ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP)) {
		LAGOPUS_DEBUG("Send arp packet to kernel.");
		return ROUTER_ACTION_TO_KERNEL;
	}

	// header check
	struct ipv4_hdr *ipv4;
	bool option_enable = false;
	if ((ipv4 = check_ipv4_header(mbuf, &option_enable)) == NULL) {
		//drop a packet.
		LAGOPUS_DEBUG("router: not support packet is drop.");
		rte_pktmbuf_free(mbuf);
		return ROUTER_ACTION_DROP;
	}

#ifdef DEBUG
	char srcbuf[INET_ADDRSTRLEN];
	char dstbuf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ipv4->src_addr), srcbuf, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ipv4->dst_addr), dstbuf, INET_ADDRSTRLEN);
	LAGOPUS_DEBUG("router: routing packet: %s -> %s\n", srcbuf, dstbuf);
#endif

	// get dst ip address from input packet.
	dstip = ipv4->dst_addr;

	// get routing table by vrfidx
	if (!check_tables(ctx)) {
		rte_pktmbuf_free(mbuf);
		lagopus_printf("router: %s: Don't get routing information tables", ctx->name);
		return ROUTER_ACTION_DROP;
	}

	// set local variables for coding.
	struct route_table *routetable		= ctx->route;
	struct arp_table *arptable		= ctx->arp;
	struct interface_table *interfacetable	= ctx->vif;

	// check all self interfaces.
	if (INTERFACE_IS_SELF(interfacetable, dstip)) {
		// check ip protocol is IPIP or ESP.
		if (ipv4->next_proto_id == IPPROTO_IPIP) {
			return ROUTER_ACTION_TO_IPIP;
		} else if (ipv4->next_proto_id == IPPROTO_ESP) {
			return ROUTER_ACTION_TO_ESP;
		} else if (ipv4->next_proto_id == IPPROTO_GRE) {
			return ROUTER_ACTION_TO_GRE;
		} else {
			// send arp, icmp, ike and self unicast ip packets to tap
			return ROUTER_ACTION_TO_KERNEL;
		}
	}

	// check ip broadcast.
	if (IS_IPV4_BROADCAST(htonl(dstip)) == true) {
		return ROUTER_ACTION_TO_KERNEL;
	}

	// lookup routing table
	ipv4_nexthop_t *nh = route_entry_get(routetable, dstip);
	if (!nh) {
		char dbuf[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &dstip, dbuf, sizeof(dbuf));
		lagopus_printf("router: %s: route entry not found(dstip: %s).\n", ctx->name, dbuf);
		// to return unreacheable message by kernel.
		return ROUTER_ACTION_TO_KERNEL;
	}

	// decide the nexthop address.
	// scope is LINK or nexthop is not specified.
	if (nh->scope == SCOPE_LINK || nh->gw == 0) {
		nhip = dstip;
	} else {
		nhip = nh->gw;
	}

	// set interface informations.
	struct interface *ie = nh->interface;

	if (!ie) {
		// get informations of the self interface.
		ie = interface_entry_get(interfacetable, nh->ifindex);
		if (!ie) {
			// drop this packet.
			lagopus_printf("router: %s: interface is not found.\n", ctx->name);
			rte_pktmbuf_free(mbuf);
			return ROUTER_ACTION_DROP;
		}
		nh->interface = ie;
	}

	*mtu = ie->mtu;

	// get mbuf metadata and router metadata.
	struct lagopus_packet_metadata *md = LAGOPUS_MBUF_METADATA(mbuf);
	struct router_mbuf_metadata *rmd = (struct router_mbuf_metadata *) &md->udata;

	// check DF bit for fragmentation.
	uint16_t frag_size = get_frag_size(ie->mtu);
	LAGOPUS_DEBUG("mtu: %d, frag size: %d\n", ie->mtu, frag_size);
	if (frag_size < ((struct rte_mbuf *)mbuf)->pkt_len && rmd->df) {
		lagopus_printf("DF bit is true, but fragmentation needed.\n");
		return ROUTER_ACTION_TO_KERNEL;
	}

	// check resolve flag.
	// arp entry is NULL: have to lookup interface table and arp table.
	struct arp_entry *arp = nh->arp; // set cache arp entry.
	if (!arp && !(ie->tunnel)) {
		//get dst mac address and output port from arp table(hash table).
		arp = arp_entry_get(arptable, nhip);
		if (arp) {
			if (arp->valid) {
				// arp entry is exist.
			} else {
				// it is no entry on the arp table, send packet to tap(kernel).
				LAGOPUS_DEBUG("router: %s: arp entry not found, send to tap.",
						ctx->name);
				return ROUTER_ACTION_TO_KERNEL;
			}
		} else {
			// arp entry is NULL.
			return ROUTER_ACTION_TO_KERNEL;
		}

		// update arp result to routing table.
		if (!route_entry_resolve_update(routetable, nhip, nh, arp)) {
			lagopus_printf("router: arp resolution update failed.");
		}
	}

	// get source ip address
	uint32_t srcaddr = 0;
	uint32_t nh_netaddr = get_networkaddr(nhip, nh->prefixlen);
	for (int i = 0; i < ie->count; i++) {
		uint32_t plen = ie->addr[i].prefixlen;
		if (nh_netaddr == get_networkaddr(ie->addr[i].addr, plen)) {
			srcaddr = ie->addr[i].addr;
			break;
		}
	}
#ifdef DEBUG
	char sbuf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &srcaddr, sbuf, sizeof(sbuf));
	LAGOPUS_DEBUG("self source address: %s\n", sbuf);
#endif

	// parse options field and update header
	if (option_enable &&
	    parse_options((uint8_t *)ipv4, ((ipv4->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER), srcaddr) < 0) {
		// drop packet that option field is invalid.
		rte_pktmbuf_free(mbuf);
		return ROUTER_ACTION_DROP;
	}

	if (!(ie->tunnel)) {
		// rewrite header
		if (rewrite_pkt_header(hdr, ipv4, md, &(ie->mac), &(arp->mac)) < 0) {
			// Forward to tap module if ttl=0,
			// need to send time exceeded ICMP message.
			return ROUTER_ACTION_TO_KERNEL;
		}

		// rewrite vlan id.
		if (ie->vid!= 0) {
			((struct rte_mbuf *)mbuf)->vlan_tci = ie->vid;
		}
	}

	// to dispatcher
	md->md_vif.out_vif = ie->ifindex;
	rmd->ring = ie->ring;

	LAGOPUS_DEBUG("router: %s: forwarding[in:%d -> out:%d], vid[%d]",
			ctx->name, md->md_vif.in_vif, ie->ifindex, ie->vid);
	return ROUTER_ACTION_FORWARDING;
}

static int
forward_packets(struct rte_mbuf *fwd_mbufs[],
		    int count, struct rte_ring **output) {
	// XXX: size of mbufs SHALL match with the size of fwd_mbufs
	struct rte_mbuf *mbufs[MAX_ROUTER_MBUFS * RTE_LIBRTE_IP_FRAG_MAX_FRAG];
	int total_count = 0;
	int start = 0;

	while (total_count < count) {
		struct rte_ring *ring;
		int cnt = 0;
		vifindex_t outvif = VIF_INVALID_INDEX;
		for (int i = start; i < count; i++) {
			if (fwd_mbufs[i] == NULL)
				continue;

			struct lagopus_packet_metadata *md = LAGOPUS_MBUF_METADATA(fwd_mbufs[i]);

			if (outvif == VIF_INVALID_INDEX) {
				outvif = md->md_vif.out_vif;
				ring = *(struct rte_ring**)md->udata;
				start = -1;
			}

			if (outvif == md->md_vif.out_vif) {
				mbufs[cnt++] = fwd_mbufs[i];
				fwd_mbufs[i] = NULL;
			} else if (start < 0) {
				start = i;
			}
		}

		int n = 0;
		while (cnt > 0) {
			struct lagopus_packet_metadata *md = LAGOPUS_MBUF_METADATA(mbufs[n]);
			unsigned sent = rte_ring_enqueue_burst(ring, (void * const*)&mbufs[n], cnt, NULL);
			cnt -= sent;
			n += sent;
		}
		total_count += n;
	}

	return total_count;
}

static int
dispatch_packets(struct rte_mbuf *mbufs[], int count,
		struct rte_ring *output) {
	int n = 0;
	while (count > 0) {
		unsigned sent = rte_ring_enqueue_burst(output, (void * const*)&mbufs[n], count, NULL);
		count -= sent;
		n += sent;
	}
	return n;
}

struct rte_mbuf *
get_reass_packet(struct rte_mbuf *mbuf, struct router_runtime *runtime,
		uint32_t count) {
	struct rte_mbuf *out_mbuf = mbuf;
	// reassemble
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	struct ipv4_hdr *iphdr = (struct ipv4_hdr *)(eth_hdr + 1);
	if (rte_ipv4_frag_pkt_is_fragmented(iphdr)) {
		// mbuf is fragment packet, so reassemble.
		out_mbuf = reassemble_packet(mbuf, iphdr,
				runtime->frag_tbl, &runtime->death_row);
		if (out_mbuf != NULL) {
			LAGOPUS_DEBUG("reassembled pkt segs: %d", out_mbuf->nb_segs);
		}
		rte_ip_frag_free_death_row(&runtime->death_row, count);
		// out_mbuf is NULL, fragments are not enough.
	}

	return out_mbuf;
}

static void
routing_packets(struct rte_mbuf **mbufs, uint32_t count,
		struct router_runtime *runtime, struct router_context *ctx) {
	// lookup
	int n = 0, out_cnt, ret;
	uint32_t fwd_count = 0, tap_count = 0, hostif_count = 0, ipip_count = 0, esp_count = 0, gre_count = 0;
	struct rte_mbuf *fwd_mbufs[MAX_ROUTER_MBUFS * RTE_LIBRTE_IP_FRAG_MAX_FRAG];
	struct rte_mbuf *tap_mbufs[MAX_ROUTER_MBUFS * RTE_LIBRTE_IP_FRAG_MAX_FRAG];
	struct rte_mbuf *hostif_mbufs[MAX_ROUTER_MBUFS];
	struct rte_mbuf *ipip_mbufs[MAX_ROUTER_MBUFS];
	struct rte_mbuf *esp_mbufs[MAX_ROUTER_MBUFS];
	struct rte_mbuf *gre_mbufs[MAX_ROUTER_MBUFS];
	// fragmentation
	struct rte_mbuf *out_mbufs[RTE_LIBRTE_IP_FRAG_MAX_FRAG];
	uint16_t mtu, frag_size;
	// reassemble
	struct rte_mbuf *out_mbuf;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip;

	if (runtime == NULL || ctx == NULL) {
		lagopus_printf("router: invalid argument. runtime: %p, ctx: %p", runtime, ctx);
		return;
	}

	struct rte_mbuf *tmp;
	while (n < count) {
		int ret = lookup(mbufs[n], ctx, &mtu);
		int header_size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
		frag_size = ((mtu - header_size) & ~7) + sizeof(struct ipv4_hdr);
		out_cnt = 1;
		struct lagopus_packet_metadata *md =
			LAGOPUS_MBUF_METADATA(mbufs[n]);
		switch (ret) {
		case ROUTER_ACTION_FORWARDING:
			// fragment packet
			// register frag_size instead of mtu to route table,
			// to cut cost of calculation.
			if (unlikely(frag_size < (mbufs[n]->pkt_len - sizeof(struct ether_hdr)))) {
				// fragmentation.
				int cnt = 0;
				ret = fragment_packet(mbufs[n], (struct rte_mbuf **)fwd_mbufs,
						&cnt, frag_size, &runtime->mempools);
				if (ret < 0) {
					// fragmentation failed and send mbufs[n] to tap.
					lagopus_printf("router: fragmentation failed(%d)\n", ret);
				}
				fwd_count += cnt;
			} else {
				// don't fragmentation.
				fwd_mbufs[fwd_count++] = mbufs[n];
			}
			break;
		case ROUTER_ACTION_TO_KERNEL:
		{
			// check packet size
			if (unlikely((frag_size < mbufs[n]->pkt_len) &&
				     (md->md_vif.local))) {
				// local packet only.
				LAGOPUS_DEBUG("router: fragmentation local packets.\n");
				ret = fragment_packet(mbufs[n],
						(struct rte_mbuf **)tap_mbufs,
						&tap_count, frag_size,
						&runtime->mempools);
				if (ret < 0) {
					// fragmentation failed and send mbufs[n] to tap.
					lagopus_printf("router: fragmentation failed(%d)\n", ret);
				}
			} else {
				// don't fragment.
				tap_mbufs[tap_count++] = mbufs[n];
			}
			break;
		}
		case ROUTER_ACTION_TO_HOSTIF:
				if ((tmp = get_reass_packet(mbufs[n], runtime, hostif_count)) != NULL) {
					hostif_mbufs[hostif_count++] = tmp;
				}
			break;
		case ROUTER_ACTION_TO_IPIP:
				if ((tmp = get_reass_packet(mbufs[n], runtime, ipip_count)) != NULL) {
					ipip_mbufs[ipip_count++] = tmp;
				}
			break;
		case ROUTER_ACTION_TO_ESP:
				if ((tmp = get_reass_packet(mbufs[n], runtime, esp_count)) != NULL) {
					esp_mbufs[esp_count++] = tmp;
				}
			break;
		case ROUTER_ACTION_TO_GRE:
			if ((tmp = get_reass_packet(mbufs[n], runtime, esp_count)) != NULL) {
				gre_mbufs[gre_count++] = tmp;
			}
			break;
		default:
			break;
		}
		n = n + out_cnt;
	}

	// forward packets
	// Currently, Output ring is set in the user data area of the metadata of the packet.
	int sent;
	if (fwd_count > 0) {
		sent = forward_packets(fwd_mbufs, fwd_count, NULL);
		if (sent > 0)
			LAGOPUS_DEBUG("router: %s: Forward to bridge: out queued %u packets.",
				ctx->name, sent);
	}

	// send to tunnel module.
	if (ipip_count > 0) {
		if (ctx->rings.ipip) {
			sent = dispatch_packets(ipip_mbufs, ipip_count, ctx->rings.ipip);
			if (sent > 0)
				LAGOPUS_DEBUG("router: %s: Forward to ipip: out queued %u packets.",
						ctx->name, sent);
		} else {
			// warning text.
			LAGOPUS_DEBUG("router: warning: IPIP tunnel ring is NULL.");
		}
	}
	if (esp_count > 0) {
		if (ctx->rings.esp) {
			sent = dispatch_packets(esp_mbufs, esp_count, ctx->rings.esp);
			if (sent > 0)
				LAGOPUS_DEBUG("router: %s: Forward to esp: out queued %u packets.",
						ctx->name, sent);
		} else {
			// warning text.
			LAGOPUS_DEBUG("router: warning: ESP tunnel ring is NULL.");
		}
	}
	if (gre_count > 0) {
		if (ctx->rings.gre) {
			sent = dispatch_packets(gre_mbufs, gre_count, ctx->rings.gre);
			if (sent > 0)
				LAGOPUS_DEBUG("router: %s: Forward to gre: out queued %u packets.",
						ctx->name, sent);
		} else {
			// warning text.
			LAGOPUS_DEBUG("router: warning: GRE tunnel ring is NULL.");
		}
	}

	// send to tap
	if (tap_count > 0) {
		if (ctx->rings.tap) {
			sent = dispatch_packets(tap_mbufs, tap_count, ctx->rings.tap);
			if (sent > 0)
				LAGOPUS_DEBUG("router: %s: Forward to tap: out queued %u packets.",
						ctx->name, sent);
		} else {
			// warning text.
			LAGOPUS_DEBUG("router: warning: Tap ring is NULL.");
		}
	}

	// send to hostif module
	if (hostif_count > 0) {
		if (ctx->rings.hostif) {
			sent = dispatch_packets(hostif_mbufs, hostif_count, ctx->rings.hostif);
			if (sent > 0)
				LAGOPUS_DEBUG("router: %s: Forward to hostif: out queued %u packets.",
						ctx->name, sent);
		} else {
			// warning text.
			LAGOPUS_DEBUG("router: warning: HostIF ring is NULL.");
		}
	}
}

static bool
router_register_instance(void *p, struct lagopus_instance *base) {
	struct router_runtime *r = p;
	struct router_instance *ri = (struct router_instance *)base;

	// set router instance
	ri->vif_count = 0;

	// set router context
	ri->ctx = rte_zmalloc(NULL, sizeof(struct router_context), 0);
	if (ri->ctx == NULL) {
		lagopus_printf("router: %s: rte_zmalloc() failed.", ri->base.name);
		return false;
	}
	ri->ctx->vrfidx = ri->vrfidx;
	ri->ctx->name = rte_zmalloc(NULL, BUFSIZ, 0);
	memcpy(ri->ctx->name, ri->base.name, sizeof(ri->base.name));

	if (!init_tables(ri->ctx)) {
		lagopus_printf("router: %s: init talbes failed.", base->name);
		return false;
	}

	if (rte_hash_add_key_data(r->router_hash, &ri->base.id, ri) < 0) {
		lagopus_printf("router: Can't add router %s", base->name);
		free_context(ri->ctx);
		return false;
	}

	return true;
}

static bool
router_unregister_instance(void *p, struct lagopus_instance *base) {
	struct router_runtime *r = p;
	struct router_instance *ri = (struct router_instance *)base;
	LAGOPUS_DEBUG("router: %s(%d)", __func__, __LINE__);

	free_context(ri->ctx);
	if (rte_hash_del_key(r->router_hash, &ri->base.id) < 0 ) {
		return false;
	}

	return true;
}

static bool
router_control_instance(void *p, struct lagopus_instance *base, void *param) {
	struct router_runtime *r = p;
	struct router_instance *ri = (struct router_instance*)base;
	struct router_control_param *rp = param;
	struct router_context *ctx = ri->ctx;
	struct router_information *info = rp->info;
	//LAGOPUS_DEBUG("router: %s(%d) cmd = %d, vrfrd = %"PRIu64"\n", __func__, __LINE__, rp->cmd, ri->vrfrd);

	// check if there's any control message from the frontend.
	// pre check
	switch (rp->cmd) {
		case ROUTER_CMD_ENABLE:
			ctx->active = true;
			break;
		case ROUTER_CMD_DISABLE:
			ctx->active = false;
			break;

		case ROUTER_CMD_CONFIG_RING_TAP:
			ctx->rings.tap = info->rings.tap;
			break;

		case ROUTER_CMD_CONFIG_RING_HOSTIF:
			ctx->rings.hostif = info->rings.hostif;
			break;

		case ROUTER_CMD_CONFIG_RING_IPIP:
			ctx->rings.ipip = info->rings.ipip;
			break;

		case ROUTER_CMD_CONFIG_RING_ESP:
			ctx->rings.esp = info->rings.esp;
			break;

		case ROUTER_CMD_CONFIG_RING_GRE:
			ctx->rings.gre = info->rings.gre;
			break;

		// manage the rib
		case ROUTER_CMD_ROUTE_ADD:
		case ROUTER_CMD_ROUTE_DELETE:
			route_update(ctx, info);
			break;
		case ROUTER_CMD_ARP_ADD:
		case ROUTER_CMD_ARP_DELETE:
			arp_update(ctx, info);
			break;
		case ROUTER_CMD_VIF_ADD:
		case ROUTER_CMD_VIF_DELETE:
		case ROUTER_CMD_VIF_ADD_IP:
		case ROUTER_CMD_VIF_DELETE_IP:
			info->vif.ring = rp->ring;
			interface_update(ctx, info);
			// When the interface information is deleted,
			// must be clear route informations using the interface.
			// But, deleting an route entry,
			// follow the instructions of the netlink.
			// Therefore, it is not deleted here. arp too.
			break;
	}
	return true;
}

static void*
router_init(void *param) {
	struct router_runtime *r;
	struct router_runtime_param *p = param;
	LAGOPUS_DEBUG("router: %s(%d) start router init.....", __func__, __LINE__);

	if (!(r = rte_zmalloc(NULL, sizeof(struct router_runtime), 0))) {
		lagopus_printf("router: %s: rte_zmalloc() failed. Can't start.", __func__);
		return NULL;
	}

	// Create hash table for router instances
	struct rte_hash_parameters hash_params = {
		.name = "routers",
		.entries = MAX_ROUTERS,
		.key_len = sizeof(uint64_t),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	if ((r->router_hash = rte_hash_create(&hash_params)) == NULL) {
		rte_free(r);
		return NULL;
	}

	// Set mempools for fragmentation process.
	r->mempools.direct_pool = p->pool;
	r->mempools.indirect_pool =
		rte_pktmbuf_pool_create("pool_indirect", 4096, 32, 0,
					RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (r->mempools.indirect_pool == NULL) {
		rte_hash_free(r->router_hash);
		rte_free(r);
		lagopus_printf("router: ERROR: Cannot create indirect mempool: %s",
				rte_strerror(rte_errno));
		return NULL;
	}
	uint64_t frag_cycles =
		(rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S * DEF_FLOW_TTL;
	r->frag_tbl = rte_ip_frag_table_create(DEF_FLOW_NUM,
			IP_FRAG_TBL_BUCKET_ENTRIES, DEF_FLOW_NUM,
			frag_cycles, rte_socket_id());
	if (r->frag_tbl == NULL) {
		rte_hash_free(r->router_hash);
		rte_mempool_free(r->mempools.indirect_pool);
		rte_free(r);
		lagopus_printf("router: ERROR: fragment table create failed.");
		return NULL;
	}
	return r;
}

static bool
router_process(void *p) {
	struct router_runtime *r = p;
	struct rte_mbuf *mbufs[MAX_ROUTER_MBUFS];
	uint32_t next = 0;
	uint64_t *id;
	struct router_instance *ri;
	struct rte_ring *noti = r->notify;

	while (rte_hash_iterate(r->router_hash, (const void **)&id, (void **)&ri, &next) >= 0) {
		if (!ri->base.enabled) {
			continue;
		}

		unsigned count = rte_ring_dequeue_burst(ri->base.input, (void **)mbufs, MAX_ROUTER_MBUFS, NULL);
		if (count > 0) {
			LAGOPUS_DEBUG("router: %s: name = %s count = %d ----------", __func__, ri->base.name, count);

			//--- packet routing ---//
			routing_packets((struct rte_mbuf **)mbufs, count, r, ri->ctx);
		}
	}

	return true;
}

static void
router_deinit(void *p) {
	struct router_runtime *r = p;
	uint64_t *id;
	uint32_t next = 0;
	struct router_instance *ri;

	LAGOPUS_DEBUG("router: %s(%d)", __func__, __LINE__);

	// free context
	while (rte_hash_iterate(r->router_hash, (const void **)&id, (void **)&ri, &next) >= 0) {
		free_context(ri->ctx);
	}
	// free fragmentation table.
	rte_ip_frag_table_destroy(r->frag_tbl);
	// free hash table
	rte_hash_free(r->router_hash);
	// free mempool
	rte_mempool_free(r->mempools.indirect_pool);
	// free runtime
	rte_free(r);
	return;
}

struct lagopus_runtime_ops router_runtime_ops = {
	.init = router_init,
	.process = router_process,
	.deinit = router_deinit,
	.register_instance = router_register_instance,
	.unregister_instance = router_unregister_instance,
	.update_rings = NULL,
	.control_instance = router_control_instance,
};

