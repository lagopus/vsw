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

#include <rte_malloc.h>
#include <rte_ether.h>

#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_cycles.h>
#include <arpa/inet.h>

#include "packet.h"
#include "l3_log.h"
#include "l3.h"
#include "route.h"
#include "arp.h"
#include "interface.h"

#include "lagopus_types.h"
#include "lagopus_error.h"

/* for vrrp */
#define IPV4_MULTICAST_VRRP IPv4(224, 0, 0, 18)
#define IS_IPV4_VRRP(x) ((x) == IPV4_MULTICAST_VRRP)

typedef enum {
	L3_ACTION_FORWARDING,	// send packet to bridge module.
	L3_ACTION_TO_KERNEL,	// send packet to tap module.
	L3_ACTION_TO_HOSTIF,	// send packet to hostif module.
	L3_ACTION_DROP
} l3_action_t;

struct l3_runtime {
	char *name;
	struct rte_hash *l3_hash;
	bool running;
};

static lagopus_result_t
l3_init_tables(struct l3_context *ctx) {
	if (!(ctx->route = rte_zmalloc(NULL, sizeof(struct route_table), 0))) {
		goto nomemory;
	}
	if (!(ctx->arp = rte_zmalloc(NULL, sizeof(struct arp_table), 0))) {
		goto nomemory;
	}
	if (!(ctx->vif = rte_zmalloc(NULL, sizeof(struct interface_table), 0))) {
		goto nomemory;
	}

	// initialize tables.
	route_init(ctx->route, ctx->name, ctx->vrfrd);
	arp_init(ctx->arp, ctx->name, ctx->vrfrd);
	interface_init(ctx->vif, ctx->name, ctx->vrfrd);

	return LAGOPUS_RESULT_OK;

nomemory:
	lagopus_printf("%s: table rte_zmalloc() failed.", ctx->name);
	if (ctx->route) rte_free(ctx->route);
	if (ctx->arp) rte_free(ctx->arp);
	return LAGOPUS_RESULT_NO_MEMORY;
}

static void
l3_free_context(struct l3_context *ctx) {
	// ctx->name is runtime->name, ctx->name don't free.

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

static lagopus_result_t
l3_create(struct l3_runtime *runtime, struct l3_request *r) {
	struct l3_context *ctx = rte_zmalloc(NULL, sizeof(struct l3_context), 0);
	if (ctx == NULL) {
		lagopus_printf("%s: rte_zmalloc() failed.", runtime->name);
		return LAGOPUS_RESULT_NO_MEMORY;
	}
	ctx->vrfrd = r->vrfrd;
	ctx->name = runtime->name;

	// create and set tables.
	if (l3_init_tables(ctx) != LAGOPUS_RESULT_OK) {
		return LAGOPUS_RESULT_ANY_FAILURES;
	}

	// add context to hash table.
	if (rte_hash_add_key_data(runtime->l3_hash, &r->vrfrd, ctx) < 0) {
		lagopus_printf("%s: add l3 context failed.", runtime->name);
		l3_free_context(ctx);
		return LAGOPUS_RESULT_ANY_FAILURES;
	}
}

static inline void
l3_destroy(struct l3_runtime *runtime, struct l3_request *r) {
	uint32_t next = 0;
	uint64_t *vrfrd;
	struct l3_context *ctx;
	while (rte_hash_iterate(runtime->l3_hash, (const void **)&vrfrd,
				(void **)&ctx, &next) >= 0) {
		l3_free_context(ctx);
	}
}

static inline void
l3_config_ring(struct l3_context *ctx, struct l3_request *r) {
	ctx->input = r->ring.input;
	for (int i = 0; i < VIF_MAX_INDEX; i++) {
		ctx->output[i] = r->ring.output[i];
	}
	ctx->tap = r->ring.tap;
	ctx->hostif = r->ring.hostif;
	ctx->notify_ring = r->ring.notify_ring;
}

// manage ribs
static void
l3_route_update(struct l3_context *ctx, struct l3_request *r) {
	struct route_table *rt = ctx->route;
	struct route_entry *re = &(r->route);
	lagopus_result_t ret = LAGOPUS_RESULT_OK;
	if (!rt & !re) {
		lagopus_printf("%s: %s: invalid args.\n", ctx->name, __func__);
		return;
	}
	switch (r->cmd) {
	case L3_CMD_ROUTE_ADD:
		ret = route_entry_add(rt, &(re->dest), (int)re->prefixlen,
				&(re->gate), re->ifindex, re->scope,
				re->metric, re->bridgeid);
		break;
	case L3_CMD_ROUTE_DELETE:
		ret = route_entry_delete(rt, &(re->dest), (int)re->prefixlen,
				&(re->gate), re->ifindex, re->metric);
		break;
	}

	if (ret != LAGOPUS_RESULT_OK)
		lagopus_printf("%s: %s: route update failed. (err: %d).",
				ctx->name, __func__, ret);
}

static void
l3_arp_update(struct l3_context *ctx, struct l3_request *r) {
	struct arp_table *at = ctx->arp;
	struct arp_entry *ae = &(r->arp);
	lagopus_result_t ret = LAGOPUS_RESULT_OK;
	if (!at & !ae) {
		lagopus_printf("%s: %s: invalid args.\n", ctx->name, __func__);
		return;
	}

	switch (r->cmd) {
	case L3_CMD_ARP_ADD:
		ret = arp_entry_update(at, (int)ae->ifindex, &(ae->ip), ae->mac);
		break;
	case L3_CMD_ARP_DELETE:
		ret = arp_entry_delete(at, (int)ae->ifindex, &(ae->ip), ae->mac);
		break;
	}

	if (ret != LAGOPUS_RESULT_OK)
		lagopus_printf("%s: %s: arp update failed. (err: %d).",
				ctx->name, __func__, ret);
}

static void
l3_interface_update(struct l3_context *ctx, struct l3_request *r) {
	struct interface_table *it = ctx->vif;
	struct interface_entry *ie = &(r->vif);
	lagopus_result_t ret = LAGOPUS_RESULT_OK;
	if (!it && !ie) {
		lagopus_printf("%s: %s: invalid args.\n", ctx->name, __func__);
		return;
	}
	switch (r->cmd) {
	case L3_CMD_INTERFACE_ADD:
		ret = interface_update(it, ie->ifindex, ie->mac);
		break;
	case L3_CMD_INTERFACE_DELETE:
		ret = interface_delete(it, ie->ifindex);
		break;
	case L3_CMD_INTERFACE_IP_ADD:
		ret = interface_self_update(it, ie->ip);
		if (ret == LAGOPUS_RESULT_OK)
			ret = interface_self_update(it, ie->broad);
		break;
	case L3_CMD_INTERFACE_IP_DELETE:
		ret = interface_self_delete(it, ie->ip);
		if (ret == LAGOPUS_RESULT_OK)
			ret = interface_self_delete(it, ie->broad);
		break;
	case L3_CMD_INTERFACE_HOSTIF_IP_ADD:
		ret = interface_hostif_update(it, ie->ip);
		break;
	case L3_CMD_INTERFACE_HOSTIF_IP_DELETE:
		ret = interface_hostif_delete(it, ie->ip);
		break;
	}

	if (ret != LAGOPUS_RESULT_OK)
		lagopus_printf("%s: %s: interface update failed. (err: %d).",
				ctx->name, __func__, ret);
}

static inline void
process_requests(struct l3_runtime *runtime, struct rte_ring *ring) {
	lagopus_result_t ret = LAGOPUS_RESULT_OK;
	static struct l3_request *reqs[MAX_L3_REQUESTS];
	unsigned req_count = rte_ring_dequeue_burst(ring, (void **)reqs,
			MAX_L3_REQUESTS);

	for (int i = 0; i < req_count; i++) {
		struct l3_request *r = reqs[i];
		struct l3_context *ctx;
		LAGOPUS_DEBUG("%s: (%d/%d) update tables. cmd: %d, vrfrd: %"PRIu64"\n",
				runtime->name, i, req_count, r->cmd, r->vrfrd);

		// pre check
		switch (r->cmd) {
			case L3_CMD_CREATE:
			case L3_CMD_QUIT:
				break;
			default:
				if (rte_hash_lookup_data(runtime->l3_hash, &r->vrfrd,
							(void **)&ctx) < 0) {
					continue;
				}
		}

		switch (r->cmd) {
			// manage the l3 instance
			case L3_CMD_CREATE:
				l3_create(runtime, r);
				break;
			case L3_CMD_DESTROY:
				l3_destroy(runtime, r);
				break;

			case L3_CMD_ENABLE:
				ctx->active = true;
				break;
			case L3_CMD_DISABLE:
				ctx->active = false;
				break;

			case L3_CMD_CONFIG_RING:
				l3_config_ring(ctx, r);

			// manage the rib
			case L3_CMD_ROUTE_ADD:
			case L3_CMD_ROUTE_DELETE:
				l3_route_update(ctx, r);
				break;
			case L3_CMD_ARP_ADD:
			case L3_CMD_ARP_DELETE:
				l3_arp_update(ctx, r);
				ret = route_entry_resolve_reset(ctx->route);
				if (ret != LAGOPUS_RESULT_OK)
					lagopus_printf("%s: %s:route_entry_resolve_reset() is failed(err: %d).",
						ctx->name, __func__, ret);
				break;
			case L3_CMD_INTERFACE_ADD:
			case L3_CMD_INTERFACE_IP_ADD:
			case L3_CMD_INTERFACE_HOSTIF_IP_ADD:
			case L3_CMD_INTERFACE_DELETE:
			case L3_CMD_INTERFACE_IP_DELETE:
			case L3_CMD_INTERFACE_HOSTIF_IP_DELETE:
				l3_interface_update(ctx, r);
				ret = route_entry_resolve_reset(ctx->route);
				if (ret != LAGOPUS_RESULT_OK)
					lagopus_printf("%s: %s:route_entry_resolve_reset() is failed(err: %d).",
						ctx->name, __func__, ret);
				break;

			// manage runtime
			case L3_CMD_QUIT:
				runtime->running = false;
				break;

		}
		free(r);
	}
}

//
// packet handling
//
static bool
check_ip_header(void *mbuf) {
	struct ipv4_hdr *ipv4 =
		rte_pktmbuf_mtod_offset((struct rte_mbuf *)mbuf,
			struct ipv4_hdr *, sizeof(struct ether_hdr));

	// check packet length
	uint16_t length = rte_cpu_to_be_16(ipv4->total_length);
	if (unlikely(length < 20)) {
		LAGOPUS_DEBUG("l3: %s(%d): invalid packet length(len = %d)\n",
				__func__, __LINE__, length);
		return false;
	}

	// validation header checksum
	struct ipv4_hdr tmp = *ipv4;
	tmp.hdr_checksum = 0;
	uint16_t checksum = rte_ipv4_cksum(&tmp);
	if (unlikely(ipv4->hdr_checksum != checksum)) {
		LAGOPUS_DEBUG("l3: %s(%d): invalid cehcksum(chksum = %u, calc chksum = %u)\n",
				__func__, __LINE__, ipv4->hdr_checksum, checksum);
		return false;
	}

	// check version
	uint8_t version = (ipv4->version_ihl & 0xf0) >> 4;
	if (likely(version == VERSION_IPV4)) {
		// supported, nothing to do.
	} else if (version == VERSION_IPV6) {
		// TODO: not supported.
		return false;
	} else {
		// not supported.
		return false;
	}

	// check header length
	uint8_t header_len = ipv4->version_ihl & 0x0f;
	if (likely(header_len == 5)) {
		// supported, nothing to do.
	} else if (header_len > 5) {
		// TODO: option header, not supported now.
		LAGOPUS_DEBUG("l3: %s(%d): option header\n", __func__, __LINE__);
		return false;
	} else {
		// invalid data.
		LAGOPUS_DEBUG("l3: %s(%d): invalid header length(length = %d)\n",
				__func__, __LINE__, header_len);
		return false;
	}

#if 0 //debug
	LAGOPUS_DEBUG("total len: %u, checksum: %u(hdr checksum: %u), version: %d, leader_len: %d\n",
			length, checksum, ipv4->hdr_checksum, version, header_len);
#endif

	return true;
}

static int
rewrite_pkt_header(void *mbuf, struct ether_addr *src, struct ether_addr *dst) {
	struct ether_hdr *eth =
		rte_pktmbuf_mtod((struct rte_mbuf *)mbuf, struct ether_hdr *);
	struct ipv4_hdr *ipv4 =
		rte_pktmbuf_mtod_offset((struct rte_mbuf *)mbuf,
					 struct ipv4_hdr *, sizeof(struct ether_hdr));

	LAGOPUS_DEBUG("l3: rewrite packet header \
src[%02x:%02x:%02x:%02x:%02x:%02x], dst[%02x:%02x:%02x:%02x:%02x:%02x]",
		src->addr_bytes[0], src->addr_bytes[1], src->addr_bytes[2],
		src->addr_bytes[3], src->addr_bytes[4], src->addr_bytes[5],
		dst->addr_bytes[0], dst->addr_bytes[1], dst->addr_bytes[2],
		dst->addr_bytes[3], dst->addr_bytes[4], dst->addr_bytes[5]);

	// rewrite ether header. (pkt, src hw addr, dst hw addr).
	ether_addr_copy(src, &(eth->s_addr));
	ether_addr_copy(dst, &(eth->d_addr));

	// check ttl and set checksum
	if (likely(ipv4->time_to_live > 0)) {
		ipv4->time_to_live--;
		if (unlikely(ipv4->hdr_checksum == 0xffff)) {
			// recalc checksum
			ipv4->hdr_checksum = 0;
			ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);
		} else {
			// update checksum
			ipv4->hdr_checksum++;
		}
	}

	return 0;
}

static int
check_tables(struct l3_context *ctx) {
	if (ctx->route == NULL) {
		// not found table
		lagopus_printf("%s: routing table not found.\n", ctx->name);
		return LAGOPUS_RESULT_INVALID_ARGS;
	} else if (ctx->arp == NULL) {
		// not found table
		lagopus_printf("%s: arp table not found.\n", ctx->name);
		return LAGOPUS_RESULT_INVALID_ARGS;
	} else if (ctx->vif == NULL) {
		// not found table
		lagopus_printf("%s: interface table not found.\n", ctx->name);
		return LAGOPUS_RESULT_INVALID_ARGS;
	}
	return LAGOPUS_RESULT_OK;
}

static int
lookup(void *mbuf, struct l3_context *ctx) {
	int ret = -1;
	uint64_t vrfrd;
	struct route_table *routetable = NULL;
	struct arp_table *arptable = NULL;
	struct interface_table *interfacetable = NULL;
	int ifindex;
	uint8_t scope;
	struct ether_addr dst_mac;
	struct ether_addr src_mac;
	struct in_addr nexthop, dst, broadcast;
	struct ipv4_hdr *ipv4;
	struct lagopus_packet_metadata *md = LAGOPUS_MBUF_METADATA(mbuf);

	// header check
	if (!check_ip_header(mbuf)) {
		//drop a packet.
		LAGOPUS_DEBUG("not support packet is drop.\n");
		rte_pktmbuf_free(mbuf);
		return L3_ACTION_DROP;
	}

	// get dst ip address from input packet.
	ipv4 = rte_pktmbuf_mtod_offset((struct rte_mbuf *)mbuf,
					struct ipv4_hdr *, sizeof(struct ether_hdr));
	dst.s_addr = ipv4->dst_addr;

	// get vrfrd
	vrfrd = md->md_vif.vrf;

	// get routing table by vrfrd
	if (check_tables(ctx)
			!= LAGOPUS_RESULT_OK) {
		rte_pktmbuf_free(mbuf);
		return LAGOPUS_RESULT_INVALID_ARGS;
	}

	// set local variables for coding.
	routetable = ctx->route;
	arptable = ctx->arp;
	interfacetable = ctx->vif;

	// send multicast packet for vrrp to hostif
	if (interface_is_hostif(interfacetable, dst) == true) {
		return L3_ACTION_TO_HOSTIF;
	}

	// check all self if.
	if (interface_is_self(interfacetable, dst) == true) {
		// send arp, icmp, ike and self unicast ip packets to tap
		return L3_ACTION_TO_KERNEL;
	}


	// lookup routing table
	int prefixlen = 32;
	uint32_t bridgeid = 0;
	uint32_t nhid = 0;
	ipv4_nexthop_t nh;
	ret = route_entry_get(routetable, &dst, prefixlen, &nh, &nhid);
	if (ret != 0) {
		lagopus_printf("%s: route entry not found.\n", ctx->name);
		// to return unreacheable message by kernel.
		return L3_ACTION_TO_KERNEL;
	}

	// decide the nexthop address.
	if (nh.scope == SCOPE_LINK) {
		nexthop = dst;
	} else {
		nexthop.s_addr = nh.gw;
	}

	// set bridge id to metadata to use it in forwading process.
	*(uint32_t *)md->udata = nh.bridgeid;

	ifindex = nh.ifindex;

	// check resolve flag.
	// NO_RESOLVE: have to lookup interface table and arp table.
	if (nh.resolve_status == NO_RESOLVE) {
		// get informations of the self interface.
		if (interface_get(interfacetable, ifindex, &src_mac) != LAGOPUS_RESULT_OK) {
			// drop this packet.
			lagopus_printf("%s: interface is not found.\n", ctx->name);
			rte_pktmbuf_free(mbuf);
			return L3_ACTION_DROP;
		}

		//get dst mac address and output port from arp table(hash table).
		ret = arp_get(arptable, &nexthop, &dst_mac);
		switch (ret) {
		case ARP_RESULT_OK:
			// arp entry is exist.
			break;
		case ARP_RESULT_TO_RESOLVE:
			// it is no entry on the arp table, send packet to tap(kernel).
			LAGOPUS_DEBUG("%s: arp entry not found, send to tap.\n",
					ctx->name);
			return L3_ACTION_TO_KERNEL;
		case ARP_RESULT_WAIT_RESOLUTION:
			return L3_ACTION_DROP;
		default:
			// TODO:
			lagopus_printf("arp table error.\n");
			return L3_ACTION_DROP;
		}

		// update arp result to routing table.
		route_resolve_update(routetable, nhid, nh.gw, nh.ifindex, nh.metric, &src_mac, &dst_mac);

		// rewrite header
		rewrite_pkt_header(mbuf, &src_mac, &dst_mac);
	} else {
		// it is not necessary to lookup tables.
		// rewrite header
		rewrite_pkt_header(mbuf, &(nh.src_mac), &(nh.dst_mac));
	}
	LAGOPUS_DEBUG("%s: vrf [%"PRIu64"], bridge [id: %"PRIu32", ifindex: %"PRIu32"]",
		ctx->name, vrfrd, nh.bridgeid, ifindex)

	// to dispatcher
	md->md_vif.in_vif = 0;

	return L3_ACTION_FORWARDING;
}

static int forward_packets(struct rte_mbuf *mbufs[],
		    int count, struct rte_ring **output) {
	int n = 0;
	while (count > 0) {
		struct lagopus_packet_metadata *md =
			LAGOPUS_MBUF_METADATA(mbufs[n]);
		uint32_t bridge_id = *(uint32_t *)md->udata;
		unsigned sent = rte_ring_enqueue_burst(
				output[bridge_id],
				(void * const*)&mbufs[n], count);
		count -= sent;
		n += sent;
	}
	return n;
}

static int dispatch_packets(struct rte_mbuf *mbufs[], int count,
		struct rte_ring *output) {
	int n = 0;
	while (count > 0) {
		struct lagopus_packet_metadata *md =
			LAGOPUS_MBUF_METADATA(mbufs[n]);
		unsigned sent = rte_ring_enqueue_burst(
				output, (void * const*)&mbufs[n], count);
		count -= sent;
		n += sent;
	}
	return n;
}

//
// call by frontend
//
int l3_task(void *arg) {
	struct l3_launch_param *p = arg;
	struct rte_ring *from_frontend = p->request;

	struct rte_mbuf *mbufs[MAX_L3_MBUFS];
	struct rte_mbuf *fwd_mbufs[MAX_L3_MBUFS];
	struct rte_mbuf *tap_mbufs[MAX_L3_MBUFS];
	struct rte_mbuf *hostif_mbufs[MAX_L3_MBUFS];

	struct l3_runtime *runtime;
	struct l3_context *ctx;

	LAGOPUS_DEBUG("%s: start backend.\n", p->name);

	if (!(runtime = rte_zmalloc(NULL, sizeof(struct l3_runtime), 0))) {
		lagopus_printf("%s: rte_malloc() failed. Can't start.", p->name);
		return -1;
	}

	// create hash table for l3
	struct rte_hash_parameters hash_params = {
		.name = p->name,
		.entries = MAX_L3_INSTANCES,
		.key_len = sizeof(uint64_t),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	// set runtime
	runtime->l3_hash = rte_hash_create(&hash_params);
	runtime->name = p->name;
	runtime->running = true;

	// free launch param.
	free(p);

	// start
	while (runtime->running) {
		uint32_t next = 0;
		uint64_t *vrfrd;
		struct l3_context *ctx;

		while (rte_hash_iterate(runtime->l3_hash, (const void **)&vrfrd,
					(void **)&ctx, &next) >= 0) {
			// skip if the l3 is not ready yet.
			if (!ctx->active)
				continue;

			//--- packet handring ---//
			// packet from input
			unsigned count = rte_ring_dequeue_burst(ctx->input,
					(void **)mbufs, MAX_L3_MBUFS);
			if (count > 0)
				LAGOPUS_DEBUG("%s: in_ring: got %u packets.\n",
						runtime->name, count);

			// lookup
			int n = 0;
			unsigned fwd_count = 0, tap_count = 0, hostif_count = 0;
			while (n < count) {
				int ret = lookup(mbufs[n], ctx);
				switch (ret) {
				case L3_ACTION_FORWARDING:
					fwd_mbufs[fwd_count++] = mbufs[n];
					break;
				case L3_ACTION_TO_KERNEL:
					tap_mbufs[tap_count++] = mbufs[n];
					break;
				case L3_ACTION_TO_HOSTIF:
					hostif_mbufs[hostif_count++] = mbufs[n];
					break;
				default:
					break;
				}
				n++;
			}
			// forward packets
			int sent = forward_packets(fwd_mbufs, fwd_count,
					ctx->output);
			if (sent > 0)
				LAGOPUS_DEBUG("%s: forward to bridge: out queued %u packets.\n",
					runtime->name, sent);
			sent = dispatch_packets(tap_mbufs, tap_count,
					ctx->tap);
			if (sent > 0)
				LAGOPUS_DEBUG("%s: forward to tap: out queued %u packets.\n",
						runtime->name, sent);
			sent = dispatch_packets(hostif_mbufs, hostif_count,
					ctx->hostif);
			if (sent > 0)
				LAGOPUS_DEBUG("%s: forward to hostif: out queued %u packets.\n",
						runtime->name, sent);
		}

		// check if there's any control message from the frontend.
		process_requests(runtime, from_frontend);
	}

	// clean up
	if (runtime->name)
		free(runtime->name);
	rte_free(runtime);

	return 0;
}

