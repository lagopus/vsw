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

/**
 *      @file   pbr.c
 *      @brief  PBR entry management.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <linux/l2tp.h>
#include <netinet/in.h>

#include <rte_ether.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "ipproto.h"
#include "interface.h"
#include "pbr.h"
#include "router_common.h"
#include "router_log.h"

// Length of radix trie key supported by radix-trie library is 32 bit.
#define PBR_KEY_LEN 32

/*
 * Implement multi-dimensional PBR structure.
 * Each hierarchy of multidimensional trie is as follows.
 * 1: src address
 * 2: dst address
 * 3: protocol
 * 4: src port
 * 5: dst port
 * 6: input interface
 *
 * These fields are managed by index is defined by field_index.
 *
 * Use search() to search for an entry.
 * At that time, the search target is set in the array of keys
 * with field_index as index, and processing is performed in a loop.
 */

// field index of multi dimensional radix trie.
typedef enum {
	SRC_ADDRESS,
	DST_ADDRESS,
	PROTOCOL,
	SRC_PORT,
	DST_PORT,
	IN_INTERFACE,
	TUPLE_NUM,
} field_index;

struct l4_hdr {
	uint16_t src_port;
	uint16_t dst_port;
};

// nexthop information for pbr.
typedef struct pbr_nexthop {
	uint32_t priority;
	int nexthop_num;
	nexthop_t *nexthops;
} pbr_nexthop_t;

inline static char *
get_action_str(pbr_action_t action) {
	switch (action) {
	case PBRACTION_NONE:
		return "none";
	case PBRACTION_DROP:
		return "drop";
	case PBRACTION_PASS:
		return "pass";
	case PBRACTION_FORWARD:
		return "forward";
	default:
		return NULL;
	}
}
static void
print_nexthop(int index, nexthop_t *nh) {
	ROUTER_DEBUG(
	    "[PBR-ACTION(%d)] gw: %0x, weight: %u, ifindex: %u, action: %s",
	    index, nh->gw, nh->weight, nh->ifindex, get_action_str(nh->action));
}

static void
print_pbr_entry(struct pbr_entry *pbr) {
	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];
	uint32_t s = htonl(pbr->src_addr);
	uint32_t d = htonl(pbr->dst_addr);
	inet_ntop(AF_INET, &s, src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &d, dst, INET_ADDRSTRLEN);
	ROUTER_DEBUG(
	    "[PBR] priority:%d, addr[%s/%d:%s/%d], proto:%d, "
	    "port[%d..%d:%d..%d], if:%d, nh:%d",
	    pbr->priority, src, pbr->src_mask, dst, pbr->dst_mask,
	    pbr->protocol, pbr->src_port.from, pbr->src_port.to,
	    pbr->dst_port.from, pbr->dst_port.to, pbr->in_vif,
	    pbr->nexthop_num);

	for (int i = 0; i < pbr->nexthop_num; i++) {
		nexthop_t *nh = &pbr->nexthops[i];
		print_nexthop(i, nh);
	}
}

static bool
range_rule_add(struct rte_hash *hash, range_t *key, rt_value_t *val) {
	return rte_hash_add_key_data(hash, (uint32_t *)key, val) >= 0;
}

static inline rt_value_t *
range_rule_get(struct rte_hash *hash, range_t *key) {
	void *val;
	int ret = rte_hash_lookup_data(hash, &key, (void **)&val);
	if (unlikely(ret == -ENOENT))
		return NULL; // no entry.

	// Invalid parameter, assertion fail..
	assert(ret >= 0);

	return val;
}

// TODO
#if 0
static bool
range_rule_delete(struct rte_hash *hash, uint16_t from, uint16_t to) {
	uint32_t key = rule_create_key(from, to);
	if (rte_hash_del_key(hash, &key) < 0) {
		ROUTER_DEBUG("can not delete a key and data from hashmap.");
		return false;
	}
	return true;
}
#endif

static rt_value_t *
create_trie() {
	rt_value_t *rtv;
	if (!(rtv = rte_zmalloc(NULL, sizeof(rt_value_t), 0))) {
		return NULL;
	}
	struct rt *rt;
	if (!(rt = rt_new())) {
		rte_free(rtv);
		return NULL;
	}
	rtv->val = rt;
	rtv->type = PBR_RT_VALUE_TYPE_TRIE;
	return rtv;
}

static void
free_trie(rt_value_t *rtv) {
	if (!rtv)
		return;
	rt_free(rtv->val);
	rte_free(rtv);
}

static inline rt_value_t *
range_insert(struct rt *rt, struct rte_hash *hash, range_t port) {
	rt_value_t *rtv = range_rule_get(hash, &port);
	if (rtv)
		return rtv;

	rtv = create_trie();
	if (!rtv)
		return NULL;
	if (!range_rule_add(hash, &port, rtv)) {
		ROUTER_ERROR("Could not add range specification rule to hash table.(from: %u, to: %u)",
			     port.from, port.to);
		free_trie(rtv);
		return NULL;
	}

	if (!rt_insert_range(rt, (uint32_t)port.from, (uint32_t)port.to, rtv)) {
		// TODO: range_rule_delete
		free_trie(rtv);
		return NULL;
	}

	return rtv;
}

rt_value_t *
insert(struct rt *rt, uint32_t key, uint32_t len) {
	struct set *set = rt_alloc_node(rt, key, len);
	if (!set) {
		// TODO free set structure.
		return NULL;
	}
	// get next trie pointer.
	rt_value_t *rtv = set_get_first(set);
	if (rtv)
		return rtv;
	else {
		if (!(rtv = create_trie())) {
			// TODO: free set created by rt_alloc_node().
			return NULL;
		}
	}

	if (!set_insert(set, rtv)) {
		// TODO: free set created by rt_alloc_node().
		free_trie(rtv);
		return NULL;
	}
	return rtv;
}

rt_value_t *
insert_value(struct rt *rt, uint32_t key, uint32_t len, void *val) {
	struct set *set = rt_alloc_node(rt, key, len);
	if (!set) {
		// TODO free set structure.
		return NULL;
	}
	rt_value_t *value;
	if (!(value = rte_zmalloc(NULL, sizeof(rt_value_t), 0))) {
		// TODO: free set created by rt_alloc_node().
		return NULL;
	}
	value->val = val;
	value->type = PBR_RT_VALUE_TYPE_VALUE;

	if (!set_insert(set, value)) {
		// TODO: free set created by rt_alloc_node().
		rte_free(value);
		return NULL;
	}
	return value;
}

bool
pbr_entry_add(struct router_tables *tbls, struct pbr_entry *pbr) {
	if (VSW_LOG_DEBUG_ENABLED(router_log_id)) {
		print_pbr_entry(pbr);
	}

	struct pbr_table *pt = tbls->pbr;
	rt_value_t *rtv;
	// src addr.
	if (!(rtv = insert(pt->top->val, pbr->src_addr, pbr->src_mask)))
		return false;
	// dst addr.
	if (!(rtv = insert(rtv->val, pbr->dst_addr, pbr->dst_mask)))
		return false;
	// protocol.
	uint32_t len = pbr->protocol == IPPROTO_ANY ? 0 : PBR_KEY_LEN;
	if (!(rtv = insert(rtv->val, pbr->protocol, len)))
		return false;
	// src port.
	if (pbr->src_port.to == 0) {
		uint32_t len = pbr->src_port.from == 0 ? 0 : PBR_KEY_LEN;
		if (!(rtv = insert(rtv->val, (uint32_t)pbr->src_port.from, len)))
			return false;
	} else {
		if (!(rtv = range_insert(rtv->val, pt->sp_hash, pbr->src_port)))
			return false;
	}
	// dst port.
	if (pbr->dst_port.to == 0) {
		uint32_t len = pbr->dst_port.from == 0 ? 0 : PBR_KEY_LEN;
		if (!(rtv = insert(rtv->val, (uint32_t)pbr->dst_port.from, len)))
			return false;
	} else {
		if (!(rtv = range_insert(rtv->val, pt->dp_hash, pbr->dst_port)))
			return false;
	}
	// create result
	pbr_nexthop_t *nh = rte_zmalloc(NULL, sizeof(pbr_nexthop_t), 0);
	if (!nh) {
		ROUTER_ERROR("PBR result creation failed.");
		return false;
	}

	nh->priority = pbr->priority;
	nh->nexthop_num = pbr->nexthop_num;
	nh->nexthops = pbr->nexthops;
	for (int i = 0; i < pbr->nexthop_num; i++) {
		nh->nexthops[i].interface = interface_entry_get(tbls->interface, nh->nexthops[i].ifindex);
	}

	// input interface.
	len = pbr->in_vif == VIF_INVALID_INDEX ? 0 : PBR_KEY_LEN;

	if (!(insert_value(rtv->val, pbr->in_vif, len, nh)))
		return false;

	return true;
}

bool
pbr_entry_delete(struct pbr_table *pt, struct pbr_entry *pbr) {
// TODO: delete key and value of pbr entry.
//       radix trie library deletion processing needs to be updated.
#if 0

	rt_delete_key(rts.src_addr->val, pbr->src_addr, pbr->src_mask, rts.dst_addr);
	rt_delete_key(rts.dst_addr->val, pbr->dst_addr, pbr->dst_mask, rts.protocol);
	// protocol
	int len = pbr->protocol == IPPROTO_ANY ? 0 : PBR_KEY_LEN;
	rt_delete_key(rts.protocol->val, pbr->protocol, len, rts.src_port);

	// port
	if (pbr->src_port.to == 0) {
		len = pbr->src_port.from == 0 ? 0 : PBR_KEY_LEN;
		rt_delete_key(rts.src_port->val, pbr->src_port.from, len, rts.dst_port);
	} else {
		rt_delete_range(rts.src_port->val, pbr->src_port.from, pbr->src_port.to, rts.dst_port);
		range_rule_delete(pt->sp_hash, pbr->src_port.from, pbr->src_port.to);
	}
	if (pbr->dst_port.to == 0) {
		len = pbr->dst_port.from == 0 ? 0 : PBR_KEY_LEN;
		rt_delete_key(rts.dst_port->val, pbr->dst_port.from, len, rts.interface);
	} else {
		rt_delete_range(rts.dst_port->val, pbr->dst_port.from, pbr->dst_port.to, rts.interface);
		range_rule_delete(pt->dp_hash, pbr->dst_port.from, pbr->dst_port.to);
	}

	// interface
	len = pbr->in_vif == VIF_INVALID_INDEX ? 0 : PBR_KEY_LEN;
	rt_delete_key(rts.interface->val, pbr->in_vif, len, rts.nh);
	rte_free(rts.nh->val);
	rte_free(rts.nh);
#endif
	return true;
}

static pbr_nexthop_t *
_search(struct rt *rt, uint32_t *keys, int index) {
	if (index >= TUPLE_NUM)
		return NULL;

	int count = rt_search_key(rt, keys[index], PBR_KEY_LEN);
	ROUTER_DEBUG("[PBR] match count = %d, key = %x, len = %d",
		     count, keys[index], PBR_KEY_LEN);
	rt_value_t *ret;

	pbr_nexthop_t *rc = NULL;
	while (rt_iterate_results(rt, (void **)&ret)) {
		pbr_nexthop_t *nh = ret->val;

		if (ret->type == PBR_RT_VALUE_TYPE_TRIE) {
			nh = _search(ret->val, keys, index + 1);
		} else {
			nh = ret->val;
		}
		if (!(rc) || (rc->priority < nh->priority))
			rc = nh;
	}
	return rc;
}

static pbr_nexthop_t *
search(struct rt *rt, uint32_t *keys) {
	return _search(rt, keys, 0);
}

nexthop_t *
pbr_entry_get(struct pbr_table *pt, struct rte_mbuf *mbuf) {
	uint32_t keys[TUPLE_NUM] = {0};

	// input packet data.
	struct ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(
	    mbuf, struct ipv4_hdr *, sizeof(struct ether_hdr));
	struct vsw_packet_metadata *md = VSW_MBUF_METADATA(mbuf);
	// src ip address.
	keys[SRC_ADDRESS] = ntohl(iphdr->src_addr);
	// dst ip address.
	keys[DST_ADDRESS] = ntohl(iphdr->dst_addr);
	// protocol.
	uint8_t proto = iphdr->next_proto_id;
	keys[PROTOCOL] = proto;
	// src port and dst port in transport layer.
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		struct ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(
		    mbuf, struct ipv4_hdr *, sizeof(struct ether_hdr));
		struct l4_hdr *l4_hdr = (void *)ip_hdr + sizeof(struct ipv4_hdr);
		keys[SRC_PORT] = ntohs(l4_hdr->src_port);
		keys[DST_PORT] = ntohs(l4_hdr->dst_port);
	}

	// input interface index.
	keys[IN_INTERFACE] = md->common.in_vif;

	// debug
	ROUTER_DEBUG(
	    "[PBR] input packet: addr[%0x, %0x], proto:%d, port[%u,%u], in "
	    "if:%u",
	    keys[SRC_ADDRESS], keys[DST_ADDRESS], keys[PROTOCOL],
	    keys[SRC_PORT], keys[DST_PORT], keys[IN_INTERFACE]);

	// search from radix trie.
	pbr_nexthop_t *result = search(pt->top->val, keys);

	// no match rule.
	if (!result) {
		ROUTER_DEBUG("[PBR] no matching rule.");
		return NULL;
	}

	// for debug
	if (VSW_LOG_DEBUG_ENABLED(router_log_id)) {
		ROUTER_DEBUG("[PBR] priority: %" PRIu32 ", num: %d",
			     result->priority, result->nexthop_num);
		if (result->nexthop_num > 0) {
			nexthop_t *nh = &(result->nexthops[0]);
			print_nexthop(0, nh);
		}
	}

	// return first nexthop.
	// expect to be sorted in radix-trie library.
	return &(result->nexthops[0]);
}

static uint32_t
pbr_hash_func(const void *key, uint32_t length, uint32_t initval) {
	const uint32_t *p = (const uint32_t *)key;
	uint32_t v;

	assert(length == 4);

	v = rte_hash_crc_4byte(p[0], initval);

	return v;
}

static struct rte_hash *
create_hashmap(const char *name, const char *hname) {
	char hash_name[RTE_HASH_NAMESIZE];
	snprintf(hash_name, sizeof(hash_name), "%s_%s", hname, name);
	ROUTER_DEBUG("[PBR] (%s) pbr hashmap table name: %s\n", name,
		     hash_name);
	struct rte_hash_parameters hash_params = {
	    .name = hash_name,
	    .entries = PBR_RULE_MAX, // TODO
	    .key_len = sizeof(uint32_t),
	    .hash_func = pbr_hash_func,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};
	return rte_hash_create(&hash_params);
}

struct pbr_table *
pbr_init(const char *name) {
	struct pbr_table *pt;
	if (!(pt = rte_zmalloc(NULL, sizeof(struct pbr_table), 0))) {
		ROUTER_ERROR("router: %s: pbr table rte_zmalloc() failed.",
			     name);
		return NULL;
	}

	if (!(pt->top = create_trie())) {
		ROUTER_ERROR("[PBR] Error allocating radix tree.");
		rte_free(pt);
		return NULL;
	}

	pt->sp_hash = create_hashmap(name, "pbr_sp");
	pt->dp_hash = create_hashmap(name, "pbr_dp");
	if (!pt->sp_hash || !pt->dp_hash) {
		// If argument of rte_hash_free() is NULL,
		// return without doing anything.
		rte_hash_free(pt->sp_hash);
		rte_hash_free(pt->dp_hash);
		free_trie(pt->top);
		rte_free(pt);
		ROUTER_ERROR("[PBR] Error allocating hash table");
		return NULL;
	}

	return pt;
}

void
pbr_fini(struct pbr_table *pt) {
	if (!pt)
		return;
	rte_hash_free(pt->sp_hash);
	rte_hash_free(pt->dp_hash);
	free_trie(pt->top);
}
