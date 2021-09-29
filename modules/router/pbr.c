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

#include "interface.h"
#include "ipproto.h"
#include "pbr.h"
#include "router_common.h"
#include "router_log.h"

// Length of radix trie key supported by radix-trie library is 32 bit.
#define PBR_KEY_LEN 32
// 0 is any port.
#define PORT_ANY 0
// any key length
#define ANY_KEY_LEN 0

// If any is specified, the key length is 0(any key length).
#define PBR_GET_KEY_LEN(value, any) ((value == any) ? ANY_KEY_LEN : PBR_KEY_LEN)

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
// only the last index i s the nexthop.
typedef enum {
	SRC_ADDRESS,
	DST_ADDRESS,
	PROTOCOL,
	SRC_PORT,
	DST_PORT,
	IN_INTERFACE,
	NEXTHOP,
} field_index_t;

struct rt_values {
	// An array to hold the trie of each field and the value of nexthop.
	rt_value_t *rtv[NEXTHOP + 1];
};

static char *field_name[] = {"src addr", "dst addr", "protocol",
			     "src port", "dst port", "interface"};

struct l4_hdr {
	uint16_t src_port;
	uint16_t dst_port;
};

static bool delete_value(struct rt *rt, uint32_t key, uint32_t len, rt_value_t *val);
static bool delete_port_value(struct rte_hash *hash, struct rt *rt, rt_value_t *val, range_t port);

const char *
__s(void *p) {
	rt_value_t *v = p;
	struct pbr_action *act = v->val;
	static char buf[64];
	snprintf(buf, sizeof(buf), "prio=%d", act->priority);
	return buf;
};

static void
print_pbr_entry(struct pbr_entry *pbr, char *event_type) {
	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];
	uint32_t s = htonl(pbr->src_addr);
	uint32_t d = htonl(pbr->dst_addr);
	inet_ntop(AF_INET, &s, src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &d, dst, INET_ADDRSTRLEN);
	ROUTER_DEBUG(
	    "[PBR] %s: priority:%d, addr[%s/%d:%s/%d], proto:%d, "
	    "port[%d..%d:%d..%d], if:%d, nh_count:%d, pass=%s",
	    event_type,
	    pbr->priority, src, pbr->src_mask, dst, pbr->dst_mask,
	    pbr->protocol, pbr->src_port.from, pbr->src_port.to,
	    pbr->dst_port.from, pbr->dst_port.to, pbr->in_vif,
	    pbr->nexthop_count, pbr->pass ? "true" : "false");

	if (pbr->nexthop_count > 0) {
		struct pbr_entry_nh *pbr_nh = (struct pbr_entry_nh *)pbr;
		for (int i = 0; i < pbr->nexthop_count; i++) {
			struct pbr_nexthop *nh = &pbr_nh->nexthops[i];
			ROUTER_DEBUG(
			    "[PBR-NEXTHOP(%d)] gw: %02x.%02x.%02x.%02x, weight: %u, out_vif: %u",
			    i, (nh->gw >> 24) & 0xff, (nh->gw >> 16) & 0xff,
			    (nh->gw >> 8) & 0xff, nh->gw & 0xff,
			    nh->weight, nh->out_vif);
		}
	}
}

static bool
range_rule_add(struct rte_hash *hash, range_t *key, rt_value_t *val) {
	return rte_hash_add_key_data(hash, (uint32_t *)key, val) >= 0;
}

static inline rt_value_t *
range_rule_get(struct rte_hash *hash, range_t key) {
	void *val;
	int ret = rte_hash_lookup_data(hash, &key, (void **)&val);
	if (unlikely(ret == -ENOENT))
		return NULL; // no entry.

	// Lookup failed
	if (ret < 0) {
		ROUTER_ERROR("[PBR] rte_hash_lookup_data() failed, err = %d.", ret);
		return NULL;
	}

	return val;
}

static bool
range_rule_delete(struct rte_hash *hash, range_t key) {
	// If the value is not referenced, remove it from the tree.
	int ret = rte_hash_del_key(hash, &key);
	if (ret < 0) {
		// It is also an error if the entry does not exist.
		ROUTER_ERROR("[PBR] Can not delete a key and data from hashmap, err = %d.", ret);
		return false;
	}
	return true;
}

static rt_value_t *
create_trie(uint32_t len) {
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
	rtv->key_len = len;
	rtv->ref_cnt = 1;
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
	rt_value_t *rtv = range_rule_get(hash, port);
	if (rtv) {
		// If the same value is used, increment the reference counter.
		// It is released only when the reference counter is 1 at the time of deletion.
		rtv->ref_cnt++;
		return rtv;
	}

	rtv = create_trie(PBR_KEY_LEN);
	if (!rtv)
		return NULL;
	if (!range_rule_add(hash, &port, rtv)) {
		ROUTER_ERROR("[PBR] Could not add range specification rule to hash table.(from: %u, to: %u)",
			     port.from, port.to);
		free_trie(rtv);
		return NULL;
	}

	if (!rt_insert_range(rt, (uint32_t)port.from, (uint32_t)port.to, rtv)) {
		// Error check is unnecessary because it is a deletion process for rollback.
		range_rule_delete(hash, port);
		free_trie(rtv);
		return NULL;
	}

	return rtv;
}

rt_value_t *
insert(struct rt *rt, uint32_t key, uint32_t len) {
	struct set *set = rt_alloc_node(rt, key, len);
	if (!set) {
		return NULL;
	}
	// get next trie pointer.
	rt_value_t *rtv = set_get_first(set);
	if (!rtv) {
		if (!(rtv = create_trie(len))) {
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

bool
insert_value(struct rt *rt, uint32_t key, uint32_t len, void *val) {
	struct set *set = rt_alloc_node(rt, key, len);
	if (!set) {
		return false;
	}
	rt_value_t *value;
	if (!(value = rte_zmalloc(NULL, sizeof(rt_value_t), 0))) {
		// TODO: free set created by rt_alloc_node().
		return false;
	}
	value->val = val;
	value->key_len = len;
	value->type = PBR_RT_VALUE_TYPE_VALUE;

	if (!set_insert(set, value)) {
		// TODO: free set created by rt_alloc_node().
		rte_free(value);
		return false;
	}
	return true;
}

// rollback_failed_add rollback by removing the added entry.
// failed_index is index number of the hierarchy that faield to be added.
static void
rollback_failed_add(struct pbr_table *pt, struct pbr_entry *pbr, struct rt_values *vs, field_index_t failed_index) {
	ROUTER_DEBUG("[PBR] Rollback from previous field. index = %d\n", failed_index);
	// If the deletion process fails, no rollback is performed.
	rt_value_t **rtv = vs->rtv;
	// Additional processing failed in processing after failed field.
	// Delete entry from previous field.
	if (IN_INTERFACE < failed_index)
		if (!delete_port_value(pt->dp_hash, rtv[DST_PORT]->val,
				       rtv[IN_INTERFACE], pbr->dst_port))
			ROUTER_ERROR("[PBR] rollback failed at DST_PORT field.");

	if (DST_PORT < failed_index)
		if (!delete_port_value(pt->sp_hash, rtv[SRC_PORT]->val,
				       rtv[DST_PORT], pbr->src_port))
			ROUTER_ERROR("[PBR] rollback failed at SRC_PORT field.");

	if (SRC_PORT < failed_index) {
		uint32_t len = PBR_GET_KEY_LEN(pbr->protocol, IPPROTO_ANY);
		if (!delete_value(rtv[PROTOCOL]->val,
				  pbr->protocol, len, rtv[SRC_PORT]))
			ROUTER_ERROR("[PBR] rollback failed at PROTOCOL field.");
	}

	if (PROTOCOL < failed_index)
		if (!delete_value(rtv[DST_ADDRESS]->val,
				  pbr->dst_addr, pbr->dst_mask, rtv[PROTOCOL]))
			ROUTER_ERROR("[PBR] rollback failed at DST_ADDRESS field.");

	if (DST_ADDRESS < failed_index)
		if (!delete_value(rtv[SRC_ADDRESS]->val,
				  pbr->src_addr, pbr->src_mask, rtv[DST_ADDRESS]))
			ROUTER_ERROR("[PBR] rollback failed at SRC_ADDRESS field.");
}

bool
pbr_entry_add(struct router_tables *tbls, struct pbr_entry *pbr) {
	if (VSW_LOG_DEBUG_ENABLED(router_log_id)) {
		print_pbr_entry(pbr, "Add");
	}

	// Do not change the order of addition and rollback.
	struct pbr_table *pt = tbls->pbr;
	struct rt_values vs;
	vs.rtv[SRC_ADDRESS] = pt->top;

	// src addr.
	vs.rtv[DST_ADDRESS] = insert(vs.rtv[SRC_ADDRESS]->val, pbr->src_addr, pbr->src_mask);
	if (!vs.rtv[DST_ADDRESS])
		return false;

	// dst addr.
	vs.rtv[PROTOCOL] = insert(vs.rtv[DST_ADDRESS]->val, pbr->dst_addr, pbr->dst_mask);
	if (!vs.rtv[PROTOCOL]) {
		rollback_failed_add(pt, pbr, &vs, PROTOCOL);
		return false;
	}

	// protocol.
	uint32_t len = PBR_GET_KEY_LEN(pbr->protocol, IPPROTO_ANY);
	vs.rtv[SRC_PORT] = insert(vs.rtv[PROTOCOL]->val, pbr->protocol, len);
	if (!vs.rtv[SRC_PORT]) {
		rollback_failed_add(pt, pbr, &vs, SRC_PORT);
		return false;
	}

	// src port.
	if (pbr->src_port.to == PORT_ANY) {
		len = PBR_GET_KEY_LEN(pbr->src_port.from, PORT_ANY);
		vs.rtv[DST_PORT] = insert(vs.rtv[SRC_PORT]->val,
					  (uint32_t)pbr->src_port.from, len);
	} else {
		vs.rtv[DST_PORT] = range_insert(vs.rtv[SRC_PORT]->val,
						pt->sp_hash, pbr->src_port);
	}
	if (!vs.rtv[DST_PORT]) {
		rollback_failed_add(pt, pbr, &vs, DST_PORT);
		return false;
	}

	// dst port.
	if (pbr->dst_port.to == PORT_ANY) {
		len = PBR_GET_KEY_LEN(pbr->dst_port.from, PORT_ANY);
		vs.rtv[IN_INTERFACE] = insert(vs.rtv[DST_PORT]->val,
					      (uint32_t)pbr->dst_port.from, len);
	} else {
		vs.rtv[IN_INTERFACE] = range_insert(vs.rtv[DST_PORT]->val,
						    pt->dp_hash, pbr->dst_port);
	}
	if (!vs.rtv[IN_INTERFACE]) {
		rollback_failed_add(pt, pbr, &vs, IN_INTERFACE);
		return false;
	}

	// create result
	size_t size = (pbr->nexthop_count == 0) ?
			sizeof(struct pbr_action) : sizeof(struct pbr_action_nh);
	struct pbr_action *act = rte_zmalloc(NULL, size, 0);

	if (!act) {
		ROUTER_ERROR("[PBR] result creation failed.");
		rollback_failed_add(pt, pbr, &vs, NEXTHOP);
		return false;
	}

	act->priority = pbr->priority;
	act->pass = pbr->pass;
	act->nexthop_count = pbr->nexthop_count;

	if (pbr->nexthop_count > 0) {
		struct pbr_entry_nh *pbr_nh = (struct pbr_entry_nh *)pbr;
		struct pbr_action_nh *act_nh = (struct pbr_action_nh*)act;

		for (int i = 0; i < pbr->nexthop_count; i++) {
			act_nh->nexthops[i].weight = pbr_nh->nexthops[i].weight;
			act_nh->nexthops[i].gw = pbr_nh->nexthops[i].gw;
			act_nh->nexthops[i].ifindex = pbr_nh->nexthops[i].out_vif;

			if (pbr_nh->nexthops[i].out_vif != VIF_INVALID_INDEX)
				act_nh->nexthops[i].interface = interface_entry_get(tbls->interface,
										pbr_nh->nexthops[i].out_vif);

			// Add reference of a nexthop that refer to a interface
			if (act_nh->nexthops[i].interface &&
			    !interface_nexthop_reference_add(act_nh->nexthops[i].interface,
							     &act_nh->nexthops[i])) {
				rte_free(act_nh);
				rollback_failed_add(pt, pbr, &vs, NEXTHOP);
				return false;
			}
		}
	}

	// input interface.
	len = PBR_GET_KEY_LEN(pbr->in_vif, VIF_INVALID_INDEX);
	if (!insert_value(vs.rtv[IN_INTERFACE]->val, pbr->in_vif, len, act)) {
		rollback_failed_add(pt, pbr, &vs, NEXTHOP);
		return false;
	}

	if (VSW_LOG_DEBUG_ENABLED(router_log_id))
		rt_dump2(vs.rtv[IN_INTERFACE]->val, __s);

	pt->rule_num++;
	return true;
}

static rt_value_t *
get_action(struct rt *rt, uint32_t key, uint32_t priority) {
	// key is specified in the registered rule
	// So there is only one result that matches trie
	uint32_t len = PBR_GET_KEY_LEN(key, VIF_INVALID_INDEX);
	rt_search_key(rt, key, len);
	rt_value_t *ret;
	while (rt_iterate_results(rt, (void **)&ret)) {
		struct pbr_action *act = (struct pbr_action *)ret->val;
		if (act->priority == priority)
			return ret;
	}
	return NULL;
}

static rt_value_t *
get_value(struct rt *rt, uint32_t key, uint32_t len) {
	// key is specified in the registered rule
	// So there is only one result that matches trie
	rt_search_key(rt, key, len);
	rt_value_t *ret;
	while (rt_iterate_results(rt, (void **)&ret)) {
		if (ret->key_len == len)
			return ret;
	}
	return NULL;
}

bool
get_values(struct pbr_table *pt, struct pbr_entry *pbr, struct rt_values *vals) {
	uint32_t len; // key length

	// Trie for src address is generated by pbr initialization process
	vals->rtv[SRC_ADDRESS] = pt->top;

	// Get trie of each layer.
	// If trie cannot be obtained,
	// the nexthop registration is not completed, so the process is interrupted.
	vals->rtv[DST_ADDRESS] = get_value(pt->top->val,
					   pbr->src_addr, pbr->src_mask);
	if (!vals->rtv[DST_ADDRESS]) {
		ROUTER_ERROR("[PBR] Failed to get trie(src: %x/%d)",
			     pbr->src_addr, pbr->src_mask);
		return false;
	}

	vals->rtv[PROTOCOL] = get_value(vals->rtv[DST_ADDRESS]->val,
					pbr->dst_addr, pbr->dst_mask);
	if (!vals->rtv[PROTOCOL]) {
		ROUTER_ERROR("[PBR] Failed to get trie(dst: %x/%d)",
			     pbr->dst_addr, pbr->dst_mask);
		return false;
	}

	len = PBR_GET_KEY_LEN(pbr->protocol, IPPROTO_ANY);
	vals->rtv[SRC_PORT] = get_value(vals->rtv[PROTOCOL]->val,
					pbr->protocol, len);
	if (!vals->rtv[SRC_PORT]) {
		ROUTER_ERROR("[PBR] Failed to get trie(protocol: %x/%d)",
			     pbr->protocol, len);
		return false;
	}

	if (pbr->src_port.to == PORT_ANY) {
		len = PBR_GET_KEY_LEN(pbr->src_port.from, PORT_ANY);
		vals->rtv[DST_PORT] = get_value(vals->rtv[SRC_PORT]->val,
						pbr->src_port.from, len);
	} else {
		vals->rtv[DST_PORT] = range_rule_get(pt->sp_hash, pbr->src_port);
	}
	if (!vals->rtv[DST_PORT]) {
		ROUTER_ERROR("[PBR] Failed to get trie(src port: %d-%d)",
			     pbr->src_port.from, pbr->src_port.to);
		return false;
	}

	if (pbr->dst_port.to == PORT_ANY) {
		len = PBR_GET_KEY_LEN(pbr->dst_port.from, PORT_ANY);
		vals->rtv[IN_INTERFACE] = get_value(vals->rtv[DST_PORT]->val,
						    pbr->dst_port.from, len);
	} else {
		vals->rtv[IN_INTERFACE] = range_rule_get(pt->dp_hash, pbr->dst_port);
	}
	if (!vals->rtv[IN_INTERFACE]) {
		ROUTER_ERROR("[PBR] Failed to get trie(dst port: %d-%d)",
			     pbr->dst_port.from, pbr->dst_port.to);
		return false;
	}

	// value of nexthop
	vals->rtv[NEXTHOP] = get_action(vals->rtv[IN_INTERFACE]->val,
					pbr->in_vif, pbr->priority);
	if (!vals->rtv[NEXTHOP]) {
		ROUTER_ERROR("[PBR] Failed to get trie(in interface: %x)",
			     pbr->in_vif);
		return false;
	}
	return true;
}

static bool
delete_port_value(struct rte_hash *hash, struct rt *rt, rt_value_t *val, range_t port) {

	bool ret = true;
	if (port.to == PORT_ANY) {
		uint32_t len = PBR_GET_KEY_LEN(port.from, PORT_ANY);
		if (!(ret = rt_delete_key(rt, port.from, len, val)))
			ROUTER_ERROR("[PBR] Failed to rt_delete_key (port from=%, len=%d)",
				     port.from, len);
	} else {
		if (!rt_delete_range(rt, port.from, port.to, val)) {
			ROUTER_ERROR("[PBR] Failed to rt_delete_range (port from= %x, to= %d)",
				     port.from, port.to);
			ret = false;
		}
		val->ref_cnt--;
		if (val->ref_cnt > 0)
			return ret;
		if (!range_rule_delete(hash, port)) {
			ROUTER_ERROR("[PBR] Failed to range_rule_delete (port from= %x, to= %d)",
				     port.from, port.to);
			ret = false;
		}
	}

	ROUTER_DEBUG("[PBR] Delete port value: port[%d-%d], ref = %d\n",
		     port.from, port.to, val->ref_cnt);

	return ret;
}

static bool
delete_value(struct rt *rt, uint32_t key, uint32_t len, rt_value_t *val) {
	if (!rt_delete_key(rt, key, len, val)) {
		ROUTER_ERROR("[PBR] Failed to delete rule(key=%x(%d), len=%d)",
			     key, key, len);
		return false;
	}

	ROUTER_DEBUG("[PBR] Delete value of single key: key=%x(%d), len=%d\n",
		     key, key, len);

	return true;
}

bool
pbr_entry_delete(struct pbr_table *pt, struct pbr_entry *pbr) {
	if (VSW_LOG_DEBUG_ENABLED(router_log_id)) {
		print_pbr_entry(pbr, "Delete");
	}

	// Get trie of each layer
	struct rt_values vals;
	if (!get_values(pt, pbr, &vals))
		return false;

	uint32_t len;
	bool ret = true;

	if (VSW_LOG_DEBUG_ENABLED(router_log_id))
		rt_dump2(vals.rtv[IN_INTERFACE]->val, __s);

	// Get value and delete interface rule
	len = PBR_GET_KEY_LEN(pbr->in_vif, VIF_INVALID_INDEX);
	if (!delete_value(vals.rtv[IN_INTERFACE]->val, pbr->in_vif, len, vals.rtv[NEXTHOP]))
		ret = false;

	if (VSW_LOG_DEBUG_ENABLED(router_log_id))
		rt_dump2(vals.rtv[IN_INTERFACE]->val, __s);

	// Delete the specified key from radix trie
	if (!delete_port_value(pt->dp_hash, vals.rtv[DST_PORT]->val, vals.rtv[IN_INTERFACE], pbr->dst_port))
		ret = false;

	if (!delete_port_value(pt->sp_hash, vals.rtv[SRC_PORT]->val, vals.rtv[DST_PORT], pbr->src_port))
		ret = false;

	len = PBR_GET_KEY_LEN(pbr->protocol, IPPROTO_ANY);
	if (!delete_value(vals.rtv[PROTOCOL]->val, pbr->protocol, len, vals.rtv[SRC_PORT]))
		ret = false;

	if (!delete_value(vals.rtv[DST_ADDRESS]->val, pbr->dst_addr, pbr->dst_mask, vals.rtv[PROTOCOL]))
		ret = false;

	if (!delete_value(vals.rtv[SRC_ADDRESS]->val, pbr->src_addr, pbr->src_mask, vals.rtv[DST_ADDRESS]))
		ret = false;

	// Only if all fileds have been successfully deleted
	if (ret)
		pt->rule_num--;
	return ret;
}

static struct pbr_action *
_search(struct rt *rt, uint32_t *keys, field_index_t index) {
	assert(index < NEXTHOP);

	int count = rt_search_key(rt, keys[index], PBR_KEY_LEN);
	ROUTER_DEBUG("[PBR] (%s) match count = %d, key = %x(%d), len = %d",
		     field_name[index], count, keys[index], keys[index], PBR_KEY_LEN);

	if (count == 0)
		return NULL;

	rt_value_t *ret;
	struct pbr_action *action = NULL;
	while (rt_iterate_results(rt, (void **)&ret)) {
		struct pbr_action *candidate = ret->val;

		if (ret->type == PBR_RT_VALUE_TYPE_TRIE)
			candidate = _search(ret->val, keys, index + 1);

		if (!(action) || ((candidate) && (action->priority < candidate->priority)))
			action = candidate;
	}
	return action;
}

static struct pbr_action *
search(struct rt *rt, uint32_t *keys) {
	return _search(rt, keys, 0);
}

struct pbr_action *
pbr_entry_get(struct pbr_table *pt, struct rte_mbuf *mbuf) {
	uint32_t keys[NEXTHOP] = {0};

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
	struct pbr_action *action = search(pt->top->val, keys);

	// no match rule.
	if (!action) {
		ROUTER_DEBUG("[PBR] no matching rule.");
		return NULL;
	}

	// for debug
	if (VSW_LOG_DEBUG_ENABLED(router_log_id)) {
		ROUTER_DEBUG("[PBR] priority: %" PRIu32 ", num: %d",
			     action->priority, action->nexthop_count);

		struct pbr_action_nh *action_nh = pbr_get_action_nh(action);
		if (action_nh) {
			nexthop_t *nh = &action_nh->nexthops[0];
			ROUTER_DEBUG(
			    "[PBR-NEXTHOP(0)] gw: %0x, weight: %u, ifindex: %u",
			    nh->gw, nh->weight, nh->ifindex);
		}
	}

	// XXX: return the whole action. we must do Weighted ECMP in the future.
	return action;
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

	if (!(pt->top = create_trie(ANY_KEY_LEN))) {
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
	rte_hash_reset(pt->sp_hash);
	rte_hash_reset(pt->dp_hash);
	rte_hash_free(pt->sp_hash);
	rte_hash_free(pt->dp_hash);
	free_trie(pt->top);
	rte_free(pt);
}
