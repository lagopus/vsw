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
 *      @file   pbr.h
 *      @brief  PBR entry management.
 */

#ifndef VSW_MODULE_ROUTER_PBR_H_
#define VSW_MODULE_ROUTER_PBR_H_

#include "router_common.h"

#define PBR_RULE_MAX 256

// type of radix trie value.
typedef enum {
	PBR_RT_VALUE_TYPE_TRIE,
	PBR_RT_VALUE_TYPE_VALUE,
} pbr_rt_value_t;

typedef struct radix_trie_value {
	// The key length when the rule is registered.
	// This determines whether the rules are the same.
	// If key is any, key length is set to 0(ANY_KEY_LEN).
	uint32_t key_len;

	// The number of port range rules that reference this value.
	// It may be referenced from different rules.
	uint32_t ref_cnt;

	void *val;
	pbr_rt_value_t type;
} rt_value_t;

typedef struct pbr_table {
	uint32_t rule_num;
	rt_value_t *top;
	struct rte_hash *sp_hash;
	struct rte_hash *dp_hash;
} pbr_table_t;


// PBR action
struct pbr_action {
	uint32_t priority;
	bool pass;	// if true, forward to the default routing
	uint8_t nexthop_count;
};

// PBR action with nexthops
struct pbr_action_nh {
	struct pbr_action base;
	nexthop_t nexthops[ROUTER_MAX_PBR_NEXTHOPS];
};

struct pbr_table *
pbr_init(const char *name);

void
pbr_fini(struct pbr_table *pt);

bool
pbr_entry_add(struct router_tables *tbls, struct pbr_entry *entry);

bool
pbr_entry_delete(struct pbr_table *pt, struct pbr_entry *entry);

struct pbr_action *
pbr_entry_get(struct pbr_table *pt, struct rte_mbuf *mbuf);

static inline struct pbr_action_nh *
pbr_get_action_nh(struct pbr_action *act) {
	if (act == NULL || act->nexthop_count == 0)
		return NULL;
	return (struct pbr_action_nh *)act;
}

// XXX: We should implement Weighted ECMP in the future
static inline nexthop_t *
pbr_select_nexthop(struct pbr_action_nh *act_nh) {
	return &act_nh->nexthops[0];
}

#endif /* VSW_MODULE_ROUTER_PBR_H_ */
