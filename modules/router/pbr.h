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
	void *val;
	pbr_rt_value_t type;
} rt_value_t;

typedef struct pbr_table {
	rt_value_t *top;
	struct rte_hash *sp_hash;
	struct rte_hash *dp_hash;
} pbr_table_t;

struct pbr_table *
pbr_init(const char *name);
void
pbr_fini(struct pbr_table *pt);
bool
pbr_entry_add(struct router_tables *tbls, struct pbr_entry *entry);
bool
pbr_entry_delete(struct pbr_table *pt, struct pbr_entry *entry);
nexthop_t *
pbr_entry_get(struct pbr_table *pt, struct rte_mbuf *mbuf);

#endif /* VSW_MODULE_ROUTER_PBR_H_ */
