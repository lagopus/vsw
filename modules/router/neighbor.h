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
 *      @file   neighbor.h
 *      @brief  Neighbor table.
 */

#ifndef VSW_MODULE_ROUTER_NEIGHBOR_H_
#define VSW_MODULE_ROUTER_NEIGHBOR_H_

#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include "router_common.h"

struct neighbor_table {
	struct rte_hash *hashmap; /**< hashtabble for neighbor information.*/
	struct neighbor *cache;
	int cache_size;
};

/* Neighbor APIs. */
struct neighbor_table *
neighbor_init(vifindex_t vif);

void
neighbor_fini(struct neighbor_table *nt);

bool
neighbor_entry_delete(struct neighbor_table *nt, uint32_t target);

struct neighbor *
neighbor_entry_update(struct neighbor_table *nt, struct neighbor_entry *ne);

struct neighbor *
neighbor_entry_get(struct neighbor_table *nt, uint32_t target);

static inline void
neighbor_entry_push_pending(struct neighbor *n, struct rte_mbuf *mbuf) {
	if (n->pending)
		rte_pktmbuf_free(n->pending);
	n->pending = mbuf;
}

static inline struct rte_mbuf *
neighbor_entry_pop_pending(struct neighbor *n) {
	struct rte_mbuf *mbuf = n->pending;
	n->pending = NULL;
	return mbuf;
}

static inline bool
neighbor_entry_has_pending(struct neighbor *n) {
	return n->pending != NULL;
}
#endif /* VSW_MODULE_ROUTER_NEIGHBOR_H_ */
