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
 *      @file   neighbor.c
 *      @brief  Neighbor table use dpdk hash.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_hash_crc.h>

#include "neighbor.h"
#include "router_log.h"

/**
 * Get neighbor from neighbor hash table.
 */
struct neighbor *
neighbor_entry_get(struct neighbor_table *nt, uint32_t target) {
	int32_t ret = rte_hash_lookup(nt->hashmap, &target);

	if (unlikely(ret == -ENOENT)) {
		ret = rte_hash_add_key(nt->hashmap, &target);
		if (ret == -ENOSPC) {
			// TODO: Do GC. Quit for now.
			ROUTER_DEBUG("[NEIGH] no space for %02x.%02x.%02x.%02x",
				     (target >> 24) & 0xff, (target >> 16) & 0xff,
				     (target >>  8) & 0xff, target & 0xff);
			return NULL;
		}
		nt->cache[ret].addr = target;
	}

	assert(ret >= 0);

	nt->cache[ret].used = true;

	return &nt->cache[ret];
}

/**
 * Delete entry from hash table.
 */
bool
neighbor_entry_delete(struct neighbor_table *nt, uint32_t target) {
	int32_t ret = rte_hash_del_key(nt->hashmap, &target);

	if (ret < 0) {
		ROUTER_ERROR("[NEIGH] can't delete %02x.%02x.%02x.%02x",
			     (target >> 24) & 0xff, (target >> 16) & 0xff,
			     (target >>  8) & 0xff, target & 0xff);
		return false;
	}

	// ARP resolution may have failed. Free pending mbuf.
	struct rte_mbuf *mbuf = nt->cache[ret].pending;
	if (mbuf)
		rte_pktmbuf_free(mbuf);

	memset(&nt->cache[ret], 0, sizeof(struct neighbor));

	return true;
}

/**
 * Add entry to hash table.
 */
struct neighbor *
neighbor_entry_update(struct neighbor_table *nt, struct neighbor_entry *entry) {
	struct neighbor *ne = neighbor_entry_get(nt, entry->ip);

	if (ne == NULL)
		return NULL;

	ne->mac_addr = entry->mac;
	ne->valid    = true;
	ne->used     = false;

	return ne;
}

static uint32_t
neighbor_hash(const void *key, uint32_t key_len, uint32_t init_val) {
	return rte_hash_crc_4byte(*(uint32_t *)key, init_val);
}

/**
 * Initialize neighbor table.
 */
struct neighbor_table *
neighbor_init(vifindex_t vif) {
	struct neighbor_table *nt;
	if (!(nt = rte_zmalloc(NULL, sizeof(struct neighbor_table), 0))) {
		ROUTER_ERROR("[NEIGH] table alloc failed for VIF %d", vif);
		return NULL;
	}

	nt->cache_size = ROUTER_MAX_NEIGHBOR_ENTRIES;
	if (!(nt->cache = rte_zmalloc(NULL, sizeof(struct neighbor) * nt->cache_size, 0))) {
		ROUTER_ERROR("[NEIGH] cache alloc failed for VIF %d", vif);
		rte_free(nt);
		return NULL;
	}

	// Create hashmap
	char hash_name[RTE_HASH_NAMESIZE];
	snprintf(hash_name, sizeof(hash_name), "neigh_vif_%d", vif);

	struct rte_hash_parameters hash_params = {
	    .name = hash_name,
	    .entries = nt->cache_size,
	    .key_len = sizeof(uint32_t),
	    .hash_func = neighbor_hash,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	if (!(nt->hashmap = rte_hash_create(&hash_params))) {
		ROUTER_ERROR("[NEIGH] hash table alloc failed for VIF %d: %s",
			     vif, rte_strerror(rte_errno));
		rte_free(nt->cache);
		rte_free(nt);
		return NULL;
	}

	return nt;
}

/**
 * Finalize neighbor table.
 */
void
neighbor_fini(struct neighbor_table *nt) {
	if (!nt)
		return;
	uint32_t *ip;
	struct neighbor *entry;
	uint32_t next = 0;
	// Free all entries.
	while (rte_hash_iterate(nt->hashmap, (const void **)&ip,
				(void **)&entry, &next) >= 0)
		rte_free(entry);

	// Destroy hashmap for neighbor table.
	if (nt->hashmap)
		rte_hash_free(nt->hashmap);
	rte_free(nt->cache);
	rte_free(nt);
}
