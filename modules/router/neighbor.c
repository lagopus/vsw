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
#include <rte_errno.h>
#include <rte_malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "neighbor.h"
#include "router_log.h"

static void
print_neighbor_entry(char *str, neighbor_t *neigh) {
	if (!neigh)
		return;

	ROUTER_DEBUG("[NEIGH] %s: ip: %s, mac: %s, state: %d, ifindex: %d\n",
		     str, ip2str(neigh->ip_addr),
		     mac2str(neigh->mac_addr), neigh->state, neigh->ifindex);
}

static void
print_neighbor_list(struct neighbor_table *nt) {
	neighbor_t *neigh;
	uint32_t *idx;
	uint32_t next = 0;

	while (rte_hash_iterate(nt->hashmap, (const void **)&idx,
				(void **)&neigh, &next) >= 0) {
		print_neighbor_entry("List", neigh);
	}
}

/**
 * Clean neighbor table.
 */
static void
neighbor_table_clean(struct neighbor_table *nt) {
	uint32_t *ip;
	neighbor_t *entry;
	uint32_t next = 0;
	uint32_t removed = 0; // For debug.

	while (rte_hash_iterate(nt->hashmap, (const void **)&ip,
				(void **)&entry, &next) >= 0) {
		rte_hash_del_key(nt->hashmap, ip);
		rte_free(entry);
		removed++;
	}

	// For debug.
	if (removed > 0) {
		ROUTER_DEBUG("[NEIGH] Free %d entries.\n", removed);
	} else {
		ROUTER_INFO("[NEIGH] Couldn't free entry, all entry valid.\n");
		// Flush neighbor table
		rte_hash_reset(nt->hashmap);
	}
}

/**
 * Create neighbor.
 */
static neighbor_t *
neighbor_create(struct neighbor_entry *ne) {
	neighbor_t *neigh = rte_zmalloc(NULL, sizeof(neighbor_t), 0);
	if (!neigh) {
		ROUTER_ERROR("[NEIGH] rte_zmalloc() failed.");
		return NULL;
	}

	// Set neighbor
	neigh->ip_addr = ne->ip;
	ether_addr_copy(&(ne->mac), &(neigh->mac_addr));
	neigh->state = ne->state;
	neigh->ifindex = ne->ifindex;

	return neigh;
}

/**
 * Add neighbor to hash table.
 */
static bool
neighbor_add(struct neighbor_table *nt, neighbor_t *neigh) {
	if (nt->neighbor_num > IPV4_MAX_NEXTHOPS)
		neighbor_table_clean(nt);

	int ret = rte_hash_add_key_data(nt->hashmap, &neigh->ip_addr, neigh);
	// No space in the hash for this key.
	if (ret == -ENOSPC) {
		ROUTER_INFO("[NEIGH] Failed to add neighbor entry, hashtable is full.\n");
		// Free unused entries.
		neighbor_table_clean(nt);
		// To add again.
		neighbor_add(nt, neigh);
	}
	// Parameters are invalid.
	else if (ret == -EINVAL) {
		ROUTER_ERROR("[NEIGH] Failed to add neighbor entry, invalid arguments.");
		return false;
	}

	nt->neighbor_num++;
	return true;
}

/**
 * Get neighbor from neighbor hash table.
 */
neighbor_t *
neighbor_entry_get(struct neighbor_table *nt, uint32_t ip) {
	neighbor_t *neigh;
	int ret = rte_hash_lookup_data(nt->hashmap,
				       (const void *)&(ip),
				       (void **)&neigh);
	// No entry
	if (unlikely(ret == -ENOENT)) {
		// no neighbor entry
		ROUTER_DEBUG("[NEIGH] no neighbor entry. ip = %s\n", ip2str(ip));
		return NULL;
	}
	// Invalid parameter, assertion fail..
	assert(ret >= 0);

	return neigh;
}

/**
 * Delete entry from hash table.
 */
bool
neighbor_entry_delete(struct neighbor_table *nt, struct neighbor_entry *entry) {
	neighbor_t *neigh;
	/* free entry data. */
	int ret = rte_hash_lookup_data(nt->hashmap, &(entry->ip), (void **)&neigh);
	// No entry
	if (unlikely(ret == -ENOENT)) {
		// TODO: If ret is -EINVAL, should panic.
		ROUTER_INFO("[NEIGH] neighbor entry free failed.(key:%s, ret:%d).",
			    ip2str(entry->ip), ret);
		return NULL;
	}
	// Invalid parameter, assertion fail..
	assert(ret >= 0);

	if (neigh) {
		if (rte_hash_del_key(nt->hashmap, &(entry->ip)) < 0) {
			ROUTER_ERROR("[NEIGH] not found neighbor.");
			return false;
		}
		rte_free(neigh);
	}

	return true;
}

/**
 * Add entry to hash table.
 */
bool
neighbor_entry_update(struct neighbor_table *nt, struct neighbor_entry *entry) {
	// Check if entry is exist in arp table.
	neighbor_t *neigh;
	int ret = rte_hash_lookup_data(nt->hashmap, &(entry->ip), (void **)&neigh);
	// No entry
	if (unlikely(ret == -ENOENT)) {
		neighbor_t *ne = neighbor_create(entry);
		if (!ne)
			return false;
		neighbor_add(nt, ne);
		print_neighbor_list(nt);
		return true;
	}
	// Invalid parameter, assertion fail..
	assert(ret >= 0);

	// Entry exists.
	ether_addr_copy(&(entry->mac), &(neigh->mac_addr));
	neigh->state = entry->state;
	print_neighbor_list(nt);
	return true;
}

/**
 * Initialize neighbor table.
 */
struct neighbor_table *
neighbor_init(const char *name) {
	struct neighbor_table *nt;
	if (!(nt = rte_zmalloc(NULL, sizeof(struct neighbor_table), 0))) {
		ROUTER_ERROR("router: %s: neighbor table rte_zmalloc() failed.", name);
		return NULL;
	}

	// Create hashmap
	char hash_name[RTE_HASH_NAMESIZE];
	snprintf(hash_name, sizeof(hash_name), "neighbor_%s", name);
	ROUTER_DEBUG("[NEIGH] (%s) neighbor table name: %s\n", name, hash_name);
	struct rte_hash_parameters hash_params = {
	    .name = hash_name,
	    .entries = IPV4_MAX_NEXTHOPS, // TODO: MAX number of neigbor entries.
	    .key_len = sizeof(uint32_t),
	    .hash_func = rte_jhash,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};
	nt->hashmap = rte_hash_create(&hash_params);
	if (!nt->hashmap) {
		ROUTER_ERROR("[NEIGH] Error allocating hash table");
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
	neighbor_t *entry;
	uint32_t next = 0;
	// Free all entries.
	while (rte_hash_iterate(nt->hashmap, (const void **)&ip,
				(void **)&entry, &next) >= 0)
		rte_free(entry);

	// Destroy hashmap for neighbor table.
	if (nt->hashmap)
		rte_hash_free(nt->hashmap);
}
