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
 *      @file   interface.c
 *      @brief  Interface table.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <rte_ether.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_malloc.h>

#include "interface.h"
#include "router.h"

#include "packet.h"
#include "router_log.h"

// Increase capacity of nexthop list by 4,
// as 4 nexthops is added when a route is added generally.
#define NEXTHOPS_CAPACITY_INCREMENT 4

static void
print_interface_entry(char *str, struct interface *interface) {
	if (!interface)
		return;

	struct interface_entry *ie = &interface->base;

	ROUTER_DEBUG("[INTERFACE] %s: ifindex: %" PRIu32 ", mac: %s, mtu: %d, vid: %d\n",
		     str, ie->ifindex, mac2str(ie->mac), ie->mtu, ie->vid);
	for (int i = 0; i < ROUTER_MAX_VIF_IPADDRS && interface->addr[i].addr != 0; i++) {
		ROUTER_DEBUG("\t\t\t\t: addr[%d] %s\n", i, ip2str(interface->addr[i].addr));
	}
}

static void
print_interface_list(struct interface_table *interface_table) {
	struct interface *interface;
	uint32_t *idx;
	uint32_t next = 0;

	while (rte_hash_iterate(interface_table->hashmap, (const void **)&idx,
				(void **)&interface, &next) >= 0) {
		print_interface_entry("List", interface);
	}
}

static uint32_t
self_hash_func(const void *key, uint32_t length, uint32_t initval) {
	assert(length == 8);
	return rte_hash_crc_8byte(*(uint64_t *)key, initval);
}

/*** public functions ***/
/**
 * Initialize interface table.
 */
struct interface_table *
interface_init(const char *name) {
	struct interface_table *it;
	if (!(it = rte_zmalloc(NULL, sizeof(struct interface_table), 0))) {
		ROUTER_ERROR("router: %s: interface table rte_zmalloc() failed.", name);
		return NULL;
	}

	char hash_name[RTE_HASH_NAMESIZE];
	// Interface information.
	snprintf(hash_name, sizeof(hash_name), "if_%s", name);
	ROUTER_DEBUG("[INTERFACE] (%s) interface table name: %s\n",
		     name, hash_name);
	struct rte_hash_parameters hash_params = {
	    .name = hash_name,
	    .entries = ROUTER_MAX_VIFS, // MAX number of interfaces.
	    .key_len = sizeof(uint32_t),
	    .hash_func = rte_jhash,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};
	it->hashmap = rte_hash_create(&hash_params);
	if (!it->hashmap) {
		ROUTER_ERROR("[INTERFACE] Error allocating hash table");
		return NULL;
	}

	// Management self ip.
	snprintf(hash_name, sizeof(hash_name), "self_%s", name);
	ROUTER_DEBUG("[INTERFACE] (%s) interface self table name: %s\n",
		     name, hash_name);
	struct rte_hash_parameters self_hash_params = {
	    .name = hash_name,
	    .entries = ROUTER_MAX_VIF_IPADDRS, //MAX number of ip address.
	    .key_len = sizeof(uint64_t),
	    .hash_func = self_hash_func,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};
	it->self = rte_hash_create(&self_hash_params);
	if (!it->self) {
		ROUTER_ERROR("[INTERFACE] Error allocating self hash table");
		rte_free(it);
		return NULL;
	}

	return it;
}

/**
 * Finalize interface table.
 */
void
interface_fini(struct interface_table *interface_table) {
	if (!interface_table)
		return;
	uint32_t *ifindex;
	struct interface *interface;
	uint32_t next = 0;
	// Free all entries.
	while (rte_hash_iterate(interface_table->hashmap, (const void **)&ifindex, (void **)&interface, &next) >= 0) {
		rte_free(interface->nexthops);
		rte_free(interface);
	}
	// Destroy hashmaps.
	if (interface_table->hashmap)
		rte_hash_free(interface_table->hashmap);
	if (interface_table->self)
		rte_hash_free(interface_table->self);
	rte_free(interface_table);
}

inline static uint64_t
create_ip_key(uint32_t addr, vifindex_t idx) {
	uint64_t key = (uint64_t)addr;
	return ((key << 32) | idx);
}

/**
 * Add IP address to interface entry.
 */
bool
interface_ip_add(struct interface_table *interface_table, struct interface_addr_entry *ia) {
	struct interface *interface;
	uint32_t ifindex = ia->ifindex;
	uint32_t addr = ia->addr;
	uint32_t prefixlen = ia->prefixlen;

	int ret = rte_hash_lookup_data(interface_table->hashmap, &ifindex, (void **)&interface);
	// No entry
	if (unlikely(ret == -ENOENT)) {
		ROUTER_DEBUG("[INTERFACE] no interface entry. ifindex = %d\n", ifindex);
		return false;
	}

	// Lookup failed
	if (ret < 0) {
		ROUTER_ERROR("[INTERFACE] rte_hash_lookup_data() failed, err = %d.", ret);
		return false;
	}

	// full of ip address
	if (interface->count == ROUTER_MAX_VIF_IPADDRS)
		return false;

	// Interface entry exists.
	for (int i = 0; i < interface->count; i++) {
		// If the same IP address has already been registered,
		// it returns silently.
		if (interface->addr[i].addr == addr)
			return true;
	}

	// Add new ip address.
	interface->addr[interface->count].addr = addr;
	interface->addr[interface->count].prefixlen = prefixlen;
	interface->count++;

	// Add a address to hashmap for self.
	uint64_t key = create_ip_key(addr, ifindex);
	if (rte_hash_add_key(interface_table->self, &key) < 0) {
		ROUTER_ERROR("[INTERFACE] regist ip address to self table failed.");
		return false;
	}

	// Dump ip list
	ROUTER_DEBUG("[INTERFACE] Add IP Address: %s\n", ip2str(addr));
	if (VSW_LOG_DEBUG_ENABLED(router_log_id))
		print_interface_list(interface_table);
	return true;
}

/**
 * Delete IP address from interface entry.
 */
bool
interface_ip_delete(struct interface_table *interface_table, struct interface_addr_entry *ia) {
	struct interface *interface;
	uint32_t ifindex = ia->ifindex;
	uint32_t addr = ia->addr;

	int ret = rte_hash_lookup_data(interface_table->hashmap, &(ifindex), (void **)&interface);
	// No entry
	if (unlikely(ret == -ENOENT)) {
		ROUTER_DEBUG("[NEIGH] no interface entry. ifindex = %d\n", ifindex);
		return false;
	}
	// Lookup failed
	if (ret < 0) {
		ROUTER_ERROR("[INTERFACE] rte_hash_lookup_data() failed, err = %d.", ret);
		return false;
	}

	// Remove ip address.
	for (int i = 0; i < interface->count; i++) {
		if (interface->addr[i].addr == addr) {
			interface->count--;
			interface->addr[i].addr = interface->addr[interface->count].addr;

			// Delete a address from hashmap for self.
			uint64_t key = create_ip_key(addr, ifindex);
			if (rte_hash_del_key(interface_table->self, &key) < 0) {
				ROUTER_INFO("[INTERFACE] delete %02x.%02x.%02x.%02x from VIF %d failed. no such address.",
					    (addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) &0xff, addr & 0xff,
					    ifindex);
			}
			break;
		}
	}

	// Dump ip list
	if (VSW_LOG_DEBUG_ENABLED(router_log_id))
		print_interface_list(interface_table);
	return true;
}

inline bool
interface_ip_is_self(struct interface_table *interface_table, uint32_t addr, vifindex_t ifindex) {
	uint64_t key = create_ip_key(addr, ifindex);
	return (rte_hash_lookup(interface_table->self, &key) >= 0);
}

/**
 * Add a nexthop reference that refers to the interface,
 * to delete the interface reference that the nexthop has
 * when the interface is deleted.
 */
bool
interface_nexthop_reference_add(struct interface *interface, nexthop_t *nh) {
	if (interface->nexthops_cap <= interface->nexthop_num) {
		size_t new_cap = interface->nexthops_cap + NEXTHOPS_CAPACITY_INCREMENT;
		nexthop_t **new = (nexthop_t **)rte_realloc(interface->nexthops,
							    sizeof(nexthop_t *) * new_cap, 0);

		if (!new) {
			ROUTER_ERROR("[INTERFACE] Error allocation nexthop list\n");
			return false;
		}

		interface->nexthops = new;
		interface->nexthops_cap = new_cap;
	}

	interface->nexthops[interface->nexthop_num] = nh;
	interface->nexthop_num++;
	return true;
}

/**
 * Delete a nexthop reference if the nexthop is deleted.
 */
void
interface_nexthop_reference_delete(struct interface *interface, nexthop_t *nh) {
	for (int i = 0; i < interface->nexthop_num; i++) {
		if (interface->nexthops[i] == nh) {
			interface->nexthop_num--;
			interface->nexthops[i] = interface->nexthops[interface->nexthop_num];
			return;
		}
	}
}

/**
 * Add interface(vif) entry.
 */
bool
interface_entry_add(struct router_instance *ri, struct interface_entry *ie) {
	struct interface_table *interface_table = ri->tables.interface;
	struct interface *interface;
	uint32_t ifindex = ie->ifindex;

	// Check if entry is exist in interface table.
	int ret = rte_hash_lookup_data(interface_table->hashmap, &ifindex, (void **)&interface);

	if (ret >= 0) {
		return true;
	} else if (ret != -ENOENT) {
		ROUTER_ERROR("[INTERFACE] Unexpected error during lookup: %d", ret);
		return false;
	}

	// create new entry
	ie->rr = get_router_ring(ri, ie->ring);
	if (!ie->rr) {
		ROUTER_ERROR("[INTERFACE] Can't get router ring for VIF %d", ifindex);
		return false;
	}

	interface = rte_zmalloc(NULL, sizeof(struct interface), 0);
	if (!interface) {
		ROUTER_ERROR("[INTERFACE] interface entry allocation failed.");
		return false;
	}

	// Create neighbor cache if the interface is normal VIF, i.e. neither tunnel nor VRF.
	if (is_iff_type_vif(ie)) {
		struct neighbor_table *nt = neighbor_init(ie->ifindex);
		if (nt == NULL) {
			ROUTER_ERROR("[INTERFACE] neighbor cache creation failed.");
			rte_free(interface);
			return false;
		}
		interface->neighbor = nt;

		// Tell Go frontend about neighbor cache.
		ie->cache = nt->cache;
		ie->cache_size = nt->cache_size;
	}

	// Add new key to hash table of the self interface.
	if (rte_hash_add_key_data(interface_table->hashmap, &ifindex, interface) < 0) {
		ROUTER_ERROR("[INTERFACE] interface entry add failed.");
		neighbor_fini(interface->neighbor);
		rte_free(interface);
		return false;
	}

	interface->base = *ie;

	if (VSW_LOG_DEBUG_ENABLED(router_log_id))
		print_interface_entry("Add", interface);
	return true;
}

/**
 * Delete interface(vif) entry.
 */
bool
interface_entry_delete(struct router_instance *ri, struct interface_entry *ie) {
	struct interface_table *interface_table = ri->tables.interface;
	struct interface *interface;

	int ret = rte_hash_lookup_data(interface_table->hashmap, &(ie->ifindex), (void **)&interface);
	// No entry
	if (unlikely(ret == -ENOENT)) {
		ROUTER_DEBUG("[NEIGH] no interface entry. ifindex = %d\n", ie->ifindex);
		return false;
	}
	// Lookup failed
	if (ret < 0) {
		ROUTER_ERROR("[INTERFACE] rte_hash_lookup_data() failed, err = %d.", ret);
		return false;
	}

	// Delete the interace reference from nexthops that refer it.
	for (int i = 0; i < interface->nexthop_num; i++)
		interface->nexthops[i]->interface = NULL;
	rte_free(interface->nexthops);

	// Delete ip address from self table.
	for (int i = 0; i < interface->count; i++) {
		if (!interface_ip_delete(interface_table, &interface->addr[i])) {
			ROUTER_INFO("[INTERFACE] failed to delete ip address %s from %d.", ip2str(interface->addr[i].addr), ie->ifindex);
		}
	}

	// Delete from interface table.
	if (rte_hash_del_key(interface_table->hashmap, &(ie->ifindex)) < 0) {
		ROUTER_ERROR("[INTERFACE] not found interface [ifindex: %" PRIu32 "]",
			     ie->ifindex);
		return false;
	}

	put_router_ring(ri, interface->base.rr);

	// Free entry data.
	neighbor_fini(interface->neighbor);
	rte_free(interface);

	ROUTER_DEBUG("[INTERFACE] deleted entry [ifindex = %" PRIu32 "]\n", ie->ifindex);
	return true;
}

/**
 * Get interface(vif) entry.
 */
struct interface *
interface_entry_get(struct interface_table *interface_table, uint32_t ifindex) {
	struct interface *interface;
	uint32_t key = ifindex;
	int ret = rte_hash_lookup_data(interface_table->hashmap,
				       (const void *)&key, (void **)&interface);
	// No entry
	if (unlikely(ret == -ENOENT)) {
		ROUTER_INFO("[INTERFACE] can't find VIF %d", ifindex);
		return NULL;
	} else {
		assert(ret >= 0);
	}

	if (VSW_LOG_DEBUG_ENABLED(router_log_id)) {
		print_interface_entry("Get", interface);
		print_interface_list(interface_table);
	}
	return interface;
}

/**
 * Update interface(vif) mtu.
 */
bool
interface_mtu_update(struct interface_table *interface_table, struct interface_entry *ie) {
	struct interface *interface;
	int ret = rte_hash_lookup_data(interface_table->hashmap,
				       &(ie->ifindex), (void **)&interface);

	// No entry
	if (unlikely(ret == -ENOENT)) {
		ROUTER_INFO("[INTERFACE] Not found entry in %s\n", __func__);
		return false;
	} else {
		assert(ret >= 0);
	}

	// If the interface entry already exists, update MTU>
	interface->base.mtu = ie->mtu;

	ROUTER_DEBUG("[INTERFACE] Update MTU: %u\n", interface->base.mtu);

	return true;
}
