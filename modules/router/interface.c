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
#include <rte_ip.h>
#include <rte_malloc.h>

#include "interface.h"
#include "router.h"

#include "packet.h"
#include "router_log.h"

static void
print_interface_entry(char *str, struct interface *interface) {
	if (!interface)
		return;

	struct interface_entry *ie = &interface->base;

	ROUTER_DEBUG("[INTERFACE] %s: ifindex: %" PRIu32 ", mac: %s, mtu: %d, vid: %d\n",
		     str, ie->ifindex, mac2str(ie->mac), ie->mtu, ie->vid);
	for (int i = 0; i < IPADDR_MAX_NUM && interface->addr[i].addr != 0; i++) {
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
	    .entries = MAX_ROUTER_VIFS, // MAX number of interfaces.
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
	    .entries = IPADDR_MAX_NUM, //MAX number of ip address.
	    .key_len = sizeof(uint32_t),
	    .hash_func = rte_jhash,
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
		rte_free(interface);
	}
	// Destroy hashmaps.
	if (interface_table->hashmap)
		rte_hash_free(interface_table->hashmap);
	if (interface_table->self)
		rte_hash_free(interface_table->self);
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
	// Invalid parameter, assertion fail..
	assert(ret >= 0);

	// full of ip address
	if (interface->count == IPADDR_MAX_NUM)
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
	if (rte_hash_add_key(interface_table->self, &addr) < 0) {
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
	// Invalid parameter, assertion fail..
	assert(ret >= 0);

	// Remove ip address.
	for (int i = 0; i < interface->count; i++) {
		if (interface->addr[i].addr == addr) {
			interface->count--;
			interface->addr[i].addr = interface->addr[interface->count].addr;

			// Delete a address from hashmap for self.
			if (rte_hash_del_key(interface_table->self, &addr) < 0) {
				ROUTER_INFO("[INTERFACE] Not found entry.");
			}
			break;
		}
	}

	// Dump ip list
	if (VSW_LOG_DEBUG_ENABLED(router_log_id))
		print_interface_list(interface_table);
	return true;
}

/**
 * Add interface(vif) entry.
 */
bool
interface_entry_add(struct router_context *ctx, struct interface_entry *ie) {
	struct interface_table *interface_table = ctx->tables.interface;
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
	ie->rr = get_router_ring(ctx, ie->ring);
	if (!ie->rr) {
		ROUTER_ERROR("[INTERFACE] Can't get router ring for VIF %d", ifindex);
		return false;
	}

	interface = rte_zmalloc(NULL, sizeof(struct interface), 0);
	if (!interface) {
		ROUTER_ERROR("[INTERFACE] interface entry allocation failed.");
		return false;
	}

	// Add new key to hash table of the self interface.
	if (rte_hash_add_key_data(interface_table->hashmap, &ifindex, interface) < 0) {
		ROUTER_ERROR("[INTERFACE] interface entry add failed.");
		rte_free(interface);
		return false;
	}

	// If the interface entry already exists,
	// to update the entry.
	interface->base = *ie;

	if (VSW_LOG_DEBUG_ENABLED(router_log_id))
		print_interface_entry("Add", interface);
	return true;
}

/**
 * Delete interface(vif) entry.
 */
bool
interface_entry_delete(struct router_context *ctx, struct interface_entry *ie) {
	struct interface_table *interface_table = ctx->tables.interface;
	struct interface *interface;

	int ret = rte_hash_lookup_data(interface_table->hashmap, &(ie->ifindex), (void **)&interface);
	// No entry
	if (unlikely(ret == -ENOENT)) {
		ROUTER_DEBUG("[NEIGH] no interface entry. ifindex = %d\n", ie->ifindex);
		return false;
	}
	// Invalid parameter, assertion fail..
	assert(ret >= 0);

	// Delete ip address from self table.
	for (int i = 0; i < interface->count; i++) {
		if (!interface_ip_delete(interface_table, &interface->addr[i])) {
			ROUTER_INFO("[INTERFACE] %s: (%s) failed to delete ip address.");
		}
	}

	// Delete from interface table.
	if (rte_hash_del_key(interface_table->hashmap, &(ie->ifindex)) < 0) {
		ROUTER_ERROR("[INTERFACE] not found interface [ifindex: %" PRIu32 "]",
			     ie->ifindex);
		return false;
	}

	put_router_ring(ctx, interface->base.rr);

	// Free entry data.
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
		ROUTER_INFO("[INTERFACE] Not found entry.");
		return NULL;
	}
	// Invalid parameter, assertion fail..
	assert(ret >= 0);

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
	}
	// Invalid parameter, assertion fail.
	assert(ret >= 0);

	// If the interface entry already exists, update MTU>
	interface->base.mtu = ie->mtu;

	ROUTER_DEBUG("[INTERFACE] Update MTU: %u\n", interface->base.mtu);

	return true;
}
