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

/**
 *      @file   interface.c
 *      @brief  Interface table.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rte_ip.h>
#include <rte_malloc.h>

#include "interface.h"

#include "router_log.h"
#include "packet.h"

#define ETHADDR_STRLEN 18

static char *
ip2str(uint32_t addr) {
	static char buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &addr, buf, sizeof(buf));
	return buf;
}

static char *
mac2str(struct ether_addr mac) {
	static char buf[ETHADDR_STRLEN];
	ether_format_addr(buf, sizeof buf, &mac);
	return buf;
}

static void
print_interface_entry(char *str, char *name, struct interface *interface) {
	LAGOPUS_DEBUG("[INTERFACE] (%s) %s: ifindex: %"PRIu32", mac: %s, mtu: %d, vid: %d\n",
			name, str, interface->ifindex, mac2str(interface->mac),
			interface->mtu, interface->vid);
	for (int i = 0; i < IPADDR_MAX_NUM && interface->addr[i].addr != 0; i++) {
		LAGOPUS_DEBUG("\t\t\t\t: addr[%d] %s\n", i, ip2str(interface->addr[i].addr));
	}
}

static void
print_interface_list(struct interface_table *interface_table) {
#if 1 //debug
	struct interface *interface;
	uint32_t *idx;
	uint32_t next = 0;

	while (rte_hash_iterate(interface_table->hashmap, (const void **)&idx,
				(void **)&interface, &next) >= 0) {
		print_interface_entry("List", interface_table->name, interface);
	}
#endif
}

/*** public functions ***/
/**
 * Initialize interface table.
 */
bool
interface_init(struct interface_table *interface_table, const char *name) {
	// set module name.
	snprintf(interface_table->name, sizeof(interface_table->name), "%s", name);
	char hash_name[RTE_HASH_NAMESIZE];
	/** interface information **/
	snprintf(hash_name, sizeof(hash_name), "if_%s", name);
	LAGOPUS_DEBUG("[INTERFACE] (%s) interface table name: %s\n",
			interface_table->name, hash_name);
	struct rte_hash_parameters hash_params = {
		.name = hash_name,
		.entries = IPADDR_MAX_NUM, // TODO: max number of interfaces.
		.key_len = sizeof(uint32_t),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};
	interface_table->hashmap = rte_hash_create(&hash_params);
	if (!interface_table->hashmap) {
		lagopus_printf("[INTERFACE] %s: (%s) Error allocating hash table",
				__func__, interface_table->name);
		return false;
	}

	/** management self ip **/
	snprintf(hash_name, sizeof(hash_name), "self_%s", name);
	LAGOPUS_DEBUG("[INTERFACE] (%s) interface self table name: %s\n",
			interface_table->name, hash_name);
	struct rte_hash_parameters self_hash_params = {
		.name = hash_name,
		.entries = IPADDR_MAX_NUM, // TODO: max number of ip address.
		.key_len = sizeof(uint32_t),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};
	interface_table->self = rte_hash_create(&self_hash_params);
	if (!interface_table->self) {
		lagopus_printf("[INTERFACE] %s: (%s) Error allocating self hash table",
				__func__, interface_table->name);
		return false;
	}

	return true;
}

/**
 * Finalize interface table.
 */
void
interface_fini(struct interface_table *interface_table) {
	uint32_t *ifindex;
	struct interface *interface;
	uint32_t next = 0;
	/* free all entries. */
	while (rte_hash_iterate(interface_table->hashmap, (const void **)&ifindex, (void **)&interface, &next) >= 0) {
		rte_free(interface);
	}
	/* destroy hashmaps */
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
	if (!interface_table->hashmap) {
		lagopus_printf("[INTERFACE] %s: (%s) Invalid argument (hashmap is nil).",
				__func__, interface_table->name);
		return false;
	}

	int ret = rte_hash_lookup_data(interface_table->hashmap, &ifindex, (void **)&interface);
	if (ret < 0) {
		lagopus_printf("[INTERFACE] %s: (%s) no interface. ifindex = %"PRIu32"\n",
				__func__, interface_table->name, ifindex);
		return false;
	}

	// full of ip address
	if (interface->count == IPADDR_MAX_NUM)
		return false;

	// interface entry exists.
	for (int i = 0; i < interface->count; i++) {
		if (interface->addr[i].addr == addr)
			return false;
	}

	// add new ip address.
	interface->addr[interface->count].addr = addr;
	interface->addr[interface->count].prefixlen = prefixlen;
	interface->count++;

	// add a address to hashmap for self.
	if (rte_hash_add_key(interface_table->self, &addr) < 0) {
		lagopus_printf("[INTERFACE] %s: (%s) regist ip address to self table failed.",
				__func__, interface_table->name);
		return false;
	}

	// dump ip list
	LAGOPUS_DEBUG("[INTERFACE] %s: (%s) Add IP Address: %s\n",
			__func__, interface_table->name, ip2str(addr));
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
	uint32_t prefixlen = ia->prefixlen;
	if (!interface_table->hashmap) {
		lagopus_printf("[INTERFACE] %s: (%s) Invalid argument (hashmap is nil).",
				__func__, interface_table->name);
		return false;
	}

	int ret  = rte_hash_lookup_data(interface_table->hashmap, &(ifindex), (void **)&interface);
	if (ret < 0 || !interface) {
		lagopus_printf("[INTERFACE] %s: (%s) no interface. ifindex = %"PRIu32"\n",
				__func__, interface_table->name, ifindex);
		return false;
	}

	// remove ip address.
	for (int i = 0; i < interface->count; i++) {
		uint32_t addr = interface->addr[i].addr;
		if (interface->addr[i].addr == addr) {
			interface->count--;
			interface->addr[i].addr = interface->addr[interface->count].addr;

			// delete a address from hashmap for self.
			if (rte_hash_del_key(interface_table->self, &addr) < 0) {
				lagopus_printf("[INTERFACE] %s: Not found entry.", __func__);
			}
			break;
		}
	}

	// dump ip list
	print_interface_list(interface_table);
	return true;
}

/**
 * Add interface(vif) entry.
 */
bool
interface_entry_add(struct interface_table *interface_table, struct interface_entry *ie) {
	struct interface *interface;
	uint32_t ifindex       = ie->ifindex;
	struct ether_addr *mac = &(ie->mac);
	uint16_t mtu           = ie->mtu;
	struct rte_ring *ring  = ie->ring;
	uint16_t vid           = ie->vid;
	bool tunnel            = ie->tunnel;

	if (!(interface_table->hashmap)) {
		lagopus_printf("[INTERFACE] %s: (%s) Invalid argument (hashmap is nil).",
				__func__, interface_table->name);
		return false;
	}

	/* check if entry is exist in interface table. */
	int ret = rte_hash_lookup_data(interface_table->hashmap, &ifindex, (void **)&interface);
	if (ret < 0 && ret != -ENOENT) {
		lagopus_printf("[INTERFACE] %s: (%s) interface hash table lookup error.",
				__func__, interface_table->name);
		return false;
	}

	if (ret >= 0 ) {
		/* if the interface entry already exists,
		 * to update the entry. */
		LAGOPUS_DEBUG("%s(%d) update entry.\n", __func__, __LINE__);
		ether_addr_copy(mac, &(interface->mac));
		interface->mtu    = mtu;
		interface->ring   = ring;
		interface->vid    = vid;
		interface->tunnel = tunnel;
	} else if (ret == -ENOENT) {
		// add new entry
		interface= rte_zmalloc(NULL, sizeof(struct interface), 0);
		if (!interface) {
			lagopus_printf("[INTERFACE] %s: (%s) interface entry allocation failed.",
					__func__, interface_table->name);
			return false;
		}
		ether_addr_copy(mac, &(interface->mac));
		interface->ifindex      = ifindex;
		interface->mtu          = mtu;
		interface->ring         = ring;
		interface->vid          = vid;
		interface->tunnel       = tunnel;

		// add key to hash table of the self interface.
		if (rte_hash_add_key_data(interface_table->hashmap, &interface->ifindex, interface) < 0) {
			lagopus_printf("[INTERFACE] %s: (%s) interface entry add failed.",
				__func__, interface_table->name);
			rte_free(interface);
			return false;
		}
	}

	print_interface_entry("Add", interface_table->name, interface);
	return true;
}

/**
 * Delete interface(vif) entry.
 */
bool
interface_entry_delete(struct interface_table *interface_table, struct interface_entry *ie) {
	struct interface *interface;
	bool is_ip = false;

	if (!(interface_table->hashmap)) {
		lagopus_printf("[INTERFACE] %s: (%s) Invalid argument (hashmap is nil).",
				__func__, interface_table->name);
		return false;
	}

	int ret  = rte_hash_lookup_data(interface_table->hashmap, &(ie->ifindex), (void **)&interface);
	if (ret < 0 && !interface) {
		lagopus_printf("[INTERFACE] %s: (%s) interface entry free failed.",
				__func__, interface_table->name);
		return false;
	}

	// delete ip address from self table.
	for (int i = 0; i < interface->count; i++) {
		if (!interface_ip_delete(interface_table, &interface->addr[i])) {
			lagopus_printf("[INTERFACE] %s: (%s) failed to delete ip address.");
		}
	}

	// delete from interface table.
	if (rte_hash_del_key(interface_table->hashmap, &(ie->ifindex)) < 0) {
		lagopus_printf("[INTERFACE] %s: (%s) not found interface [ifindex: %"PRIu32"]",
				__func__, interface_table->name, ie->ifindex);
		return false;
	}

	// free entry data.
	rte_free(interface);

	LAGOPUS_DEBUG("[INTERFACE] (%s) deleted entry [ifindex = %"PRIu32"]\n",
			interface_table->name, ie->ifindex);
	return true;
}

/**
 * Get interface(vif) entry.
 */
struct interface *
interface_entry_get(struct interface_table *interface_table, uint32_t ifindex) {
	struct interface *interface;
	uint32_t key = ifindex;
	if (!(interface_table->hashmap)) {
		lagopus_printf("[INTERFACE] %s: (%s) Invalid argument (hashmap is nil).",
				__func__, interface_table->name);
		return NULL;
	}
	if (rte_hash_lookup_data(interface_table->hashmap,
			         (const void*)&key, (void **)&interface) < 0) {
		lagopus_printf("[INTERFACE] %s: (%s) Not found entry.",
				__func__, interface_table->name);
		return NULL;
	}

	print_interface_entry("Get", interface_table->name, interface) ;
	print_interface_list(interface_table);

	return interface;
}
