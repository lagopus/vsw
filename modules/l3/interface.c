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
#include "interface.h"

#include "l3_log.h"
#include "packet.h"

/* interface entry */
struct interface_entry {
	uint32_t ifindex;
	struct in_addr ip;
	struct in_addr broad;
	struct ether_addr mac;
};

void
print_interface_entry(char *str, uint32_t ifindex, struct ether_addr *mac, char *name) {
	LAGOPUS_DEBUG("%s: [INTERFACE] %s: vifid: %"PRIu32", mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
			name, str, ifindex,
			mac->addr_bytes[0], mac->addr_bytes[1], mac->addr_bytes[2],
			mac->addr_bytes[3], mac->addr_bytes[4], mac->addr_bytes[5]);
}

/*** public functions ***/
/**
 * Initialize interface table.
 */
uint32_t
interface_hash_func(const void *key, uint32_t length, uint32_t initval)
{
	const uint16_t *k = key;
	return rte_jhash_1word(k[0], initval);
}

lagopus_result_t
interface_init(struct interface_table *interface_table, const char *name, uint64_t vrfrd) {
	// set module name.
	snprintf(interface_table->name, sizeof(interface_table->name), "%s", name);


	char hash_name[RTE_HASH_NAMESIZE];
	/** interface information **/
	snprintf(hash_name, sizeof(hash_name), "if%"SCNu64, vrfrd);
	LAGOPUS_DEBUG("%s: [INTERFACE] interface table name: %s\n",
			interface_table->name, hash_name);
	struct rte_hash_parameters hash_params = {
		.name = hash_name,
		.entries = VIF_MAX_INDEX, // TODO: max number of interfaces.
		.key_len = sizeof(uint32_t),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};
	interface_table->hashmap = rte_hash_create(&hash_params);
	if (!interface_table->hashmap) {
		lagopus_printf("%s: [INTERFACE] Error allocating hash table\n",
				interface_table->name);
		return LAGOPUS_RESULT_ANY_FAILURES;
	}

	/** management self ip **/
	snprintf(hash_name, sizeof(hash_name), "self%"SCNu64, vrfrd);
	LAGOPUS_DEBUG("%s: [INTERFACE] interface self table name: %s\n",
			interface_table->name, hash_name);
	struct rte_hash_parameters self_hash_params = {
		.name = hash_name,
		.entries = VIF_MAX_INDEX, // TODO: max number of ip address.
		.key_len = sizeof(uint32_t),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};
	interface_table->self = rte_hash_create(&self_hash_params);
	if (!interface_table->self) {
		lagopus_printf("%s: [INTERFACE] Error allocating self hash table\n",
				interface_table->name);
		return LAGOPUS_RESULT_ANY_FAILURES;
	}

	/** management hostif ip **/
	snprintf(hash_name, sizeof(hash_name), "hostif%"SCNu64, vrfrd);
	LAGOPUS_DEBUG("%s: [INTERFACE] interface hostif table name: %s\n",
			interface_table->name, hash_name);
	struct rte_hash_parameters hostif_hash_params = {
		.name = hash_name,
		.entries = VIF_MAX_INDEX, // TODO: max number of ip address.
		.key_len = sizeof(uint32_t),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};
	interface_table->hostif = rte_hash_create(&hostif_hash_params);
	if (!interface_table->hostif) {
		lagopus_printf("%s: [INTERFACE] Error allocating hostif hash table\n",
				interface_table->name);
		return LAGOPUS_RESULT_ANY_FAILURES;
	}
	return LAGOPUS_RESULT_OK;
}

/**
 * Finalize interface table.
 */
void
interface_fini(struct interface_table *interface_table) {
	/* destroy hashmaps */
	if (interface_table->hashmap)
		rte_hash_free(interface_table->hashmap);
	if (interface_table->self)
		rte_hash_free(interface_table->self);
	if (interface_table->hostif)
		rte_hash_free(interface_table->hostif);
}

/**
 * Delete interface entry.
 */
lagopus_result_t
interface_delete(struct interface_table *interface_table, uint32_t ifindex) {
	if (rte_hash_del_key(interface_table->hashmap, &ifindex) < 0)
		return LAGOPUS_RESULT_NOT_FOUND;
	LAGOPUS_DEBUG("%s: [INTERFACE] deleted entry [ifindex = %"PRIu32"]\n",
			interface_table->name, ifindex);
	return LAGOPUS_RESULT_OK;
}

/**
 * Update interface entry.
 */
lagopus_result_t
interface_update(struct interface_table *interface_table, uint32_t ifindex, struct ether_addr *mac) {
	int ret;
	struct interface_entry *entry = NULL;
	if (interface_table->hashmap == NULL) {
		return LAGOPUS_RESULT_INVALID_ARGS;
	}

	/* check if entry is exist in interface table. */
	ret = rte_hash_lookup_data(interface_table->hashmap, &ifindex, (void **)&entry);
	if (ret >= 0 ) {
		/* TODO: entry is found. */
		/* if the interface entry already exists, to update the entry contents. */
	} else if (ret == -ENOENT) {
		/* add new entry to hashmap. */
		entry = malloc(sizeof(struct interface_entry));
		if (!entry) {
			return LAGOPUS_RESULT_NO_MEMORY;
		}
		entry->ifindex = ifindex;
		ether_addr_copy(mac, &(entry->mac));
		if (rte_hash_add_key_data(interface_table->hashmap, &entry->ifindex, entry) < 0) {
			lagopus_printf("%s: [INTERFACE] interface entry add failed(%d).\n",
					interface_table->name, ret);
			free(entry);
			return LAGOPUS_RESULT_ANY_FAILURES;
		}
		print_interface_entry("Add", ifindex, mac, interface_table->name);
	} else {
		lagopus_printf("%s: [INTERFACE] interface hash table lookup error(%d).\n",
				interface_table->name, ret);
		return LAGOPUS_RESULT_INVALID_ARGS;
	}

	return LAGOPUS_RESULT_OK;
}

/**
 * Get interface entry.
 */
lagopus_result_t
interface_get(struct interface_table *interface_table, uint32_t ifindex, struct ether_addr *mac) {
	struct interface_entry *entry;
	uint32_t key = ifindex;
	if (interface_table->hashmap == NULL) {
		return LAGOPUS_RESULT_INVALID_ARGS;
	}
	if (rte_hash_lookup_data(interface_table->hashmap,
			         (const void*)&key, (void **)&entry) < 0) {
		return LAGOPUS_RESULT_NOT_FOUND;
	}
	ether_addr_copy(&(entry->mac), mac);
	print_interface_entry("Get", ifindex, mac, interface_table->name);

	return LAGOPUS_RESULT_OK;
}

static void
print_ip(const char *str, struct in_addr ip, char *name) {
	char buf[BUFSIZ];
	inet_ntop(AF_INET, &ip, buf, BUFSIZ);
	LAGOPUS_DEBUG("%s: [INTERFACE] %s: ip: %s\n", name, str, buf);
}

/*** management ip ***/
static lagopus_result_t
mng_ip_get(struct rte_hash *hash, struct in_addr ip) {
	uint32_t key = ip.s_addr;
	if (hash == NULL) {
		return LAGOPUS_RESULT_INVALID_ARGS;
	}
	if (rte_hash_lookup(hash, (const void*)&key) < 0) {
		return LAGOPUS_RESULT_NOT_FOUND;
	}
	return LAGOPUS_RESULT_OK;
}

static lagopus_result_t
mng_ip_update(struct rte_hash *hash, struct in_addr ip) {
	uint32_t key = ip.s_addr;
	if (hash == NULL) {
		return LAGOPUS_RESULT_INVALID_ARGS;
	}

	/* check if entry is exist in interface table. */
	int ret = rte_hash_lookup(hash, &key);
	if (ret >= 0 ) {
		/* ip address is already exists, so nothing to do. */
	} else if (ret == -ENOENT) {
		/* add new entry to hashmap. */
		if (rte_hash_add_key(hash, &key) < 0) {
			lagopus_fatalf("interface entry add failed(%d).\n", ret);
			return LAGOPUS_RESULT_ANY_FAILURES;
		}
	} else {
		lagopus_fatalf("interface hash table lookup error(%d).\n", ret);
		return LAGOPUS_RESULT_INVALID_ARGS;
	}
	return LAGOPUS_RESULT_OK;
}

static lagopus_result_t
mng_ip_delete(struct rte_hash *hash, struct in_addr ip) {
	uint32_t key = ip.s_addr;
	if (rte_hash_del_key(hash, &key) < 0)
		return LAGOPUS_RESULT_NOT_FOUND;
	return LAGOPUS_RESULT_OK;
}

/*** self ***/
lagopus_result_t
interface_self_update(struct interface_table *interface_table, struct in_addr ip) {
	print_ip("Add self", ip, interface_table->name);
	return mng_ip_update(interface_table->self, ip);
}

lagopus_result_t
interface_self_delete(struct interface_table *interface_table, struct in_addr ip) {
	print_ip("Delete self", ip, interface_table->name);
	return mng_ip_delete(interface_table->self, ip);
}

bool
interface_is_self(struct interface_table *interface_table, struct in_addr ip) {
	if (mng_ip_get(interface_table->self, ip) == LAGOPUS_RESULT_OK) {
		print_ip("is self", ip, interface_table->name);
		return true;
	} else {
		return false;
	}
}

/*** hostif ***/
lagopus_result_t
interface_hostif_update(struct interface_table *interface_table, struct in_addr ip) {
	print_ip("Add hostif", ip, interface_table->name);
	return mng_ip_update(interface_table->hostif, ip);
}

lagopus_result_t
interface_hostif_delete(struct interface_table *interface_table, struct in_addr ip) {
	print_ip("Delete hostif", ip, interface_table->name);
	return mng_ip_delete(interface_table->hostif, ip);
}

bool
interface_is_hostif(struct interface_table *interface_table, struct in_addr ip) {
	if (mng_ip_get(interface_table->hostif, ip) == LAGOPUS_RESULT_OK) {
		print_ip("is hostif", ip, interface_table->name);
		return true;
	} else {
		return false;
	}
}
