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
 *      @file   arp.c
 *      @brief  ARP table.
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
#include <rte_cycles.h>
#include <rte_malloc.h>

#include "router_log.h"
#include "arp.h"

/*** static functions ***/
/**
 * Debug print for arp entry.
 */
static void
print_arp_entry(const char *str, char *name, struct arp_entry *ae) {
	if (!ae) {
		return;
	}

	char buf[BUFSIZ];
	inet_ntop(AF_INET, &(ae->ip), buf, BUFSIZ);
	struct ether_addr *mac = &(ae->mac);
	LAGOPUS_DEBUG("[ARP] (%s) %s: (vif: %u) %s -> %02x:%02x:%02x:%02x:%02x:%02x\n",
			name, str, ae->ifindex, buf,
			mac->addr_bytes[0], mac->addr_bytes[1], mac->addr_bytes[2],
			mac->addr_bytes[3], mac->addr_bytes[4], mac->addr_bytes[5]);
}

static void
print_arp_entry_list(struct arp_table *arp_table) {
#if 1 //debug
	struct arp_entry *ae;
	uint32_t *ip;
	uint32_t next = 0;

	while (rte_hash_iterate(arp_table->hashmap, (const void **)&ip,
				(void **)&ae, &next) >= 0) {
		print_arp_entry("List", arp_table->name, ae);
	}
#endif
}

static struct arp_entry *
create_entry(struct arp_table *arp_table, char *str,
		struct arp_entry *src, struct arp_entry *dst) {
	struct arp_entry *entry = dst;
	// create new entry.
	if (!dst) {
		entry = rte_zmalloc(NULL, sizeof(struct arp_entry), 0);
		if (!entry) {
			lagopus_printf("[ARP] %s: (%s) Failed to allocate arp entry.",
					str, arp_table->name);
			return NULL;
		}
	}

	// set entry
	if (src) {
		entry->ip = src->ip;
		entry->ifindex = src->ifindex;
		entry->valid = src->valid;
		ether_addr_copy(&(src->mac), &(entry->mac));
	} else {
		entry->valid = false;
	}
	return entry;
}

static void
clean_arp_table(struct arp_table *arp_table) {
	struct arp_entry *ae;
	uint32_t *ip;
	uint32_t next = 0;
	uint32_t removed = 0; // for debug.

	while (rte_hash_iterate(arp_table->hashmap, (const void **)&ip,
				(void **)&ae, &next) >= 0) {
		// free unused entries.
		if (!ae->valid) {
			rte_hash_del_key(arp_table->hashmap, ip);
			rte_free(ae);
			removed++;
		}
	}

	// for debug.
	if (removed > 0) {
		LAGOPUS_DEBUG("[ARP] Free %d entries.\n", removed);
	} else {
		LAGOPUS_DEBUG("[ARP] Don't free entry, no space in arp table.\n");
	}

}

static bool
add_entry(struct arp_table *arp_table, void *ip, struct arp_entry *entry) {
	int ret = rte_hash_add_key_data(arp_table->hashmap, ip, entry);
	// no space in the hash for this key.
	if (ret == -ENOSPC) {
		lagopus_printf("[ARP] %s: (%s) Failed to add arp entry, hashtable is full.\n",
				__func__, arp_table->name);
		// free unused entries.
		clean_arp_table(arp_table);
	}
	// parameters are invalid.
	else if (ret == -EINVAL) {
		lagopus_printf("[ARP] %s: (%s) Failed to add arp entry, invalid arguments.",
				__func__, arp_table->name);
		rte_free(entry);
		return false;
	}

	// adding entry is success.
	return true;
}

/*** public functions ***/
/**
 * Initialize arp table.
 */
bool
arp_init(struct arp_table *arp_table, const char *name) {
	// set module name.
	snprintf(arp_table->name, sizeof(arp_table->name), "%s", name);

	// set hash name.
	char hash_name[RTE_HASH_NAMESIZE];
	snprintf(hash_name, sizeof(hash_name), "arp_%s", name);
	LAGOPUS_DEBUG("[ARP] (%s) arp table name: %s\n",
			arp_table->name, hash_name);
	struct rte_hash_parameters hash_params = {
		.name = hash_name,
		.entries = MAX_ARP_ENTRIES, // TODO: max number of arp entries.
		.key_len = sizeof(uint32_t),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};
	arp_table->hashmap = rte_hash_create(&hash_params);
	if (!arp_table->hashmap) {
		lagopus_printf("[ARP] %s: (%s) Error allocating hash table",
				__func__, arp_table->name);
		return false;
	}

	return true;
}

/**
 * Finalize arp table.
 */
void
arp_fini(struct arp_table *arp_table) {
	uint32_t *ip;
	struct arp_entry *entry;
	uint32_t next = 0;
	/* free all entries. */
	while (rte_hash_iterate(arp_table->hashmap, (const void **)&ip, (void **)&entry, &next) >= 0) {
		rte_free(entry);
	}
	/* destroy hashmap for arp table. */
	if (arp_table->hashmap)
		rte_hash_free(arp_table->hashmap);
}

/**
 * Delete arp entry.
 */
bool
arp_entry_delete(struct arp_table *arp_table, struct arp_entry *ae) {
	/* for debug */
	char buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ae->ip), buf, sizeof(buf));

	struct arp_entry *entry;
	/* free entry data. */
	int ret = rte_hash_lookup_data(arp_table->hashmap, &(ae->ip), (void **)&entry);
	if (ret >= 0 && entry) {
		// not free entry and only changed resolve status.
		entry->valid = false;
	} else {
		LAGOPUS_DEBUG("[ARP] %s: (%s) arp entry free failed.(key:%s, ret:%d).",
				__func__, arp_table->name, buf, ret);
	}

	print_arp_entry("Delete", arp_table->name, ae);
	return true;
}

/**
 * Update arp entry.
 */
bool
arp_entry_update(struct arp_table *arp_table, struct arp_entry *ae) {
	if (arp_table->hashmap == NULL) {
		lagopus_printf("[ARP] %s: (%s) Invalid argument hashmap is NULL.",
				__func__, arp_table->name);
		return false;
	}

	struct arp_entry *entry;
	ae->valid = true;

	/* check if entry is exist in arp table. */
	int ret = rte_hash_lookup_data(arp_table->hashmap, &(ae->ip), (void **)&entry);
	if (likely(ret >= 0)) {
		/* entry is found. */
		/* if the arp entry already exists, to update the entry contents. */
		create_entry(arp_table, "update", ae, entry);
		print_arp_entry("Update", arp_table->name, ae);
	} else if (ret == -ENOENT) {
		/* add new entry */
		entry = create_entry(arp_table, "update(new)", ae, NULL);

		/* add new entry to hashmap. */
		if (!add_entry(arp_table, &(ae->ip), entry)) {
			return false;
		}
		print_arp_entry("Add", arp_table->name, ae);
	} else {
		lagopus_printf("[ARP] %s: (%s) Failed to lookup arp hash table.",
				__func__, arp_table->name);
		return false;
	}

	return true;
}

/**
 * Get arp entry.
 */
struct arp_entry *
arp_entry_get(struct arp_table *arp_table, uint32_t addr) {
	if (arp_table->hashmap == NULL) {
		lagopus_printf("[ARP] %s: (%s) Hashmap is invalid(null).",
				__func__, arp_table->name);
		return NULL;
	}

	struct arp_entry *entry = NULL;
	int ret = rte_hash_lookup_data(arp_table->hashmap,
					(const void*)&(addr),
					(void **)&entry);

	char buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &addr, buf, sizeof(buf));

	// no entry
	if (unlikely(ret < 0)) {
		// create empty entry and set time.
		entry = create_entry(arp_table, "get", NULL, NULL);

		/* add new entry to hashmap. */
		// TODO: when arp did not solve, entry is delete from hashmap.
		if (!add_entry(arp_table, &(addr), entry)) {
			return NULL;
		}
		LAGOPUS_DEBUG("[ARP] (%s) no entry(%s), send to tap.\n",
				arp_table->name, buf);
		return NULL;
	}

	// get dummy entry
	// arp is unresolved, decide whether to send to tap.
	if (!entry->valid) {
		return NULL;
	}

	// arp entry is exist.
	print_arp_entry("Get", arp_table->name, entry);
	print_arp_entry_list(arp_table);

	return entry;
}

