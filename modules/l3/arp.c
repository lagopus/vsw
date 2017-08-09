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

#include "l3_log.h"
#include "arp.h"

/* arp entry */
struct arp_entry {
	int ifindex;
	struct in_addr ip;
	struct ether_addr mac;
	arp_resolve_status_t status;
	uint64_t expire_time;
};

/*** static functions ***/
/**
 * Debug print for arp entry.
 */
static void
print_arp_entry(const char *str, int ifindex,
		struct in_addr *dst_addr, struct ether_addr *mac, char *name) {
	if (!dst_addr || ! mac) {
		return;
	}

	char buf[BUFSIZ];
	inet_ntop(AF_INET, dst_addr, buf, BUFSIZ);
	LAGOPUS_DEBUG("%s: [ARP] %s: (vif: %u) %s -> %02x:%02x:%02x:%02x:%02x:%02x\n",
			name, str, ifindex, buf,
			mac->addr_bytes[0], mac->addr_bytes[1], mac->addr_bytes[2],
			mac->addr_bytes[3], mac->addr_bytes[4], mac->addr_bytes[5]);
}

/*** public functions ***/
uint32_t
arp_hash_func(const void *key, uint32_t length, uint32_t initval)
{
	const uint16_t *k = key;
	return rte_jhash_1word(k[0], initval);
}
/**
 * Initialize arp table.
 */
lagopus_result_t
arp_init(struct arp_table *arp_table, const char *name, uint64_t vrfrd) {
	// set module name.
	snprintf(arp_table->name, sizeof(arp_table->name), "%s", name);

	// set hash name.
	char hash_name[RTE_HASH_NAMESIZE];
	snprintf(hash_name, sizeof(hash_name), "arp%"SCNu64, vrfrd);
	LAGOPUS_DEBUG("%s: [ARP] arp table name: %s\n",
			arp_table->name, hash_name);
	struct rte_hash_parameters hash_params = {
		.name = hash_name,
		.entries = MAX_ARP_ENTRIES, // TODO: max number of arp entries.
		.key_len = sizeof(in_addr_t),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};
	arp_table->hashmap = rte_hash_create(&hash_params);
	if (!arp_table->hashmap) {
		lagopus_printf("%s: [ARP] Error allocating hash table\n",
				arp_table->name);
		return LAGOPUS_RESULT_ANY_FAILURES;
	}
	arp_table->interval = SEND_TO_TAP_INTERVAL * rte_get_timer_hz();
	return LAGOPUS_RESULT_OK;
}

/**
 * Finalize arp table.
 */
void
arp_fini(struct arp_table *arp_table) {
	/* destroy hashmap for arp table. */
	if (arp_table->hashmap)
		rte_hash_free(arp_table->hashmap);
}

/**
 * Delete arp entry.
 */
lagopus_result_t
arp_entry_delete(struct arp_table *arp_table, int ifindex,
                 struct in_addr *dst_addr, struct ether_addr *mac) {
	lagopus_result_t rv;
	(void) ifindex;
	(void) mac;


	if (rte_hash_del_key(arp_table->hashmap, &dst_addr->s_addr) < 0)
		return LAGOPUS_RESULT_NOT_FOUND;
	print_arp_entry("Delete", ifindex, dst_addr, mac, arp_table->name);
	return LAGOPUS_RESULT_OK;
}

/**
 * Update arp entry.
 */
lagopus_result_t
arp_entry_update(struct arp_table *arp_table, int ifindex,
                 struct in_addr *dst_addr, struct ether_addr *mac) {
	lagopus_result_t rv;
	int ret;
	struct arp_entry *entry;
	if (arp_table->hashmap == NULL) {
		return LAGOPUS_RESULT_INVALID_ARGS;
	}

	/* check if entry is exist in arp table. */
	ret = rte_hash_lookup_data(arp_table->hashmap, &dst_addr->s_addr, (void **)&entry);
	if (ret >= 0 ) {
		/* entry is found. */
		/* if the arp entry already exists, to update the entry contents. */
		entry->ifindex = ifindex;
		entry->status = ARP_RESOLVED;
		ether_addr_copy(mac, &(entry->mac));
		print_arp_entry("Update", ifindex, dst_addr, mac, arp_table->name);
	} else if (ret == -ENOENT) {
		/* add new entry */
		entry = malloc(sizeof(*entry));
		if (!entry) {
			rv = LAGOPUS_RESULT_NO_MEMORY;
			goto out;
		}
		entry->ifindex = ifindex;
		entry->status = ARP_RESOLVED;
		entry->ip = *dst_addr;
		ether_addr_copy(mac, &(entry->mac));

		/* add new entry to hashmap. */
		if (rte_hash_add_key_data(arp_table->hashmap, &dst_addr->s_addr, entry) < 0) {
			lagopus_printf("%s: [ARP] arp entry add failed(%d).\n", ret, arp_table->name);
			rv = LAGOPUS_RESULT_ANY_FAILURES;
			free(entry);
			goto out;
		}
		print_arp_entry("Add", ifindex, dst_addr, mac, arp_table->name);
	} else {
		lagopus_printf("%s: [ARP] arp hash table lookup error(%d).\n", ret, arp_table->name);
		rv = LAGOPUS_RESULT_INVALID_ARGS;
		goto out;
	}
out:
	return rv;
}

/**
 * Get arp entry.
 */
arp_result_t
arp_get(struct arp_table *arp_table, struct in_addr *addr, struct ether_addr *mac) {
	struct arp_entry *entry;

	if (arp_table->hashmap == NULL) {
		lagopus_printf("arp_get: hashmap is invalid(null).");
		return ARP_RESULT_ERROR;
	}

	int ret = rte_hash_lookup_data(arp_table->hashmap,
					(const void*)&addr->s_addr,
					(void **)&entry);
	// no entry
	if (unlikely(ret < 0)) {
		// create empty entry and set time.
		entry = malloc(sizeof(*entry));
		if (!entry) {
			lagopus_printf("arp_get: memory allocation failed.");
			return ARP_RESULT_ERROR;
		}
		entry->status = ARP_NO_RESOLVE;
		entry->expire_time = arp_table->interval + rte_get_timer_cycles();
		/* add new entry to hashmap. */
		// TODO: when arp did not solve, entry is delete from hashmap.
		if (rte_hash_add_key_data(arp_table->hashmap, &addr->s_addr, entry) < 0) {
			lagopus_printf("%s: [ARP] arp entry add failed(%d).\n", ret, arp_table->name);
			free(entry);
			return ARP_RESULT_ERROR;
		}
		LAGOPUS_DEBUG("%s: [ARP] no entry, send to tap. expire time: %"PRIu64".\n",
				arp_table->name, entry->expire_time);
		return ARP_RESULT_TO_RESOLVE;
	}

	// get dummy entry
	// arp is unresolved, decide whether to send to tap.
	if (entry->status == ARP_NO_RESOLVE) {
		uint64_t now = rte_get_timer_cycles();
		if (unlikely(entry->expire_time < now)) {
			// re-forwarding
			entry->expire_time = arp_table->interval + now;
			LAGOPUS_DEBUG("%s: [ARP] entry is dummy, send to tap(now: %"PRIu64", next expire: %"PRIu64").\n",
					arp_table->name, now, entry->expire_time);
			return ARP_RESULT_TO_RESOLVE;
		} else {
			// wait arp resolution, so drop packet.
			return ARP_RESULT_WAIT_RESOLUTION;
		}
	}

	// arp entry is exist.
	ether_addr_copy(&(entry->mac), mac);
	print_arp_entry("Get", entry->ifindex, addr, mac, arp_table->name);

	return ARP_RESULT_OK;
}

