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
 *      @file   arp.h
 *      @brief  ARP table.
 */

#ifndef __LAGOPUS_MODULE_L3_ARP_H__
#define __LAGOPUS_MODULE_L3_ARP_H__

#include <net/if.h>
#include <netinet/in.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ether.h>

#include "lagopus_types.h"
#include "lagopus_error.h"

#define MAX_ARP_ENTRIES 1024
#define SEND_TO_TAP_INTERVAL (3 * 1) // Interval to send to tap(mcast_solicit * retrans_time).

typedef enum {
	ARP_NO_RESOLVE = 0,
	ARP_RESOLVED,
} arp_resolve_status_t;

typedef enum {
	ARP_RESULT_ERROR = -1,
	ARP_RESULT_OK = 0,
	ARP_RESULT_TO_RESOLVE,
	ARP_RESULT_WAIT_RESOLUTION,
} arp_result_t;

/**
 * ARP table.
 */
struct arp_table {
	char name[RTE_HASH_NAMESIZE];
	struct rte_hash *hashmap;	// hashmap to registered arp info.
	uint64_t interval;		// SEND_TO_TAP_INTERVAL * rte_get_timer_hz().
};

/* ARP APIs. */
lagopus_result_t
arp_init(struct arp_table *arp_table, const char *name, uint64_t vrfrd);
void arp_fini(struct arp_table *arp_table);

lagopus_result_t
arp_entry_delete(struct arp_table *arp_table, int ifindex,
                 struct in_addr *dst_addr, struct ether_addr *mac);

lagopus_result_t
arp_entry_update(struct arp_table *arp_table, int ifindex,
                 struct in_addr *dst_addr, struct ether_addr *mac);

// arp_result_t: to decide the action by the arp resolution status.
arp_result_t
arp_get(struct arp_table *arp_table, struct in_addr *addr, struct ether_addr *mac);

lagopus_result_t
arp_entries_all_clear(struct arp_table *arp_table);

lagopus_result_t
arp_entries_all_copy(struct arp_table *src, struct arp_table *dst);
#endif /* __LAGOPUS_MODULE_L3_ARP_H__ */

