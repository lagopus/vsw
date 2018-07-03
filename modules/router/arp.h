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

#ifndef __LAGOPUS_MODULE_ROUTER_ARP_H__
#define __LAGOPUS_MODULE_ROUTER_ARP_H__

#include <net/if.h>
#include <netinet/in.h>

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ether.h>

#include "router_common.h"

#define MAX_ARP_ENTRIES 1024
#define SEND_TO_TAP_INTERVAL (3 * 1) // Interval to send to tap(mcast_solicit * retrans_time).

/**
 * ARP table.
 */
struct arp_table {
	char name[RTE_HASH_NAMESIZE];
	struct rte_hash *hashmap;	// hashmap to registered arp info.
};

/* ARP APIs. */
bool
arp_init(struct arp_table *arp_table, const char *name);
void
arp_fini(struct arp_table *arp_table);

bool
arp_entry_delete(struct arp_table *arp_table, struct arp_entry *ae);
bool
arp_entry_update(struct arp_table *arp_table, struct arp_entry *ae);
// arp_result_t: to decide the action by the arp resolution status.
struct arp_entry *
arp_entry_get(struct arp_table *arp_table, uint32_t addr);

#endif /* __LAGOPUS_MODULE_ROUTER_ARP_H__ */

