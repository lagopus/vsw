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
 *      @file   interface.h
 *      @brief  Interface table.
 */

#ifndef __LAGOPUS_MODULE_L3_INTERFACE_H__
#define __LAGOPUS_MODULE_L3_INTERFACE_H__

#include <net/if.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ether.h>
#include <stdbool.h>

#include "lagopus_types.h"
#include "lagopus_error.h"

#define IS_IPV4_BROADCAST(x) \
	((x) == (uint32_t)0xFFFFFFFF)

enum {
	INTERFACE_IP_SELF_UNICAST,
	INTERFACE_IP_BROADCAST,
	INTERFACE_IP_MULTICAST,
	INTERFACE_IP_NOT_SELF
} interface_ip;
/**
 * Interface table.
 */
struct interface_table {
	char name[RTE_HASH_NAMESIZE];
	struct rte_hash *hashmap;	// Self interface hardware address.
	struct rte_hash *self;		// Self if address to tap.
	struct rte_hash *hostif;	// Multicast address to hostif.
};

/* Interface APIs. */
lagopus_result_t
interface_init(struct interface_table *interface_tbl, const char *name, uint64_t vrfrd);
void interface_fini(struct interface_table *interface_tbl);

// management inteface infomation.
lagopus_result_t
interface_update(struct interface_table *if_tbl, uint32_t ifindex, struct ether_addr *mac);
lagopus_result_t
interface_delete(struct interface_table *if_tbl, uint32_t ifindex);
lagopus_result_t
interface_get(struct interface_table *if_tbl, uint32_t ifindex, struct ether_addr *mac);

// management ip address to self.
lagopus_result_t
interface_self_update(struct interface_table *if_tbl, struct in_addr ip);
lagopus_result_t
interface_self_delete(struct interface_table *if_tbl, struct in_addr ip);
bool
interface_is_self(struct interface_table *if_tbl, struct in_addr ip);

// management ip address to hostif.
lagopus_result_t
interface_hostif_update(struct interface_table *if_tbl, struct in_addr ip);
lagopus_result_t
interface_hostif_delete(struct interface_table *if_tbl, struct in_addr ip);
bool
interface_is_hostif(struct interface_table *if_tbl, struct in_addr ip);

#endif /* __LAGOPUS_MODULE_L3_INTERFACE_H__ */

