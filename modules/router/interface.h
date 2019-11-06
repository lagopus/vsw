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
 *      @file   interface.h
 *      @brief  Interface table.
 */

#ifndef VSW_MODULE_ROUTER_INTERFACE_H_
#define VSW_MODULE_ROUTER_INTERFACE_H_

#include <net/if.h>
#include <stdbool.h>

#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "router_common.h"

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
	struct rte_hash *hashmap; // Self interface hardware address.
	struct rte_hash *self;    // Self if address to tap.
};

/* Interface APIs. */
struct interface_table *
interface_init(const char *name);
void interface_fini(struct interface_table *interface_tbl);

// ip address
bool
interface_ip_add(struct interface_table *interface_table, struct interface_addr_entry *ia);
bool
interface_ip_delete(struct interface_table *interface_table, struct interface_addr_entry *ia);
bool
interface_ip_is_self(struct interface_table *interface_table, uint32_t addr, vifindex_t ifindex);

// nexthop reference
bool
interface_nexthop_reference_add(struct interface *interface, nexthop_t *nh);
void
interface_nexthop_reference_delete(struct interface *interface, nexthop_t *nh);

// inteface infomation.
bool
interface_entry_add(struct router_context *ctx, struct interface_entry *ie);
bool
interface_entry_delete(struct router_context *ctx, struct interface_entry *ie);
struct interface *
interface_entry_get(struct interface_table *interface_table, uint32_t ifindex);

// mtu of the interface
bool
interface_mtu_update(struct interface_table *interface_table, struct interface_entry *ie);

#endif /* VSW_MODULE_ROUTER_INTERFACE_H_ */

