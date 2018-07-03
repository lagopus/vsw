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
 *      @file   route.h
 *      @brief  Routing table.
 */

#ifndef __LAGOPUS_MODULE_ROUTER_ROUTE_H__
#define __LAGOPUS_MODULE_ROUTER_ROUTE_H__

#include <net/if.h>
#include <netinet/in.h>

#include <rte_config.h>
#include <rte_ip.h>
#include <rte_lpm.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_ether.h>

#include "router_common.h"

#define IPV4_MAX_NEXTHOPS 100000
#define IPV4_MAX_ROUTES   100000

typedef enum {
	NO_RESOLVE = 0,
	RESOLVED,
} resolve_status_t;

/**
 * Nexthop information table.
 */
typedef struct ipv4_nexthop {
	uint32_t gw;	/**< nexthop address. */
	uint32_t prefixlen;	/**< prefix length. */
	uint16_t scope;		/**< scope of interface. */
	uint32_t metric;	/**< metric of interface. */
	uint32_t ifindex;

	struct arp_entry *arp;
	struct interface *interface;

	struct ipv4_nexthop *next;
	struct ipv4_nexthop *prev;
} ipv4_nexthop_t;

/**
 * Route
 */
typedef struct ipv4_route {
	bool used;   /**< status of whether entry is registered. */
	uint32_t dst;     /**< destination address. */
	uint32_t prefixlen;     /**< length of prefix. */
	ipv4_nexthop_t *top;
} ipv4_route_t;

/**
 * Route table.
 */
struct route_table {
	struct rte_lpm *table; /**< dir-24-8 to registered route informations. */
	char name[RTE_LPM_NAMESIZE];            /**< name of dir-24-8 table. */
	ipv4_route_t routes[IPV4_MAX_ROUTES]; /**< registered nexthop information. */
};

/* ROUTE APIs. */
bool
route_init(struct route_table *route_table, const char *name);
void route_fini(struct route_table *route_table);

int
route_entry_add(struct route_table *route_table, struct route_entry *entry);

bool
route_entry_delete(struct route_table *route_table, struct route_entry *entry);

bool
route_entry_resolve_update(struct route_table *route_table, uint32_t dst,
		ipv4_nexthop_t *new, struct arp_entry *arp);

ipv4_nexthop_t *
route_entry_get(struct route_table *route_table, const uint32_t dst);

void
route_entries_all_clear(struct route_table *route_table);

bool
route_entry_resolve_reset(struct route_table *route_table);

#endif /* __LAGOPUS_MODULE_ROUTER_ROUTE_H__ */
