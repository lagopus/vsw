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

#ifndef __LAGOPUS_MODULE_L3_ROUTE_H__
#define __LAGOPUS_MODULE_L3_ROUTE_H__

#include <net/if.h>
#include <netinet/in.h>

#include "lagopus_types.h"
#include "lagopus_error.h"

#include <rte_config.h>
#include <rte_ip.h>
#include <rte_lpm.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_ether.h>

#define IPV4_MAX_NEXTHOPS 1024
#define IPV4_MAX_ROUTES 1024

typedef enum {
	NO_RESOLVE = 0,
	RESOLVED,
} resolve_status_t;

/**
 * Nexthop information table.
 */
typedef struct ipv4_nexthop {
	uint32_t gw;       /**< nexthop address. */
	uint16_t scope;    /**< scope of interface. */
	uint32_t ifindex;  /**< nexthop interface index. */
	uint32_t metric;
	uint32_t bridgeid;
	struct ether_addr src_mac;	/**< mac address of nethop */
	struct ether_addr dst_mac;	/**< mac address of nethop */
	int resolve_status;

	struct ipv4_nexthop *next;
	struct ipv4_nexthop *prev;
} ipv4_nexthop_t;

/**
 * Route
 */
typedef struct ipv4_route {
	bool used;   /**< status of whether entry is registered. */
	uint32_t dest;     /**< destination address. */
	int prefixlen;     /**< length of prefix. */
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
lagopus_result_t
route_init(struct route_table *route_table, const char *name, uint64_t vrfrd);
void route_fini(struct route_table *route_table);

lagopus_result_t
route_entry_add(struct route_table *route_table, struct in_addr *dest,
                int prefixlen, struct in_addr *gate, int ifindex,
                uint8_t scope, uint32_t metric, uint32_t bridgeid);

lagopus_result_t
route_entry_delete(struct route_table *route_table, struct in_addr *dest,
                   int prefixlen, struct in_addr *gate, int ifindex, uint32_t metric);

lagopus_result_t
route_entry_update(struct route_table *route_table, struct in_addr *dest,
                   int prefixlen, struct in_addr *gate, int ifindex,
                   uint8_t scope, uint32_t bridgeid);

lagopus_result_t
route_resolve_update(struct route_table *route_table, uint32_t nhid,
		uint32_t gw, uint32_t ifindex, uint32_t metric,
		struct ether_addr *src_mac, struct ether_addr *dst_mac);

lagopus_result_t
route_entry_modify(struct route_table *route_table,
                   int in_ifindex);

lagopus_result_t
route_entry_get(struct route_table *route_table, const struct in_addr *dest,
		int prefixlen, ipv4_nexthop_t *nh, uint32_t *nhid);

lagopus_result_t
route_rule_get(struct route_table *route_table, struct in_addr *dest,
               struct in_addr *gate, int *prefixlen, uint32_t *ifindex,
               uint8_t *scope, uint32_t *bridgeid, void **item);

void
route_entries_all_clear(struct route_table *route_table);

lagopus_result_t
route_entry_resolve_reset (struct route_table *route_table);

#endif /* __LAGOPUS_MODULE_L3_ROUTE_H__ */
