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
 *      @file   route.h
 *      @brief  Routing table.
 */

#ifndef VSW_MODULE_ROUTER_ROUTE_H_
#define VSW_MODULE_ROUTER_ROUTE_H_

#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_lpm.h>

#include "router_common.h"

#define IPV4_MAX_ROUTES 100000
#define ROUTE_ENTRY_POOL_SIZE 100

/**
 * Metric entry.
 * List by ascending order.
 */
typedef struct fib {
	uint32_t metric;
	nexthop_t *nexthop;
	int nexthop_num;
	struct fib *next;
} fib_t;

/**
 * Route entry.
 * There is a possiblity of having more than one nexthop.
 * Nexthop is listed from the top in order of preference.
 */
typedef struct route {
	uint32_t dst;	  /**< destination address. */
	uint32_t prefixlen;    /**< length of prefix. */
	enum rt_scope_t scope; /**< scope of interface. */
	uint8_t route_type;    /* Kind of route(for check broadcast)*/
	fib_t *fib;

	int next; // for free list.
} route_t;

/**
 * Routing table.
 */
struct route_table {
	struct rte_lpm *lpm; /**< dir-24-8 to registered route informations. */
	route_t *entries;    /**< registered nexthop information. */
	int free;
	uint32_t route_num;
	uint32_t total;
	route_t default_route;
};

/* ROUTE APIs. */
struct route_table *
route_init(const char *name);
void route_fini(struct route_table *route_table);

bool
route_entry_add(struct router_tables *t, struct route_entry *entry);

bool
route_entry_delete(struct router_tables *t, struct route_entry *entry);

nexthop_t *
route_entry_get(struct router_tables *t, const uint32_t dst);

#endif /* VSW_MODULE_ROUTER_ROUTE_H_ */
