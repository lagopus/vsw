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
 *      @file   route.c
 *      @brief  Routing table use dpdk hash.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <rte_errno.h>
#include <rte_malloc.h>

#include "l3_log.h"
#include "route.h"

#define IPV4_MAX_NEXTHOPS 1024
#define IPV4_LPM_MAX_RULES 1024
#define IPV4_LPM_NUMBER_TBL8S 256

/**
 * Output log for route information.
 */
static void
print_nexthop_entry(const char *type_str, ipv4_route_t *r, ipv4_nexthop_t *nh, char *name) {

	// destination network address.
	char destbuf[BUFSIZ];
	inet_ntop(AF_INET, &r->dest, destbuf, BUFSIZ);

	// gateway address.
	char gwbuf[BUFSIZ];
	inet_ntop(AF_INET, &nh->gw, gwbuf, BUFSIZ);

	LAGOPUS_DEBUG("%s: [ROUTE] %s: %s/%d, gw %s, if %d, metric %"PRIu32", brid %"PRIu32", resolve %d",
		name, type_str, destbuf, r->prefixlen, gwbuf,
		nh->ifindex, nh->metric, nh->bridgeid, nh->resolve_status);
}

static void
print_route_entry(const char *type_str, ipv4_route_t *r, char *name) {

	if (!r->used) {
		return;
	}

	ipv4_nexthop_t *nh = r->top;
	while (nh) {
		print_nexthop_entry(type_str, r, nh, name);
		nh = nh->next;
	}
}


void
debug_print_list(struct route_table *route_table) {
#if 1 // DEBUG
	for (int i = 0; i < IPV4_MAX_NEXTHOPS; i++) {
		ipv4_route_t *r = &route_table->routes[i];
		if (r->used) {
			print_route_entry("List", r, route_table->name);
		}
	}
#endif
}

/**
 * Create nexthop entry.
 */
ipv4_nexthop_t *
create_nexthop(struct in_addr *gw, int ifindex, uint8_t scope, uint32_t bridgeid, uint32_t metric) {
	ipv4_nexthop_t *nh = rte_zmalloc(NULL, sizeof(ipv4_nexthop_t), 0);
	if (!nh) {
		lagopus_printf("%s: rte_zmalloc() failed.\n", __func__);
		return NULL;
	}

	nh->gw = gw->s_addr;
	nh->scope = scope;
	nh->ifindex = ifindex;
	nh->metric = metric;
	nh->bridgeid = bridgeid;

	nh->next = NULL;
	nh->prev = NULL;

	return nh;
}

/**
 * Add nexthop to route entry.
 */
int
add_nexthop(ipv4_route_t *r, ipv4_nexthop_t *new) {
	int ret = 0;
	ipv4_nexthop_t *nh = r->top;
	while (nh) {
		if (nh->metric < new->metric) {
			if (nh->next == NULL) {
				nh->next = new;
				new->prev = nh;
				break;
			}
			nh = nh->next;
			continue;
		} else if (nh->metric == new->metric) {
			ret = -1;
			break;
		} else {
			if (r->top == nh) {
				r->top = new;
			} else {
				nh->prev->next = new;
			}
			new->next = nh;
			new->prev = nh->prev;
			nh->prev = new;
			break;
		}
	}
	return ret;
}

/**
 * Delete nexthop from route entry.
 */
void
del_nexthop(ipv4_route_t *r, uint32_t gw, uint32_t ifindex, uint32_t metric) {
	ipv4_nexthop_t *nh = r->top;
	while (nh) {
		if (nh->gw == gw && nh->metric == metric &&  nh->ifindex == ifindex) {
			if (nh->prev)
				nh->prev->next = nh->next;
			else
				r->top = nh->next;

			if (nh->next)
				nh->next->prev = nh->prev;

			rte_free(nh);
			break;
		}
		nh = nh->next;
	}
}

/*** public functions ***/
/**
 * Initialize route table.
 */
lagopus_result_t
route_init(struct route_table *route_table, const char *name, uint64_t vrfrd) {
	unsigned int sockid = 0;
	uint32_t lcore = rte_lcore_id();
	struct rte_lpm_config config;

	// set end of entries.
	route_table->routes[IPV4_MAX_ROUTES- 1].used = false;

	config.max_rules = IPV4_LPM_MAX_RULES;
	config.number_tbl8s = IPV4_LPM_NUMBER_TBL8S;
	config.flags = 0;

	if (lcore != UINT32_MAX) {
		sockid = rte_lcore_to_socket_id(lcore);
	}

	// set module name.
	snprintf(route_table->name, sizeof(route_table->name), "%s_%"SCNu64, name, vrfrd);

	// create rte_lpm.
	char lpm_name[RTE_LPM_NAMESIZE];
	snprintf(lpm_name, sizeof(lpm_name),
		 "lpm%"SCNu64, vrfrd);
	LAGOPUS_DEBUG("%s: [ROUTE] route table name: %s\n", route_table->name, lpm_name);

	route_table->table = rte_lpm_create(lpm_name, sockid, &config);
	if (route_table->table == NULL) {
		lagopus_printf("%s: [ROUTE] unable to create the lpm table: %s\n",
				route_table->name, rte_strerror(rte_errno));
		return LAGOPUS_RESULT_ANY_FAILURES;
	}
	return LAGOPUS_RESULT_OK;
}

/**
 * Finalize route table.
 */
void
route_fini(struct route_table *route_table) {
	route_entries_all_clear(route_table);
	rte_lpm_free(route_table->table);
}

/**
 * Add a route entry to route table.
 */
lagopus_result_t
route_entry_add(struct route_table *route_table, struct in_addr *dest,
		int prefixlen, struct in_addr *gw, int ifindex,
		uint8_t scope, uint32_t metric, uint32_t bridgeid) {
	int ret;
	uint32_t index;
	uint32_t nhid;

	if (route_table == NULL || dest == NULL || gw == NULL) {
		return LAGOPUS_RESULT_INVALID_ARGS;
	}
	if (route_table->table == NULL) {
		return LAGOPUS_RESULT_INVALID_ARGS;
	}

	ret = rte_lpm_lookup(route_table->table, ntohl(dest->s_addr), &nhid);
	if (ret == -ENOENT) {
		// add new route
		for (index = 0; index < IPV4_MAX_ROUTES; index++) {
			ipv4_route_t *r = &route_table->routes[index];
			if (!r->used) {
				// set nexthop data.
				r->used = true;
				r->dest = dest->s_addr;
				r->prefixlen = prefixlen;
				r->top = create_nexthop(gw, ifindex, scope, bridgeid, metric);
				if (!r->top) {
					lagopus_printf("create nexthop failed.\n");
					return LAGOPUS_RESULT_NO_MEMORY;
				}
				if (rte_lpm_add(route_table->table, ntohl(dest->s_addr),
						prefixlen, index) < 0) {
					// add failed.
					r->used = false;
					rte_free(r->top);
					return LAGOPUS_RESULT_ANY_FAILURES;
				}
				// add success.
				print_route_entry("Add", r, route_table->name);
				return LAGOPUS_RESULT_OK;
			}
		}
	} else if (ret == 0) {
		// add new nexthop
		ipv4_nexthop_t *nh = create_nexthop(gw, ifindex, scope, bridgeid, metric);
		if (!nh)
			return LAGOPUS_RESULT_NO_MEMORY;
		ret = add_nexthop(&route_table->routes[nhid], nh);
		if (ret != 0) {
			rte_free(nh);
		}
		print_route_entry("Update", &route_table->routes[nhid], route_table->name);
		return LAGOPUS_RESULT_OK;
	} else {
		return LAGOPUS_RESULT_INVALID_ARGS;
	}

	lagopus_printf("%s: [ROUTE] nexthop table is full.", route_table->name);
	return LAGOPUS_RESULT_OUT_OF_RANGE;
}

/**
 * Delete a route entry from route table.
 */
lagopus_result_t
route_entry_delete(struct route_table *route_table, struct in_addr *dest,
		int prefixlen, struct in_addr *gw, int ifindex, uint32_t metric) {
	lagopus_result_t rv = LAGOPUS_RESULT_OK;
	int ret;
	uint32_t nhid;

	/* check if the entry is exist. */
	ret = rte_lpm_is_rule_present(route_table->table,
				ntohl(dest->s_addr), (uint8_t)prefixlen, &nhid);

	/* delete the entry from route table. */
	if (ret == 1) {
		ipv4_route_t *r = &route_table->routes[nhid];
		del_nexthop(r, gw->s_addr, ifindex, metric);
		if (!r->top) {
			rte_lpm_delete(route_table->table,
				ntohl(dest->s_addr), prefixlen);
			route_table->routes[nhid].used = false;
		}
		print_route_entry("Delete", &route_table->routes[nhid], route_table->name);
	}

	debug_print_list(route_table);

	return rv;
}

/**
 * Update mac address of nexthop in nexthop entry.
 */
lagopus_result_t
route_resolve_update(struct route_table *route_table, uint32_t nhid,
		uint32_t gw, uint32_t ifindex, uint32_t metric,
		struct ether_addr *src_mac, struct ether_addr *dst_mac) {
	// get nexthop list by nhid.
	ipv4_nexthop_t *nh = route_table->routes[nhid].top;
	while (nh) {
		// update resolve info.
		if (nh->gw == gw && nh->metric == metric &&  nh->ifindex == ifindex) {
			ether_addr_copy(src_mac, &(nh->src_mac));
			ether_addr_copy(dst_mac, &(nh->dst_mac));
			nh->resolve_status = RESOLVED;
			print_route_entry("Resolve Update", &route_table->routes[nhid], route_table->name);
			return LAGOPUS_RESULT_OK;
		}
	}
	return LAGOPUS_RESULT_INVALID_ARGS;
}

/**
 * Get a route entry from route_table.
 */
lagopus_result_t
route_entry_get(struct route_table *route_table, const struct in_addr *dest,
		int prefixlen, ipv4_nexthop_t *nh, uint32_t *nhid) {
	lagopus_result_t rv = LAGOPUS_RESULT_OK;
	uint32_t nexthop_index;
	int ret;

	ret = rte_lpm_lookup(route_table->table,
			ntohl(dest->s_addr), &nexthop_index);
	/* set nexthop information. */
	ipv4_route_t *r = &route_table->routes[nexthop_index];
	if (ret == 0 && r->used && r->top) {
		memcpy(nh, r->top, sizeof(ipv4_nexthop_t));
		*nhid = nexthop_index;
		print_nexthop_entry("Get ", r, nh, route_table->name);
	} else {
		rv = LAGOPUS_RESULT_NOT_FOUND;
	}

	debug_print_list(route_table);

	return rv;
}

/**
 * Clear all entries in route table.
 */
void
route_entries_all_clear(struct route_table *route_table) {
	for (int i = 0; i < IPV4_MAX_ROUTES; i++) {
		ipv4_nexthop_t *nh = route_table->routes[i].top;
		while (nh) {
			rte_free(nh);
		}
		route_table->routes[i].used = false;
	}
	rte_lpm_delete_all(route_table->table);
	memset(route_table->routes, 0, sizeof(route_table->routes));
}

/**
 * Reset arp resolve satus of all etries.
 */
lagopus_result_t
route_entry_resolve_reset (struct route_table *route_table) {
	if (!route_table) {
		return LAGOPUS_RESULT_INVALID_ARGS;
	}

	for (int i = 0; i < IPV4_MAX_ROUTES; i++) {
		ipv4_route_t *r = &route_table->routes[i];
		if (!r->used)
			continue;
		ipv4_nexthop_t *nh = r->top;
		while (nh) {
			nh->resolve_status = NO_RESOLVE;
			nh = nh->next;
		}
	}

	debug_print_list(route_table);

	return LAGOPUS_RESULT_OK;
}

