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

#include "router_log.h"
#include "route.h"

#define IPV4_LPM_MAX_RULES 1024
#define IPV4_LPM_NUMBER_TBL8S 256

/**
 * Output log for route information.
 */
static inline char *
get_arp_status(struct arp_entry *arp) {
	if (arp == NULL)
		return "not resolved";
	if (arp->valid)
		return "valid";
	else
		return "invalid";
}
static void
print_nexthop_entry(const char *type_str, ipv4_route_t *r, ipv4_nexthop_t *nh, char *name) {

	// destination network address.
	char dstbuf[BUFSIZ];
	inet_ntop(AF_INET, &r->dst, dstbuf, BUFSIZ);

	// gateway address.
	char gwbuf[BUFSIZ];
	inet_ntop(AF_INET, &nh->gw, gwbuf, BUFSIZ);
	int resolve = (nh->arp == NULL) ? -1 : nh->arp->valid;
	int ifindex = (nh->interface == NULL) ? -1 : nh->interface->ifindex;

	LAGOPUS_DEBUG("[ROUTE] (%s) %s: %15s/%d, gw %15s, if %3d, scope %d, metric %"PRIu32", arp [%s]\n",
		name, type_str, dstbuf, r->prefixlen, gwbuf,
		ifindex, nh->scope, nh->metric, get_arp_status(nh->arp));
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
create_nexthop(uint32_t gw, int prefixlen, int ifindex, uint8_t scope, uint32_t metric) {
	ipv4_nexthop_t *nh = rte_zmalloc(NULL, sizeof(ipv4_nexthop_t), 0);
	if (!nh) {
		lagopus_printf("[ROUTE] %s: rte_zmalloc() failed.", __func__);
		return NULL;
	}

	nh->gw        = gw;
	nh->prefixlen = prefixlen;
	nh->scope     = scope;
	nh->metric    = metric;
	nh->ifindex = ifindex;

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
			// Don't add nexthop with same metric.
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
del_nexthop(ipv4_route_t *r, struct route_entry *entry) {
	ipv4_nexthop_t *nh = r->top;
	while (nh) {
		if (nh->gw == entry->gw &&
		    nh->metric == entry->metric &&
		    nh->ifindex == entry->ifindex) {
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
bool
route_init(struct route_table *route_table, const char *name) {
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
	snprintf(route_table->name, sizeof(route_table->name), "%s", name);

	// create rte_lpm.
	char lpm_name[RTE_LPM_NAMESIZE];
	snprintf(lpm_name, sizeof(lpm_name),
		 "lpm_%s", name);
	LAGOPUS_DEBUG("[ROUTE] (%s) route table name: %s\n", route_table->name, lpm_name);

	route_table->table = rte_lpm_create(lpm_name, sockid, &config);
	if (route_table->table == NULL) {
		lagopus_printf("[ROUTE] %s: (%s) unable to create the lpm table: %s",
				__func__, route_table->name, rte_strerror(rte_errno));
		return false;
	}
	return true;
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
int
route_entry_add(struct route_table *route_table, struct route_entry *entry) {
	if (route_table == NULL || route_table->table == NULL || entry == NULL) {
		lagopus_printf("[ROUTE] %s: Invalid argument(route table = %p, hash = %p, entry = %p).",
				__func__, route_table, route_table->table, entry);
		return -1;
	}

	uint32_t index;
	uint32_t nhid;
	uint32_t dst = entry->dst;
	uint32_t gw = entry->gw;
	uint32_t prefixlen = entry->prefixlen;
	uint32_t network = entry->network;
	uint32_t ifindex = entry->ifindex;
	uint8_t scope = entry->scope;
	uint32_t metric = entry->metric;

	// check if the rule is present in the lpm table.
	int ret = rte_lpm_is_rule_present(route_table->table, ntohl(dst), prefixlen, &nhid);
	if (ret == 0) {
		// add new route
		for (index = 0; index < IPV4_MAX_ROUTES; index++) {
			ipv4_route_t *r = &route_table->routes[index];
			if (!r->used) {
				// set nexthop data.
				r->used = true;
				r->dst = dst;
				r->prefixlen = prefixlen;
				r->top = create_nexthop(gw, network, ifindex, scope, metric);
				if (!r->top) {
					lagopus_printf("[ROUTE] %s: (%s) Failed to create nexthop.",
							__func__, route_table->name);
					return -1;
				}
				if (rte_lpm_add(route_table->table, ntohl(dst),
						prefixlen, index) < 0) {
					// add failed.
					r->used = false;
					rte_free(r->top);
					lagopus_printf("[ROUTE] %s: (%s) Failed to add route entry.",
							__func__, route_table->name);
					return -1;
				}
				// add success.
				print_route_entry("Add", r, route_table->name);
				return index;
			}
		}
		lagopus_printf("[ROUTE] %s: (%s) nexthop table is full.",
			__func__, route_table->name);
	} else if (ret == 1) {
		// add new nexthop
		ipv4_nexthop_t *nh = create_nexthop(gw, network, ifindex, scope, metric);
		if (!nh) {
			lagopus_printf("[ROUTE] %s: (%s) Failed to create nexthop.",
					__func__, route_table->name);
			return -1;
		}
		if (add_nexthop(&route_table->routes[nhid], nh) != 0) {
			// Don't add nexthop with same metric.
			// Just free.
			rte_free(nh);
		}
		print_route_entry("Update", &route_table->routes[nhid], route_table->name);
		return nhid;
	}

	return -1;
}

/**
 * Delete a route entry from route table.
 */
bool
route_entry_delete(struct route_table *route_table, struct route_entry *entry) {
	uint32_t nhid;

	/* check if the entry is exist. */
	int ret = rte_lpm_is_rule_present(route_table->table,
				ntohl(entry->dst), (uint8_t)entry->prefixlen, &nhid);

	/* delete the entry from route table. */
	if (ret == 1) {
		ipv4_route_t *r = &route_table->routes[nhid];
		del_nexthop(r, entry);
		if (!r->top) {
			rte_lpm_delete(route_table->table,
				ntohl(entry->dst), entry->prefixlen);
			route_table->routes[nhid].used = false;
		}
		print_route_entry("Delete", &route_table->routes[nhid], route_table->name);
	} else {
		lagopus_printf("[ROUTE] %s: (%s) No entry in lpm.", __func__, route_table->name);
	}

	debug_print_list(route_table);

	return true;
}

/**
 * Update mac address of nexthop in nexthop entry.
 */
bool
route_entry_resolve_update(struct route_table *route_table,
		uint32_t dst, ipv4_nexthop_t *new,
		struct arp_entry *arp) {
	// add new route entry, by dst ip address.
	uint32_t id;
	struct route_entry entry;

	// set values to route entry.
	entry.dst = dst;
	entry.gw = new->gw;
	entry.prefixlen = 32;
	entry.network = new->prefixlen;
	entry.scope = new->scope;
	entry.metric = new->metric;
	entry.ifindex = new->ifindex;

	// add entry to route table.
	if ((id = route_entry_add(route_table, &entry)) < 0) {
		return false;
	}

	// get nexthop list by id.
	ipv4_nexthop_t *nh = route_table->routes[id].top;
	struct interface *ie = nh->interface;
	if (!ie) {
		// if ie is null, set new interface entry.
		ie = new->interface;
	}
	struct interface *nie = new->interface;
	while (nh) {
		// update resolve info.
		if (nh->gw == new->gw &&
		    nh->metric == new->metric &&
		    ie->ifindex == nie->ifindex) {
			if (arp) {
				// set new arp entry.
				nh->arp = arp;
			}
			*ie = *nie;
			print_route_entry("Resolve Update", &route_table->routes[id], route_table->name);
			return true;
		}
		nh = nh->next;
	}

	lagopus_printf("[ROUTE] %s: (%s) Failed to update resolved route entry.",
			__func__, route_table->name);
	return false;
}

/**
 * Get a route entry from route_table.
 */
ipv4_nexthop_t *
route_entry_get(struct route_table *route_table, const uint32_t dst) {
	uint32_t nexthop_index;
	int ret;
	ipv4_nexthop_t *nh = NULL;

	ret = rte_lpm_lookup(route_table->table,
			ntohl(dst), &nexthop_index);
	/* set nexthop information. */
	ipv4_route_t *r = &route_table->routes[nexthop_index];
	if (ret == 0 && r->used && r->top) {
		// Prioritize the first nexthop.
		nh = r->top;
		print_nexthop_entry("Get ", r, nh, route_table->name);
	} else {
		lagopus_printf("[ROUTE] %s: (%s) Not found entry.",
				__func__, route_table->name);
	}
	debug_print_list(route_table);

	return nh;
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
			nh = nh->next;
		}
		route_table->routes[i].used = false;
	}
	rte_lpm_delete_all(route_table->table);
	memset(route_table->routes, 0, sizeof(route_table->routes));
}

/**
 * Reset arp resolve satus of all etries.
 */
bool
route_entry_resolve_reset (struct route_table *route_table) {
	if (!route_table) {
		lagopus_printf("[ROUTE] %s: (%s) Invalid argument(route table is nil).",
				__func__, route_table->name);
		return false;
	}

	for (int i = 0; i < IPV4_MAX_ROUTES; i++) {
		ipv4_route_t *r = &route_table->routes[i];
		if (!r->used)
			continue;
		ipv4_nexthop_t *nh = r->top;
		while (nh) {
			if (nh->arp)
				nh->arp->valid = false;
			nh = nh->next;
		}
	}

	debug_print_list(route_table);

	return true;
}

