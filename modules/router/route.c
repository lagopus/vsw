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
 *      @file   route.c
 *      @brief  Routing table use dpdk hash.
 */

#include <inttypes.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "interface.h"
#include "neighbor.h"
#include "route.h"
#include "router_log.h"

#define IPV4_LPM_MAX_RULES 1024
#define IPV4_LPM_NUMBER_TBL8S 256

#define ROUTE_EOL -1

/**
 * Update route entry table.
 * If update failed, do running.
 */
static bool
routelist_update(struct route_table *rt) {
	if (rt->total >= IPV4_MAX_ROUTES) {
		ROUTER_DEBUG("[ROUTE] Route entry table is full.");
		return false;
	}

	// TODO: If there are too many free entries,
	//      I want to shrink.
	rt->entries = rte_realloc(rt->entries,
				  sizeof(route_t) * (rt->total + ROUTE_ENTRY_POOL_SIZE),
				  0);
	if (!rt->entries) {
		ROUTER_DEBUG("[ROUTE] Route entry table realloc failed.");
		return false;
	}

	// Reset first free index.
	rt->free = rt->total;

	// Set new list number.
	int i;
	for (i = 0; i < ROUTE_ENTRY_POOL_SIZE - 1; i++)
		rt->entries[rt->total + i].next = (rt->total + i) + 1;
	// Set EOL
	rt->entries[rt->total + i].next = ROUTE_EOL;

	// Total number of entries in list.
	rt->total += ROUTE_ENTRY_POOL_SIZE;

	return true;
}

/**
 * Push route entry to free list.
 */
static void
routelist_push(struct route_table *rt, int id) {
	rt->entries[id].next = rt->free;
	rt->free = id;
}

/**
 * Pop route entry from free list.
 */
static int
routelist_pop(struct route_table *rt) {
	if (rt->free == ROUTE_EOL && !routelist_update(rt))
		return ROUTE_EOL;

	int id = rt->free;
	rt->free = rt->entries[id].next;

	return id;
}

/**
 * Create free list.
 */
static bool
routelist_create(struct route_table *rt) {
	// Create pool.ROUTE_ENTRY_POOL_SIZE.
	rt->entries = rte_zmalloc(NULL, sizeof(route_t) * ROUTE_ENTRY_POOL_SIZE, 0);
	// allocation failed, return a error.
	if (!rt->entries) {
		ROUTER_ERROR("Allocation failed.");
		return false;
	}

	// set head
	rt->free = 0;
	// create or update free list.
	int i;
	for (i = 0; i < ROUTE_ENTRY_POOL_SIZE - 1; i++)
		rt->entries[i].next = i + 1;
	rt->entries[i].next = ROUTE_EOL;
	rt->total = ROUTE_ENTRY_POOL_SIZE;
	return true;
}

/**
 * Output log for route information.
 */
static void
print_nexthop_entry(nexthop_t *nh) {
	ROUTER_DEBUG("      gw ip: %s, weight: %d, netmask: %d",
		     ip2str(nh->gw), nh->weight, nh->netmask);

	struct interface *ie = nh->interface;
	struct interface_entry *base = &ie->base;

	if (!ie)
		return;
	ROUTER_DEBUG("      ifindex: %d, vid: %d, mtu: %d, tunnel: %s\n",
		     base->ifindex, base->vid, base->mtu,
		     is_iff_type_tunnel(base) ? "true" : "false");
}

static void
print_fib_entry(fib_t *f) {
	ROUTER_DEBUG("    metric: %" PRIu32 "\n", f->metric);
	for (int i = 0; i < f->nexthop_num; i++) {
		nexthop_t *nh = &f->nexthop[i];
		if (!nh)
			return;
		print_nexthop_entry(nh);
	}
}

static void
print_route_entry(route_t *r) {
	ROUTER_DEBUG("  %s/%d route type: %d, scope: %d\n",
		     ip2str(r->dst), r->prefixlen, r->route_type, r->scope);
	fib_t *f = r->fib;
	while (f) {
		print_fib_entry(f);
		f = f->next;
	}
}

static void
print_route_list(struct route_table *rt) {
	ROUTER_DEBUG("[ROUTE] List");
	for (uint32_t i = 0, cnt = 0;
	     i < IPV4_MAX_ROUTES && cnt < rt->route_num; i++) {
		route_t *r = &rt->entries[i];
		if (!r->fib)
			continue;
		print_route_entry(r);
		cnt++;
	}
}

static void
fib_free(fib_t *fib) {
	// Delete reference of a nexthop from an interface info
	for (int i = 0; i < fib->nexthop_num; i++)
		interface_nexthop_reference_delete(fib->nexthop[i].interface, &fib->nexthop[i]);
	free(fib->nexthop);
	rte_free(fib);
}

/**
 * Create metric entry.
 */
static fib_t *
fib_create(struct interface_table *it, struct route_entry *entry) {
	fib_t *f = rte_zmalloc(NULL, sizeof(fib_t), 0);
	if (!f) {
		ROUTER_ERROR("[ROUTE] Failed to allocate metric entry.");
		return NULL;
	}

	// Set metric
	f->metric = entry->metric;
	f->next = NULL;

	f->nexthop_num = entry->nexthop_num;
	f->nexthop = entry->nexthops;
	for (int i = 0; i < f->nexthop_num; i++) {
		f->nexthop[i].interface = interface_entry_get(it, entry->nexthops[i].ifindex);

		// Add reference of a nexthop that refer to a interface
		if (!interface_nexthop_reference_add(f->nexthop[i].interface, &f->nexthop[i])) {
			f->nexthop_num = i;
			fib_free(f);
			return NULL;
		}
	}

	return f;
}

/**
 * Add metric to route entry.
 *
 * The existing entry which has the same metric as the new one
 * is replaced with the new entry.
 */
static void
fib_add(route_t *r, fib_t *new) {
	fib_t **f = &r->fib;

	while ((*f != NULL) && ((*f)->metric < new->metric))
		f = &((*f)->next);

	// Replace the old one with the new one, iff the metrics
	// are the same. Otherwise, insert.
	if ((*f != NULL) && ((*f)->metric == new->metric)) {
		new->next = (*f)->next;
		fib_free(*f);
	} else {
		new->next = *f;
	}
	*f = new;
}

/**
 * Delete metric from route entry.
 */
static void
fib_delete(route_t *r, uint32_t metric) {
	fib_t **f = &r->fib;
	while (*f) {
		if ((*f)->metric == metric) {
			fib_t *p = *f;
			*f = p->next;
			fib_free(p);
			return;
		}
		f = &(*f)->next;
	}
	ROUTER_ERROR("[ROUTE] requested to delete unknown fib entry (metric: %u)", metric);
}

/**
 * Get free route entry, and add to lpm.
 */
static uint32_t
route_add_new_entry(struct route_table *rt, struct route_entry *entry) {
	// Get free route entry.
	int index = routelist_pop(rt);
	if (index == -1) {
		ROUTER_ERROR("[ROUTE] free list updating failed.");
		return -1;
	}

	route_t *r = &rt->entries[index];
	// Set route information
	r->dst = entry->dst;
	r->prefixlen = entry->prefixlen;
	r->scope = entry->scope;
	// Add to lpm new route entry.
	if (rte_lpm_add(rt->lpm, entry->dst, entry->prefixlen, index) < 0) {
		// Add failed.
		ROUTER_ERROR("[ROUTE] Failed to add route entry.");
		return -1;
	}
	rt->route_num++;

	return index;
}

/**
 * Delete a route entry from route table.
 */
bool
route_entry_delete(struct router_tables *t, struct route_entry *entry) {
	uint32_t nhid;
	struct route_table *rt = t->route;

	// Delete default route.
	if (entry->dst == 0) {
		fib_delete(&rt->default_route, entry->metric);
		return true;
	}

	// Check if the entry is exist.
	int ret = rte_lpm_is_rule_present(rt->lpm, entry->dst,
					  (uint8_t)entry->prefixlen, &nhid);
	// fatal error.
	if (ret < 0) {
		ROUTER_ERROR("[ROUTE] rte_lpm_is_rule_present() failed, err = %d.", ret);
		return false;
	}

	// No entry.
	if (ret == 0) {
		ROUTER_INFO("[ROUTE] No entry in lpm.");
		return true;
	}

	// Route entry exists
	route_t *r = &rt->entries[nhid];

	if (VSW_LOG_DEBUG_ENABLED(router_log_id)) {
		ROUTER_DEBUG("[ROUTE] Delete");
		print_route_entry(&rt->entries[nhid]);
	}

	// Delete rule specified by agent.
	fib_delete(r, entry->metric);

	// No nexthop, delete route entry from table.
	if (!r->fib) {
		rte_lpm_delete(rt->lpm,
			       entry->dst, entry->prefixlen);
		routelist_push(rt, nhid);
		rt->route_num--;
	}

	if (VSW_LOG_DEBUG_ENABLED(router_log_id))
		print_route_list(rt);

	return true;
}

/**
 * Add a route entry to route table.
 * If entry exists, update.
 *
 * The metric of the route entry must be unique. Thus, we
 * replace the old one with the new one, if the metrics are
 * the same. fib_add() guarantees this.
 */
bool
route_entry_add(struct router_tables *t, struct route_entry *entry) {
	// Newly added or updated, create a new fib entry and nexthops.
	fib_t *f = fib_create(t->interface, entry);
	if (!f) {
		ROUTER_ERROR("Failed to create metric entry.");
		return false;
	}

	struct route_table *rt = t->route;

	// Default route.
	if (entry->dst == 0) {
		fib_add(&rt->default_route, f);
		return true;
	}

	uint32_t nhid;
	uint32_t dst = entry->dst;
	uint32_t prefixlen = entry->prefixlen;
	// Check if the rule is present in the lpm table.
	int ret = rte_lpm_is_rule_present(rt->lpm, dst, prefixlen, &nhid);
	// fatal error.
	if (ret < 0) {
		ROUTER_ERROR("[ROUTE] rte_lpm_is_rule_present() failed, err = %d.", ret);
		rte_free(f);
		return false;
	}

	// Add route entry to lpm.
	if (ret == 0) {
		nhid = route_add_new_entry(rt, entry);
		if (nhid == -1) {
			rte_free(f);
			return false;
		}
	}

	// Add nexthop to list of route entry.
	route_t *r = &rt->entries[nhid];
	// Add metric entry to metric list of the route entry.
	fib_add(r, f);

	// output route entry list for debug.
	if (VSW_LOG_DEBUG_ENABLED(router_log_id)) {
		ROUTER_DEBUG("[ROUTE] Update");
		print_route_entry(r);
		print_route_list(rt);
	}

	return true;
}

/**
 * Get a route entry from route_table.
 */
nexthop_t *
route_entry_get(struct router_tables *tbls, const uint32_t dst) {
	struct route_table *rt = tbls->route;
	uint32_t nexthop_index;
	int ret = rte_lpm_lookup(rt->lpm, dst, &nexthop_index);
	// Lookup miss, no entry.
	if (ret == -ENOENT) {
		// return default route.
		if (rt->default_route.fib)
			return rt->default_route.fib->nexthop;
		return NULL;
	}

	// Lookup failed
	if (ret < 0) {
		ROUTER_ERROR("[ROUTE] rte_lpm_lookup() failed, err = %d.", ret);
		return false;
	}

	// Set nexthop information.
	route_t *r = &rt->entries[nexthop_index];
	// Use the first nexthop with the highest metric.
	fib_t *f = r->fib;
	// TODO: In the future, we need to be able to select the nexthop by weight.
	nexthop_t *nh = &f->nexthop[0];

	// Interface must be resolved.
	// It does not hold the interface index at this timing.
	if (!nh->interface) {
		ROUTER_ERROR("[ROUTE] No valid interface.");
		return NULL;
	}

	if (VSW_LOG_DEBUG_ENABLED(router_log_id)) {
		ROUTER_DEBUG("[ROUTE] Get %s", ip2str(dst));
		print_nexthop_entry(nh);
		print_route_list(rt);
	}

	return nh;
}

/**
 * Initialize route table.
 */
struct route_table *
route_init(const char *name) {
	struct route_table *rt;
	if (!(rt = rte_zmalloc(NULL, sizeof(struct route_table), 0))) {
		ROUTER_ERROR("router: %s: route table rte_zmalloc() failed.", name);
		return NULL;
	}

	if (!routelist_create(rt)) {
		rte_free(rt);
		return NULL;
	}

	unsigned int sockid = 0;
	uint32_t lcore = rte_lcore_id();
	if (lcore != UINT32_MAX)
		sockid = rte_lcore_to_socket_id(lcore);

	// Create rte_lpm.
	char lpm_name[RTE_LPM_NAMESIZE];
	snprintf(lpm_name, sizeof(lpm_name), "lpm_%s", name);
	ROUTER_DEBUG("[ROUTE] (%s) route table name: %s\n", name, lpm_name);

	struct rte_lpm_config config;
	config.max_rules = IPV4_LPM_MAX_RULES;
	config.number_tbl8s = IPV4_LPM_NUMBER_TBL8S;
	config.flags = 0;
	rt->lpm = rte_lpm_create(lpm_name, sockid, &config);
	if (rt->lpm == NULL) {
		ROUTER_ERROR("[ROUTE] (%s) unable to create the lpm table: %s",
			     name, rte_strerror(rte_errno));
		rte_free(rt);
		return NULL;
	}

	return rt;
}

/**
 * Finalize route table.
 */
void
route_fini(struct route_table *rt) {
	if (!rt)
		return;

	struct fib *fib = rt->default_route.fib;
	while (fib) {
		fib_delete(&rt->default_route, fib->metric);
		fib = fib->next;
	}
	rte_lpm_free(rt->lpm);
	rte_free(rt);
}
