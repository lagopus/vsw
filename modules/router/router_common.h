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
 *      @file   route_common.h
 *      @brief  Common to go and C..
 */

#ifndef VSW_MODULE_ROUTER_ROUTER_COMMON_H_
#define VSW_MODULE_ROUTER_ROUTER_COMMON_H_

#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include <rte_ether.h>
#include <rte_ip_frag.h>

#include "napt.h"
#include "packet.h"
#include "radix-tree.h"
#include "runtime.h"

#include "router_config.h"

#define IPV4_MASK(p) (0xFFFFFFFF << (32 - p))

/* router command */
typedef enum {
	ROUTER_CMD_VIF_ADD,	// struct interface_entry *
	ROUTER_CMD_VIF_DELETE,     // struct interface_entry *
	ROUTER_CMD_VIF_ADD_IP,     // struct interface_addr_entry *
	ROUTER_CMD_VIF_DELETE_IP,  // struct interface_addr_entry *
	ROUTER_CMD_VIF_UPDATE_MTU, // struct interface_entry *
	ROUTER_CMD_CONFIG_TAP,     // struct rte_ring *

	ROUTER_CMD_RULE_ADD,       // struct router_rule *
	ROUTER_CMD_RULE_DELETE,    // struct router_rule *

	ROUTER_CMD_ROUTE_ADD,      // struct route_entry *
	ROUTER_CMD_ROUTE_DELETE,   // struct route_entry *
	ROUTER_CMD_NEIGH_UPDATE,   // struct neighbor_entry *
	ROUTER_CMD_NEIGH_DELETE,   // struct neighbor_entry *
	ROUTER_CMD_PBRRULE_ADD,    // struct bpr_entry *
	ROUTER_CMD_PBRRULE_DELETE, // struct pbr_entry *

	ROUTER_CMD_NAPT_ENABLE,  // struct napt_config *
	ROUTER_CMD_NAPT_DISABLE, // vifindex_t *

	ROUTER_CMD_QUIT
} router_cmd_t;

typedef enum {
	ROUTER_ACTION_FORWARDING, // send packet to vif.
	ROUTER_ACTION_TO_KERNEL,  // send packet to tap module.
	ROUTER_ACTION_TO_HOSTIF,  // TODO: send packet to hostif module.
	ROUTER_ACTION_TO_IPIP,    // send packet to ipip module.
	ROUTER_ACTION_TO_ESP,     // send packet to esp module.
	ROUTER_ACTION_TO_GRE,     // send packet to gre module.
	ROUTER_ACTION_TO_VXLAN,   // send packeet to vxlan module.
	ROUTER_ACTION_DROP,       // drop the packet.
				  // use as a termination condition,
				  // don't move from last position.
	ROUTER_ACTION_NUM
} router_action_t;

typedef struct range {
	uint16_t from;
	uint16_t to;
} range_t;

/**
 * Five tuple rules.
 * TODO: prefix length, srcport, port range
 **/
struct rule {
	uint32_t dstip;
	uint32_t srcip;
	uint32_t vni;
	uint16_t dstport;
	vifindex_t in_vif;
	uint8_t proto;
};

/**
 *  * Nexthop information.
 *   */
typedef struct {
	uint32_t gw;
	uint32_t weight;
	vifindex_t ifindex;
	uint8_t netmask;
	struct interface *interface;
} nexthop_t;

// Interface type flags
typedef enum {
	IFF_TYPE_VIF	= 0,
	IFF_TYPE_TUNNEL = 1<<0,
	IFF_TYPE_VRF    = 1<<1,
	IFF_TYPE_TAP	= 1<<2,
} interface_flag_t;

struct neighbor;

/**
 * interface entry
 * for notification from frontend.
 **/
struct interface_entry {
	vifindex_t ifindex;
	uint16_t vid;
	uint16_t mtu;
	struct rte_ring *ring;
	interface_flag_t flags;
	struct ether_addr mac;

	// neighbor cache created by router backend
	struct neighbor *cache;
	size_t cache_size;

	struct router_ring *rr; // Used by router backend
};

static inline bool is_iff_type_tunnel(struct interface_entry *ie) {
	return (ie->flags & IFF_TYPE_TUNNEL);
}

static inline bool is_iff_type_vrf(struct interface_entry *ie) {
	return (ie->flags & IFF_TYPE_VRF);
}

static inline bool is_iff_type_tap(struct interface_entry *ie) {
	return (ie->flags & IFF_TYPE_TAP);
}

static inline bool is_iff_type_vif(struct interface_entry *ie) {
	return (ie->flags == IFF_TYPE_VIF);
}

/**
 * ip address of interface entry
 * for notification from frontend.
 **/
struct interface_addr_entry {
	vifindex_t ifindex;
	uint32_t addr;
	uint32_t prefixlen;
};

/**
 * interface info
 * use interface table.
 **/
struct interface {
	struct interface_entry base;

	uint8_t count; // number of valid addresses in addr[]
	struct napt *napt;
	struct interface_addr_entry addr[ROUTER_MAX_VIF_IPADDRS];

	struct neighbor_table *neighbor; // Neighbor cache for this interface

	uint32_t nexthop_num; // number of nexthop that refers the interface
	uint32_t nexthops_cap; // capacity of nexthop list
	nexthop_t **nexthops; // nexthop list
};

/**
 * route entry
 * for notification from frontend.
 **/
struct route_entry {
	uint32_t dst;       /* Destination address. */
	uint32_t prefixlen; /* Length of prefix. */
	uint32_t netmask;
	uint32_t scope;      /* Scope of interface. */
	uint32_t route_type; /* Kind of route(for check broadcast)*/
	uint32_t metric;
	uint32_t nexthop_num;
	nexthop_t *nexthops;
};

/**
 * Neighbor entry
 * use notification and neighbor table.
 **/
struct neighbor_entry {
	struct ether_addr mac;
	vifindex_t ifindex;
	uint32_t ip;
};

/**
 * Neighbor information.
 * used in neighbor cache.
 */
struct neighbor {
	struct ether_addr mac_addr; /**< MAC address */
	bool valid;		    /**< The cache is valid */
	bool used;		    /**< The cache has been referred */
	struct rte_mbuf *pending;   /**< Pending mbuf */
	uint32_t addr;		    /**< IPv4 address */
};

/**
 * PBR Nexthop Entry
 */
struct pbr_nexthop {
	uint32_t weight;
	uint32_t gw;
	vifindex_t out_vif;
	struct interface *interface;
};

/**
 * PBR entry
 */
struct pbr_entry {
	uint32_t src_addr;
	uint32_t dst_addr;

	uint32_t priority;
	vifindex_t in_vif;
	uint8_t src_mask;
	uint8_t dst_mask;

	range_t src_port;
	range_t dst_port;

	uint8_t protocol;
	bool pass;

	uint8_t nexthop_count;
};

struct pbr_entry_nh {
	struct pbr_entry base;

	struct pbr_nexthop nexthops[ROUTER_MAX_PBR_NEXTHOPS];
};

/**
 * router module's information
 * for notification from frontend.
 **/
struct router_rule {
	struct rule rule;
	struct rte_ring *ring;

	struct router_ring *rr; // Used by router backend
};

// Router Control Parameter
struct router_control_param {
	router_cmd_t cmd;
	void *info;
};

typedef enum {
	RECORDROUTE_DISABLE,
	RECORDROUTE_IGNORE,
	RECORDROUTE_ENABLE,
} rr_process_mode_t;

// Manage ring and mbufs to be sent
struct router_ring {
	struct rte_ring *ring;
	struct rte_mbuf *mbufs[ROUTER_MAX_MBUFS];
	unsigned count;
	uint64_t sent;
	uint64_t dropped;
	unsigned rc;
};

struct router_tables {
	struct route_table *route;
	struct nexthop_table *nexthop;
	struct interface_table *interface;
	struct pbr_table *pbr;
};

/**
 * Metadata for router module.
 **/
struct router_mbuf_metadata {
	uint32_t *rr_loc;
	uint32_t *sr_loc;
	struct router_ring *rr;		    // Temporary interface used by rules to return output ring.
	time_t reassemble_expire;
	uint32_t cksum_diff;		    // diff of IPv4 header checksum. SHALL be reflected after lookup().
	uint16_t mtu;			    // MTU (used to fragment locally originated packet)
	bool reassemble_packet;
	bool has_option;
	bool no_outbound_napt;		    // true if the packet's shouldn't be NAPTed during outbound.
} __rte_cache_aligned;

struct router_instance {
	struct vsw_instance base;

	struct interface_entry tap;

	struct router_rule *rules;
	int rules_count; // number of registered rule
	int rules_cap; // capacity of rule table

	// Tables managed by router
	struct router_tables tables;

	// Number of NAPT enabled VIF
	int napt_count;

	// to manage bulk transfer
	struct router_ring router_ring[ROUTER_MAX_VIFS + 1]; // +1 is for a tap
	struct router_ring *rrp[ROUTER_MAX_VIFS + 1];
	int rr_count;

	bool (*parse_options)(struct ipv4_hdr *, struct vsw_packet_metadata *,
			      struct interface_table *);

	struct rte_ip_frag_tbl *frag_tbl;       // for reassemble.
	struct rte_ip_frag_death_row death_row; // for reassemble.
	struct rte_hash *reassemble_hash;

	rr_process_mode_t rr_mode;
	vrfindex_t router_id;

	struct router_control_param control;
	union {
		struct interface_entry interface_entry;
		struct interface_addr_entry interface_addr_entry;
		struct router_rule router_rule;
		struct route_entry route_entry;
		struct pbr_entry pbr_entry;
		struct pbr_entry pbr_entry_nh;
		struct neighbor_entry neighbor_entry;
		struct napt_config napt_config;
	} p;
};

struct router_runtime_param {
	struct rte_mempool *pool;
};

extern struct vsw_runtime_ops router_runtime_ops;

#endif /* VSW_MODULE_ROUTER_ROUTER_COMMON_H_ */
