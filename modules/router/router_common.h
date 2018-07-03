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
 *      @file   route_common.h
 *      @brief  Common to go and C..
 */

#ifndef __LAGOPUS_MODULE_ROUTER_ROUTER_COMMON_H__
#define __LAGOPUS_MODULE_ROUTER_ROUTER_COMMON_H__

#include <stdbool.h>
#include <stdint.h>
#include <net/if.h>
#include <netinet/in.h>

#include <rte_ether.h>

#include "runtime.h"
#include "packet.h"

#define MAX_ROUTERS		256
#define MAX_ROUTER_MBUFS	1024
#define MAX_ROUTER_VIFS		32

#define IPADDR_MAX_NUM 64

/* router command */
typedef enum {
	ROUTER_CMD_VIF_ADD,
	ROUTER_CMD_VIF_DELETE,
	ROUTER_CMD_VIF_ADD_IP,
	ROUTER_CMD_VIF_DELETE_IP,
	ROUTER_CMD_CREATE,
	ROUTER_CMD_DESTROY,
	ROUTER_CMD_ENABLE,
	ROUTER_CMD_DISABLE,
	ROUTER_CMD_CONFIG_RING_TAP,
	ROUTER_CMD_CONFIG_RING_HOSTIF,
	ROUTER_CMD_CONFIG_RING_IPIP,
	ROUTER_CMD_CONFIG_RING_ESP,
	ROUTER_CMD_CONFIG_RING_GRE,

	ROUTER_CMD_ROUTE_ADD,
	ROUTER_CMD_ROUTE_DELETE,
	ROUTER_CMD_ARP_ADD,
	ROUTER_CMD_ARP_DELETE,

	ROUTER_CMD_QUIT
} router_cmd_t;

/* route entry */
struct route_entry {
	uint32_t dst;     /* Destination address. */
	uint32_t gw;      /* Nexthop address. */
	uint32_t prefixlen;     /* Length of prefix. */
	uint32_t network;
	uint32_t ifindex;       /* Nexthop interface index. */
	uint32_t scope;         /* Scope of interface. */
	uint32_t metric;
	uint32_t bridgeid;
};

/* arp entry */
struct arp_entry {
	int ifindex;
	uint32_t ip;
	struct ether_addr mac;
	bool valid;
};

/* interface entry */
struct interface_entry {
	uint32_t ifindex;
	struct ether_addr mac;
	uint16_t vid;
	uint16_t mtu;
	bool     tunnel;
	bool     used;
	struct rte_ring *ring;
};

/* interface entry */
struct interface_addr_entry {
	uint32_t ifindex;
	uint32_t addr;
	uint32_t prefixlen;
};

/* interface info */
struct interface {
	uint32_t ifindex;
	struct   ether_addr mac;
	bool     tunnel;
	uint8_t  count; // number of valid addresses in addr[]
	uint16_t mtu;
	uint16_t vid;
	struct rte_ring *ring;
	struct interface_addr_entry addr[IPADDR_MAX_NUM];
};

/* use rings */
struct router_ring {
	struct rte_ring *tap;
	struct rte_ring *hostif;
	struct rte_ring *ipip;
	struct rte_ring *esp;
	struct rte_ring *gre;
};

/* router information */
struct router_information {
	router_cmd_t		cmd;
	uint64_t		vrfidx;
	struct router_ring	rings;
	struct route_entry	route;
	struct arp_entry	arp;
	struct interface_entry	vif;
	struct interface_addr_entry addr;
};

// Router Control
struct router_control_param {
	router_cmd_t	cmd;
	vifindex_t	index;
	struct rte_ring	*ring;
	struct router_information *info;
};

// structures
struct router_vif {
	vifindex_t	index;
	struct rte_ring *ring;
};

struct router_instance {
	struct lagopus_instance base;
	uint64_t	vrfidx;
	void		*notify;
	void		*pool;
	int		max_arp_entries;
	struct router_vif	vifs[MAX_ROUTER_VIFS];
	int			vif_count;
	struct router_context	*ctx;
};

struct router_runtime_param {
	struct rte_ring *notify;
	struct rte_mempool *pool;
};

extern struct lagopus_runtime_ops router_runtime_ops;


#endif /* __LAGOPUS_MODULE_ROUTER_ROUTER_COMMON_H__ */
