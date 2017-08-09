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

#ifndef __LAGOPUS_MODULES_L3_H__
#define __LAGOPUS_MODULES_L3_H__

#include <stdbool.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include "packet.h"

// check packet header
#define VERSION_IPV4 0x04
#define VERSION_IPV6 0x06

struct l3_launch_param {
	uint64_t vrfrd;
	char *name;
	void *request;
};

struct l3_context {
	char *name;
	uint64_t vrfrd;
	struct vrf *vrf;
	struct rte_ring *input;
	struct rte_ring *output[VIF_MAX_INDEX];
	struct rte_ring *tap;
	struct rte_ring *hostif;
	struct rte_ring *notify_ring;
	bool active;

	struct route_table *route;
	struct arp_table *arp;
	struct interface_table *vif;
};

typedef enum {
	L3_CMD_CREATE,
	L3_CMD_DESTROY,
	L3_CMD_ENABLE,
	L3_CMD_DISABLE,
	L3_CMD_CONFIG_RING,

	L3_CMD_ROUTE_ADD,
	L3_CMD_ROUTE_DELETE,
	L3_CMD_ARP_ADD,
	L3_CMD_ARP_DELETE,
	L3_CMD_INTERFACE_ADD,
	L3_CMD_INTERFACE_DELETE,
	L3_CMD_INTERFACE_IP_ADD,
	L3_CMD_INTERFACE_IP_DELETE,
	L3_CMD_INTERFACE_HOSTIF_IP_ADD,
	L3_CMD_INTERFACE_HOSTIF_IP_DELETE,

	L3_CMD_QUIT
} l3_cmd_t;

struct l3_ring {
	struct rte_ring *input;
	struct rte_ring *output[VIF_MAX_INDEX];
	struct rte_ring *tap;
	struct rte_ring *hostif;
	struct rte_ring *notify_ring;

};

struct route_entry {
	struct in_addr dest;  /* Destination address. */
	struct in_addr gate;  /* Nexthop address. */
	uint32_t ifindex;          /* Nexthop interface index. */
	uint32_t prefixlen;        /* Length of prefix. */
	uint32_t scope;        /* Scope of interface. */
	uint32_t metric;
	uint32_t bridgeid;
};

struct arp_entry {
	uint32_t ifindex;
	struct in_addr ip;
	struct ether_addr *mac;
};

struct interface_entry {
	uint32_t ifindex;
	struct in_addr ip;
	struct in_addr broad;
	struct ether_addr *mac;
};

struct l3_request {
	l3_cmd_t		cmd;
	uint64_t		vrfrd;
	struct l3_ring		ring;
	struct route_entry	route;
	struct arp_entry	arp;
	struct interface_entry	vif;
};

#define MAX_L3_INSTANCES 1024
#define MAX_L3_REQUESTS 1024
#define MAX_L3_MBUFS 1024

extern int l3_task(void *arg);
extern int l3_start(void *arg);
extern int test_set_tables();


/** for packet handling **/

/* netlink? */
#define SCOPE_LINK 253  //RT_SCOPE_LINK



#endif /* __LAGOPUS_MODULES_L3_H__ */
