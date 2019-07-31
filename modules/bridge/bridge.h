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

#ifndef VSW_MODULES_BRIDGE_H_
#define VSW_MODULES_BRIDGE_H_

#include <stdbool.h>
#include <rte_ether.h>
#include <rte_ring.h>
#include <rte_hash.h>

#include "packet.h"
#include "runtime.h"

#define MAX_BRIDGE_DOMAINS 1024
#define MAX_BRIDGE_MBUFS 1024
#define MAX_BRIDGE_VIFS 32
#define MAX_BRIDGE_RIFS 32

//
// Bridge Instances (== Bridge Domain)
//
struct bridge_mac_entry {
	struct ether_addr mac;		// Destination MAC
	struct rte_ring	  *ring;	// Output ring for the MAC
};

struct bridge_vif {
	vifindex_t 	index;		// VIF Index
	struct rte_ring	*ring;		// Output ring for the VIF
};

struct bridge_instance {
	struct vsw_instance base;
	uint32_t		domain_id;

	// Filled by backend
	int			mtu;
	struct bridge_mac_entry rifs[MAX_BRIDGE_RIFS];
	int 			rif_count;
	struct bridge_vif	vifs[MAX_BRIDGE_VIFS];
	int 			vif_count;
	struct rte_hash		*mac_hash;	// MAC Hash returns DPDK Ring
	int			max_mac_entries;
	struct rte_ring		*mat;
};

//
// Bridge Control
//
typedef enum {
	BRIDGE_CMD_RIF_ADD,		// Add RIF to the bridge domain
	BRIDGE_CMD_RIF_DELETE,		// Delete RIF from the bridge domain

	BRIDGE_CMD_VIF_ADD,		// Add VIF to the bridge domain
	BRIDGE_CMD_VIF_DELETE,		// Delete VIF from the bridge domain

	BRIDGE_CMD_MAC_ADD,		// Add MAC entry to the bridge domain
	BRIDGE_CMD_MAC_DELETE,		// Delete MAC entry from the bridge domain

	BRIDGE_CMD_SET_MTU,		// Set MTU in the bridge domain

	BRIDGE_CMD_SET_MAX_ENTRIES,	// Set Max MAC Entries

	BRIDGE_CMD_SET_MAT,		// Set ring for MAT
} bridge_cmd_t;

struct bridge_control_param {
	bridge_cmd_t		cmd;
	struct ether_addr 	mac;			// Destination MAC
	vifindex_t 		index;			// VIF Index
	struct rte_ring	  	*ring;			// Output ring for the MAC or MAT
	int			mtu;			// New MTU
	int			max_mac_entries;	// Max MAC Entries
};

//
// Bridge Runtime
//
struct bridge_runtime_param {
	struct rte_ring *learn;	// Incoming MAC - from C to Go (struct bridge_learn)
	struct rte_ring *free;	// Returned buffer - from Go to C (struct bridge_learn)
};

struct bridge_learn {
	uint32_t	  domain_id;	// The bridge domain ID which VIF belongs to
	vifindex_t	  index;	// The Index of VIF who observed this MAC
	struct ether_addr mac;		// Observed MAC
};

extern struct vsw_runtime_ops bridge_runtime_ops;

#endif /* VSW_MODULES_BRIDGE_H_ */
