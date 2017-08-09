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

#ifndef _LAGOPUS_MODULES_BRIDGE_H
#define _LAGOPUS_MODULES_BRIDGE_H

#include <stdbool.h>
#include <rte_ether.h>
#include <rte_ring.h>
#include <rte_hash.h>

#include "packet.h"

struct bridge_launch_param {
	char *name;			// Name of this bridge backend
	void *request;			// Control requests - from Go to C (bridge_request)
	void *used;			// Incoming MAC - from C to Go (bridge_learn)
	void *free;			// Returned buffer - from Go to C (bridge_learn)
	struct rte_hash *bridge_hash;	// Bridge domain Hash to use
};

typedef enum {
	BRIDGE_CMD_DOMAIN_ADD,		// Add bridge domain
	BRIDGE_CMD_DOMAIN_DELETE,	// Delete brdige domain
	BRIDGE_CMD_DOMAIN_ENABLE,	// Enable the domain (Processing starts)
	BRIDGE_CMD_DOMAIN_DISABLE,	// Disable the domain (Processing stops)
	BRIDGE_CMD_DOMAIN_CONFIG,	// Update Domain Config

	BRIDGE_CMD_CONFIG_RING,		// Configure input/output rings

	BRIDGE_CMD_VIF_ADD,		// Add VIF to the bridge domain
	BRIDGE_CMD_VIF_DELETE,		// Delete VIF from the bridge domain

	BRIDGE_CMD_MAC_ADD,		// Add MAC entry to the bridge domain
	BRIDGE_CMD_MAC_DELETE,		// Delete MAC entry from the bridge domain

	BRIDGE_CMD_QUIT,

	BRIDGE_CMD_END
} bridge_cmd_t;

struct bridge_ring {
	struct rte_ring *input;		// default input
	struct rte_ring *vif_input;	// input from VIF
	struct rte_ring *output;	// default output
	struct rte_ring *tap;		// output for TAP
};

struct bridge_domain {
	char		   *name;	// Name of the bridge domain (limit: <= 24 chars)
	struct bridge_ring r;

	bool		   active;	// True if activated
	struct rte_hash    *vif_hash;	// VIF Hash returns DPDK Ring
	struct rte_hash    *mac_hash;	// MAC Hash returns DPDK Ring
};

struct bridge_config {
	uint32_t	max_mac_entry;	// Max MAC entries
};

struct bridge_vif {
	vifindex_t 	index;		// VIF Index
	hash_sig_t	hsig;		// TODO: Calculate Hash in Go
	struct rte_ring	*ring;		// Output ring for the VIF
};

struct bridge_mac_entry {
	struct ether_addr mac;		// Destination MAC (must be freed by the receiver)
	hash_sig_t	  hsig;		// TODO: Calculate Hash in Go
	struct rte_ring	  *ring;	// Output ring for the MAC
};

struct bridge_request {
	bridge_cmd_t		cmd;
	uint32_t		domain_id;
	hash_sig_t		domain_hsig;
	struct bridge_domain	*domain;
	struct bridge_config	config;
	struct bridge_ring	ring;
	struct bridge_vif	vif;
	struct bridge_mac_entry mac;
};

struct bridge_learn {
	uint32_t	  domain_id;	// The bridge domain ID which VIF belongs to
	vifindex_t	  index;	// The Index of VIF who observed this MAC
	struct ether_addr mac;		// Observed MAC
};

#define MAX_BRIDGE_DOMAINS 1024
#define MAX_BRIDGE_MBUFS 1024
#define MAX_BRIDGE_REQUESTS 256
#define MAX_BRIDGE_VIFS 32

// Directions of rings
#define	INBOUND 0
#define	OUTBOUND 1

extern uint32_t bridge_domain_hash_func(const void *key, uint32_t length, uint32_t initval);
extern uint32_t mac_entry_hash_func(const void *key, uint32_t length, uint32_t initval);
extern int bridge_task(void *arg);

#endif /* _LAGOPUS_MODULES_BRIDGE_H */
