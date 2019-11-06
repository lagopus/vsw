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

#ifndef VSW_MODULES_ETHDEV_H_
#define VSW_MODULES_ETHDEV_H_

#include <stdint.h>
#include <stdlib.h>

#include <rte_ring.h>

#include "runtime.h"
#include "packet.h"
#include "counter.h"
#include "ether.h"

#define MAX_VID 4096

//
// For control
//
typedef enum {
	ETHDEV_CMD_ADD_VID,
	ETHDEV_CMD_DELETE_VID,
	ETHDEV_CMD_SET_TRUNK_MODE,
	ETHDEV_CMD_SET_ACCESS_MODE,
	ETHDEV_CMD_SET_NATIVE_VID,
	ETHDEV_CMD_SET_DST_SELF_FORWARD,
	ETHDEV_CMD_SET_DST_BC_FORWARD,
	ETHDEV_CMD_SET_DST_MC_FORWARD,
	ETHDEV_CMD_UPDATE_MAC,
} ethdev_cmd_t;

struct ethdev_control_param {
	ethdev_cmd_t cmd;
	int vid;
	vifindex_t index;
	struct rte_ring *output;
	struct vsw_counter *counter;
};

//
// ETHDEV Instances
//
struct ethdev_tx_instance;
struct ethdev_rx_instance;

struct ethdev_instance {
	struct vsw_instance base;
	struct rte_ring *o[MAX_VID];		// Internal buffers for output rings (connected to base.outputs)
	bool trunk;				// TRUNK port or not
	uint16_t port_id;			// Port ID of the ether device
	uint16_t vid;				// VID for NATIVE or ACCESS VLAN (-1 = disabled)
	vifindex_t index[MAX_VID];		// VID to VIF index
	struct vsw_counter *counter;		// Interface-level TX/RX counter
	struct vsw_counter *counters[MAX_VID];	// VIF-level TX/RX counter object

	void (*tx)(struct ethdev_tx_instance*, struct rte_mbuf**, int);
	void (*rx)(struct ethdev_rx_instance*, struct rte_mbuf**, int);
};

struct ethdev_tx_instance {
	struct ethdev_instance common;
	uint16_t nb_tx_desc;
	bool force_linearize;			// If true, multi-segment mbuf is linearized.

	struct ethdev_control_param param;	// Filled by Go, and referred by both Tx/Rx instance.

	// Filled by Runtime
	struct ethdev_runtime *r;
};

struct ethdev_rx_instance {
	struct ethdev_instance common;
	uint16_t nb_rx_desc;

	// Filled by Runtime
	struct ether_addr self_addr;		// MAC Address of the port
	struct rte_ring *fwd[MAX_VID];		// Output rings for forwarding packets
	vsw_ether_dst_t fwd_type[MAX_VID];	// Packet types to forward
};

struct ethdev_runtime_param {
	struct rte_mempool *pool;	// Mempool to use for RX
	bool iopl_required;		// Whether IOPL is required or not
};

// A length of input ring
#define ETHDEV_MBUF_LEN 1024	// XXX: Must be configurable

// Runtime OPs
extern struct vsw_runtime_ops ethdev_tx_runtime_ops;
extern struct vsw_runtime_ops ethdev_rx_runtime_ops;

#endif // VSW_MODULES_ETHDEV_H_
