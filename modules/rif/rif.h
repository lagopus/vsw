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

#ifndef _LAGOPUS_MODULES_RIF_H
#define _LAGOPUS_MODULES_RIF_H

#include <stdint.h>
#include <stdlib.h>

#include <rte_ring.h>
#include <rte_ether.h>

#include "runtime.h"
#include "packet.h"

#define MAX_VID 4096

typedef enum {
	RIF_FWD_TYPE_DEFAULT = 0x0,
	RIF_FWD_TYPE_SELF    = 0x1,
	RIF_FWD_TYPE_BC      = 0x2,
	RIF_FWD_TYPE_MC      = 0x4,
	RIF_FWD_TYPE_DROP    = 0x8,
} fwd_type_t;


// RIF Instance
struct rif_instance {
	struct lagopus_instance base;
	struct rte_ring *o[MAX_VID];	// Internal buffers for output rings (linked to base.outputs)
	bool trunk;
	int mtu;
	int vid;
	vifindex_t index[MAX_VID];
	struct ether_addr self_addr;

	// Filled by Runtime
	void (*proc)(struct rte_mempool*, struct rif_instance*, struct rte_mbuf**, int);

	struct rte_ring *fwd[MAX_VID];
	fwd_type_t fwd_type[MAX_VID];

	unsigned count;
	unsigned dropped;
};

// For Control
typedef enum {
	RIF_CMD_ADD_VID,
	RIF_CMD_DELETE_VID,
	RIF_CMD_SET_MTU,
	RIF_CMD_SET_MAC,
	RIF_CMD_SET_TRUNK_MODE,
	RIF_CMD_SET_ACCESS_MODE,
	RIF_CMD_SET_DST_SELF_FORWARD,
	RIF_CMD_SET_DST_BC_FORWARD,
	RIF_CMD_SET_DST_MC_FORWARD,
} rif_cmd_t;

struct rif_control_param {
        rif_cmd_t cmd;
        int vid;
	int mtu;
        vifindex_t index;
	struct rte_ring *output;
	struct ether_addr *mac;
};

// A length of input ring
#define RIF_MBUF_LEN 1024 // XXX: Must be configurable

// Runtime OPs
extern struct lagopus_runtime_ops rif_runtime_ops;

#endif // _LAGOPUS_MODULES_RIF_H
