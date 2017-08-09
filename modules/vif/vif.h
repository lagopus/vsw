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

#ifndef _LAGOPUS_MODULES_VIF_H
#define _LAGOPUS_MODULES_VIF_H

#include <stdint.h>
#include <stdlib.h>

#include "packet.h"

struct vif_task_param {
	void *req;	// DPDK Ring for Fronend -> Backend
};

typedef enum {
	VIF_CMD_START,	// Start TX/RX and packet processing
	VIF_CMD_STOP,	// Stop TX/RX and packet processing
	VIF_CMD_QUIT,	// Terminate backend
	VIF_CMD_NEW,	// Add a new VIF
	VIF_CMD_DELETE	// Delete a VIF
} vif_cmd_t;

struct vif_entity {
	char *name;			// Name of the interface
	vifindex_t vif;			// VIF index
	uint64_t vrf;			// VRF
	void *out_ring;			// DPDK Output ring
	void *in_ring;			// DPDK Input ring
	uint port_id;			// Port ID of the ether device
	uint rx_queue_id;		// RX queue ID
	uint tx_queue_id;		// TX queue ID
	struct ether_addr self_addr;	// MAC Address (filled by the backend)
	uint tx_count;			// TX packet counts
	uint tx_dropped;		// TX dropped packet counts
	uint rx_count;			// RX packet counts
	uint rx_dropped;		// RX dropped packet counts
};

struct vif_request {
	vif_cmd_t cmd;
	struct vif_entity *entity;
};

// A length of input ring
#define VIF_MBUF_LEN 512

// A max number of requests backend can submit at once
#define VIF_MAX_REQUESTS 8

// Backend task
extern int vif_do_task(void *arg);

#endif // _LAGOPUS_MODULES_VIF_H
