/*
 * Copyright 2019 Nippon Telegraph and Telephone Corporation.
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
#ifndef VSW_MODULE_ROUTER_REASSEMBLE_H_
#define VSW_MODULE_ROUTER_REASSEMBLE_H_

#include <stdbool.h>
#include <stdint.h>

#include <rte_hash.h>
#include <rte_ip_frag.h>
#include <rte_mbuf.h>

#include "packet.h"
#include "router_common.h"

// FRC791 IP
#define REASSEMBLE_AGING_TIME 15 // TODO: toml config

#define REASSEMBLE_MAX_ENTRIES 16 // TODO: toml config

// TODO: The buffer identifier defines dst, src, packet id and protocol.
//       However, DPDK does not use a protocol.
//       It is not used in this function.
struct reassemble_key {
	uint32_t dst;
	uint32_t src;
	uint16_t packet_id;
} __attribute__((__packed__));

void
reassemble_packet_process(struct router_instance *ri, struct rte_mbuf *mbuf);

bool
reassemble_packet_process_for_first_packet(struct router_instance *ri, struct rte_mbuf *mbuf);

bool
reassemble_init(struct router_instance *ri);

void
reassemble_fini(struct router_instance *ri);
#endif /* !VSW_MODULE_ROUTER_REASSEMBLE_H_ */

