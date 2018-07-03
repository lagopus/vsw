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

#ifndef _LAGOPUS_MODULES_IPIP_H
#define _LAGOPUS_MODULES_IPIP_H

#include <stdint.h>
#include <stdlib.h>
#include <rte_ether.h>

#include "runtime.h"
#include "tunnel.h"
#include "l2.h"
#include "l3.h"

#define IPIP_MODULE_NAME "ipip"
#define MAX_TUNNELS 2048

typedef enum {
  IPIP_CMD_SET_ADDRESS_TYPE,
  IPIP_CMD_SET_LOCAL_ADDR,
  IPIP_CMD_SET_REMOTE_ADDR,
  IPIP_CMD_SET_HOP_LIMIT,
  IPIP_CMD_SET_TOS,
  IPIP_CMD_SET_OUTPUT,
  IPIP_CMD_SET_ENABLE,
  IPIP_CMD_SET_ALL,
} ipip_cmd_t;

struct ipip_iface {
  struct lagopus_instance base;
  uint16_t index;
  uint16_t address_type;
  struct ip_addr local_addr;
  struct ip_addr remote_addr;
  uint8_t hop_limit;
  int8_t tos;
  struct rte_ring *output;
  bool enable;

  // Filled by Runtime
  uint64_t rx_packets;
  uint64_t tx_packets;
  uint64_t errors;
  uint64_t dropped;
};

struct ipip_control_param {
  ipip_cmd_t cmd;
  uint16_t address_type;
  struct ip_addr local_addr;
  struct ip_addr remote_addr;
  uint8_t hop_limit;
  int8_t tos;
  struct rte_ring *output;
  bool enable;
};

struct ipip_runtime_param {
};

extern struct lagopus_runtime_ops ipip_inbound_runtime_ops;
extern struct lagopus_runtime_ops ipip_outbound_runtime_ops;

#endif // _LAGOPUS_MODULES_IPIP_H
