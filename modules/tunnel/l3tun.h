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

#ifndef _LAGOPUS_MODULES_L3TUN_H
#define _LAGOPUS_MODULES_L3TUN_H

#include <stdint.h>
#include <stdlib.h>
#include <rte_ether.h>

#include "runtime.h"
#include "tunnel.h"

#define __UNUSED __attribute__((unused))

typedef enum {
  L3TUN_CMD_SET_ADDRESS_TYPE,
  L3TUN_CMD_SET_LOCAL_ADDR,
  L3TUN_CMD_SET_REMOTE_ADDR,
  L3TUN_CMD_SET_HOP_LIMIT,
  L3TUN_CMD_SET_TOS,
  L3TUN_CMD_SET_ENABLE,
  L3TUN_CMD_SET_DISABLE,
} l3tun_cmd_t;

struct l3tun_iface {
  struct vsw_instance base;
  uint16_t address_type;
  struct ip_addr local_addr;
  struct ip_addr remote_addr;
  uint8_t hop_limit;
  int8_t tos;
  struct rte_ring *inbound_output;
  struct rte_ring *outbound_output;
  bool enabled;
  struct tunnel_stats *stats;
};

struct l3tun_iface_entry {
  TAILQ_ENTRY(l3tun_iface_entry) iface_entries;
  struct l3tun_iface *iface;
};

TAILQ_HEAD(l3tun_iface_head, l3tun_iface_entry);

struct l3tun_iface_list {
  size_t size;
  struct l3tun_iface_head head;
};

typedef struct l3tun_iface_list l3tun_iface_list_t;

struct l3tun_control_param {
  l3tun_cmd_t cmd;
  uint16_t address_type;
  struct ip_addr local_addr;
  struct ip_addr remote_addr;
  uint8_t hop_limit;
  int8_t tos;
  struct rte_ring *inbound_output;
  struct rte_ring *outbound_output;
  struct tunnel_stats *stats;
};

struct l3tun_runtime_param {
};

static inline void
l3tun_iface_free(struct l3tun_iface *iface) {
  free(iface->stats);

  // cast const to non const
  free((char *)iface->base.name);

  // iface is free on Go.
}

static inline l3tun_iface_list_t *
l3tun_create_iface_list() {
  l3tun_iface_list_t *iface_list = NULL;
  if ((iface_list = (l3tun_iface_list_t *) calloc(1,
                    sizeof(l3tun_iface_list_t))) == NULL) {
    return NULL;
  }
  TAILQ_INIT(&(iface_list->head));
  iface_list->size = 0;

  return iface_list;
}

static inline struct l3tun_iface_entry *
l3tun_add_iface_entry(l3tun_iface_list_t *iface_list,
                      struct l3tun_iface *iface) {
  struct l3tun_iface_entry *iface_entry = NULL;
  if ((iface_entry = (struct l3tun_iface_entry *) calloc(1,
                     sizeof(struct l3tun_iface_entry))) == NULL) {
    return NULL;
  }
  iface_entry->iface = iface;

  TAILQ_INSERT_TAIL(&(iface_list->head), iface_entry, iface_entries);
  iface_list->size++;

  return iface_entry;
}

static inline void
l3tun_remove_iface_entry(l3tun_iface_list_t *iface_list,
                         struct l3tun_iface *iface) {
  struct l3tun_iface_entry *iface_entry = TAILQ_FIRST(&(iface_list->head));
  while (iface_entry != NULL) {
    if (strcmp(iface_entry->iface->base.name, iface->base.name) == 0) {
      TAILQ_REMOVE(&(iface_list->head), iface_entry, iface_entries);
      iface_list->size--;

      // free iface
      l3tun_iface_free(iface_entry->iface);

      // free iface entry
      free(iface_entry);

      break;
    }
    iface_entry = TAILQ_NEXT(iface_entry, iface_entries);
  }
}

static inline void
l3tun_free_iface_list(l3tun_iface_list_t *iface_list) {
  struct l3tun_iface_entry *iface_entry = TAILQ_FIRST(&(iface_list->head));
  while (iface_entry != NULL) {
    // remove from iface list
    TAILQ_REMOVE(&(iface_list->head), iface_entry, iface_entries);
    iface_list->size--;

    // free iface
    l3tun_iface_free(iface_entry->iface);

    // free iface entry
    free(iface_entry);

    iface_entry = TAILQ_NEXT(iface_entry, iface_entries);
  }
  RTE_ASSERT(iface_list->size == 0);
  free(iface_list);
}

static inline void
l3tun_update_stats(struct l3tun_iface *iface, struct rte_mbuf *mbuf) {
  struct tunnel_mbuf_metadata *metadata = get_tunnel_mbuf_metadata(mbuf);

  // update dst ehter address type packet
  tunnel_update_ether_addr_type_pkts(iface->stats, ETHER_ADDR_TYPE_UNICAST);

  // update inner packet bytes
  tunnel_update_inner_pkt_bytes(iface->stats, metadata->inner_pkt_bytes);
}

static inline void
l3tun_update_unknown_protos(struct l3tun_iface *iface) {
  tunnel_update_unknown_protos(iface->stats);
}

static inline void
l3tun_update_errors(struct l3tun_iface *iface) {
  tunnel_update_errors(iface->stats);
}

static inline void
l3tun_update_dropped(struct l3tun_iface *iface) {
  // update dropped
  tunnel_update_dropped(iface->stats);

  // update dropped ether address type
  tunnel_update_ether_addr_type_dropped(iface->stats, ETHER_ADDR_TYPE_UNICAST);
}

#endif // _LAGOPUS_MODULES_L3TUN_H
