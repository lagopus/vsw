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

#ifndef _LAGOPUS_MODULES_L2TUN_H
#define _LAGOPUS_MODULES_L2TUN_H

#include <stdint.h>
#include <stdlib.h>
#include <rte_ether.h>

#include "runtime.h"
#include "tunnel.h"

#define MAX_VID 4096

#define __UNUSED __attribute__((unused))

typedef enum {
  L2TUN_CMD_SET_ADDRESS_TYPE,
  L2TUN_CMD_SET_LOCAL_ADDR,
  L2TUN_CMD_SET_REMOTE_ADDRS,
  L2TUN_CMD_SET_HOP_LIMIT,
  L2TUN_CMD_SET_TOS,
  L2TUN_CMD_SET_TRUNK_MODE,
  L2TUN_CMD_SET_ACCESS_MODE,
  L2TUN_CMD_SET_VNI,
  L2TUN_CMD_SET_ENABLE,
  L2TUN_CMD_SET_DISABLE,

  // For VXLAN.
  L2TUN_CMD_FDB_LEARN,
  L2TUN_CMD_FDB_DEL,
  L2TUN_CMD_FDB_CLEAR,
  L2TUN_CMD_FDB_AGING,
} l2tun_cmd_t;

#define L2TUN_IFACE_METADATA_SIZE (512)
#define L2TUN_IFACE_METADATA(iface) ((void *) &((iface)->metadata))

struct l2tun_mbuf {
  uint32_t size;
  struct rte_mbuf *mbufs[MAX_PKT_BURST];
};

struct l2tun_vlan {
  uint16_t vid;
  vifindex_t index;
  struct rte_ring *output;
  struct l2tun_mbuf output_mbufs;
  struct tunnel_stats *stats; // TRUNK only
};

struct l2tun_vlan_entry {
  TAILQ_ENTRY(l2tun_vlan_entry) vlan_entries;
  struct l2tun_vlan *vlan;
};

TAILQ_HEAD(l2tun_vlan_head, l2tun_vlan_entry);

struct l2tun_vlan_list {
  size_t size;
  struct l2tun_vlan_head head;
};

typedef struct l2tun_vlan_list l2tun_vlan_list_t;

struct l2tun_iface {
  struct vsw_instance base;
  bool inbound;
  uint32_t inbound_core;
  uint32_t outbound_core;
  uint16_t address_type;
  struct ip_addr local_addr;
  struct ip_addrs remote_addrs;
  uint8_t hop_limit;
  uint8_t tos;
  uint16_t access_vid;
  uint16_t native_vid;
  struct l2tun_vlan *vlans[MAX_VID]; // vlan entry table(entry is the same as list)
  l2tun_vlan_list_t *vlan_list;      // vlan entry list(entry is the same as table)
  bool trunk;
  uint32_t vni;     // VXLAN only
  bool enabled;
  struct tunnel_stats *stats;

  // Free to use within each protocol.
  uint8_t metadata[L2TUN_IFACE_METADATA_SIZE];
};

#define L2TUN_CTRL_PARAM_METADATA_SIZE (512)
#define L2TUN_CTRL_PARAM_METADATA(param) ((void *) &((param)->metadata))

struct l2tun_iface_entry {
  TAILQ_ENTRY(l2tun_iface_entry) iface_entries;
  struct l2tun_iface *iface;
};

TAILQ_HEAD(l2tun_iface_head, l2tun_iface_entry);

struct l2tun_iface_list {
  size_t size;
  struct l2tun_iface_head head;
};

typedef struct l2tun_iface_list l2tun_iface_list_t;

struct l2tun_control_param {
  l2tun_cmd_t cmd;
  vifindex_t index;
  uint16_t address_type;
  struct ip_addr local_addr;
  struct ip_addrs remote_addrs;
  uint8_t hop_limit;
  uint8_t tos;
  uint16_t vid;
  struct rte_ring *inbound_output;
  struct rte_ring *outbound_output;
  bool trunk;
  uint32_t vni;
  struct tunnel_stats *inbound_stats;
  struct tunnel_stats *outbound_stats;

  // Free to use within each protocol.
  uint8_t metadata[L2TUN_CTRL_PARAM_METADATA_SIZE];
};

struct l2tun_runtime_param {
};

static inline void
l2tun_vlan_free(struct l2tun_vlan *vlan) {
  free(vlan->stats);
  free(vlan);
}

static inline l2tun_vlan_list_t *
l2tun_create_vlan_list(struct l2tun_iface *iface) {
  l2tun_vlan_list_t *vlan_list = NULL;
  if ((vlan_list = (l2tun_vlan_list_t *) calloc(1,
                   sizeof(l2tun_vlan_list_t))) == NULL) {
    return NULL;
  }
  TAILQ_INIT(&(vlan_list->head));
  vlan_list->size = 0;

  // set vlan list
  iface->vlan_list = vlan_list;

  return vlan_list;
}

static inline struct l2tun_vlan_entry *
l2tun_add_vlan_entry(struct l2tun_iface *iface, uint16_t vid) {
  l2tun_vlan_list_t *vlan_list = iface->vlan_list;
  struct l2tun_vlan_entry *vlan_entry = NULL;
  struct l2tun_vlan *vlan = NULL;

  // create VALN entry
  if ((vlan_entry = (struct l2tun_vlan_entry *) calloc(1,
                    sizeof(struct l2tun_vlan_entry))) == NULL) {
    return NULL;
  }

  // create VALN
  if ((vlan = (struct l2tun_vlan *) calloc(1,
              sizeof(struct l2tun_vlan))) == NULL) {
    free(vlan_entry);
    return NULL;
  }

  vlan->vid = vid;
  vlan_entry->vlan = vlan;

  TAILQ_INSERT_TAIL(&(vlan_list->head), vlan_entry, vlan_entries);
  vlan_list->size++;

  // add to VLAN array
  iface->vlans[vid] = vlan;

  return vlan_entry;
}

static inline void
l2tun_remove_vlan_entry(struct l2tun_iface *iface, uint16_t vid) {
  l2tun_vlan_list_t *vlan_list = iface->vlan_list;
  struct l2tun_vlan_entry *vlan_entry = TAILQ_FIRST(&(vlan_list->head));
  while (vlan_entry != NULL) {
    if (vlan_entry->vlan->vid == vid) {
      // remove from VLAN list
      TAILQ_REMOVE(&(vlan_list->head), vlan_entry, vlan_entries);
      vlan_list->size--;

      // remove from output mbuf array
      iface->vlans[vid] = NULL;

      // free VLAN
      l2tun_vlan_free(vlan_entry->vlan);

      // free VLAN entry
      free(vlan_entry);

      break;
    }
    vlan_entry = TAILQ_NEXT(vlan_entry, vlan_entries);
  }
}

static inline void
l2tun_free_vlan_list(struct l2tun_iface *iface) {
  l2tun_vlan_list_t *vlan_list = iface->vlan_list;
  struct l2tun_vlan_entry *vlan_entry = TAILQ_FIRST(&(vlan_list->head));
  while (vlan_entry != NULL) {
    // remove from VLAN list
    TAILQ_REMOVE(&(vlan_list->head), vlan_entry, vlan_entries);
    vlan_list->size--;

    // remove from output mbuf array
    iface->vlans[vlan_entry->vlan->vid] = NULL;

    // free VLAN
    l2tun_vlan_free(vlan_entry->vlan);

    // free VLAN entry
    free(vlan_entry);

    vlan_entry = TAILQ_NEXT(vlan_entry, vlan_entries);
  }
  RTE_ASSERT(vlan_list->size == 0);
  free(vlan_list);
}

static inline void
l2tun_iface_free(struct l2tun_iface *iface) {
  // free VLAN list
  l2tun_free_vlan_list(iface);

  free(iface->stats);

  // cast const to non const
  free((char *)iface->base.name);

  // iface is free on Go.
}

static inline l2tun_iface_list_t *
l2tun_create_iface_list() {
  l2tun_iface_list_t *iface_list = NULL;
  if ((iface_list = (l2tun_iface_list_t *) calloc(1,
                    sizeof(l2tun_iface_list_t))) == NULL) {
    return NULL;
  }
  TAILQ_INIT(&(iface_list->head));
  iface_list->size = 0;

  return iface_list;
}

static inline struct l2tun_iface_entry *
l2tun_add_iface_entry(l2tun_iface_list_t *iface_list,
                      struct l2tun_iface *iface) {
  struct l2tun_iface_entry *iface_entry = NULL;
  if ((iface_entry = (struct l2tun_iface_entry *) calloc(1,
                     sizeof(struct l2tun_iface_entry))) == NULL) {
    return NULL;
  }
  iface_entry->iface = iface;

  TAILQ_INSERT_TAIL(&(iface_list->head), iface_entry, iface_entries);
  iface_list->size++;

  return iface_entry;
}

static inline void
l2tun_remove_iface_entry(l2tun_iface_list_t *iface_list,
                         struct l2tun_iface *iface) {
  struct l2tun_iface_entry *iface_entry = TAILQ_FIRST(&(iface_list->head));
  while (iface_entry != NULL) {
    if (strcmp(iface_entry->iface->base.name, iface->base.name) == 0) {
      TAILQ_REMOVE(&(iface_list->head), iface_entry, iface_entries);
      iface_list->size--;

      // free iface
      l2tun_iface_free(iface_entry->iface);

      // free iface entry
      free(iface_entry);

      break;
    }
    iface_entry = TAILQ_NEXT(iface_entry, iface_entries);
  }
}

static inline void
l2tun_free_iface_list(l2tun_iface_list_t *iface_list) {
  struct l2tun_iface_entry *iface_entry = TAILQ_FIRST(&(iface_list->head));
  while (iface_entry != NULL) {
    // remove from iface list
    TAILQ_REMOVE(&(iface_list->head), iface_entry, iface_entries);
    iface_list->size--;

    // free iface
    l2tun_iface_free(iface_entry->iface);

    // free iface entry
    free(iface_entry);

    iface_entry = TAILQ_NEXT(iface_entry, iface_entries);
  }
  RTE_ASSERT(iface_list->size == 0);
  free(iface_list);
}

static inline void
l2tun_update_stats(struct l2tun_iface *iface, struct l2tun_vlan *vlan,
                   struct rte_mbuf *mbuf) {
  struct tunnel_mbuf_metadata *metadata = get_tunnel_mbuf_metadata(mbuf);

  // update dst ehter address type packet
  tunnel_update_ether_addr_type_pkts(iface->stats,
                                     metadata->inner_dst_ether_addr_type);
  tunnel_update_ether_addr_type_pkts(vlan->stats,
                                     metadata->inner_dst_ether_addr_type);

  // update inner packet bytes
  tunnel_update_inner_pkt_bytes(iface->stats, metadata->inner_pkt_bytes);
  tunnel_update_inner_pkt_bytes(vlan->stats, metadata->inner_pkt_bytes);

  // update inner vlan tagged packet bytes
  tunnel_update_inner_vlan_tagged_pkt_bytes(iface->stats,
      metadata->inner_vlan_tagged_pkt_bytes);
  tunnel_update_inner_vlan_tagged_pkt_bytes(vlan->stats,
      metadata->inner_vlan_tagged_pkt_bytes);
}

static inline void
l2tun_update_unknown_protos(struct l2tun_iface *iface) {
  tunnel_update_unknown_protos(iface->stats);
}

static inline void
l2tun_update_errors(struct l2tun_iface *iface) {
  tunnel_update_errors(iface->stats);
}

static inline void
l2tun_update_dropped(struct l2tun_iface *iface, struct l2tun_vlan *vlan,
                     struct rte_mbuf *mbuf) {
  struct tunnel_mbuf_metadata *metadata = get_tunnel_mbuf_metadata(mbuf);

  // update dropped
  tunnel_update_dropped(iface->stats);
  tunnel_update_dropped(vlan->stats);

  // update dropped ether address type
  tunnel_update_ether_addr_type_dropped(iface->stats,
                                        metadata->inner_dst_ether_addr_type);
  tunnel_update_ether_addr_type_dropped(vlan->stats,
                                        metadata->inner_dst_ether_addr_type);
}

static inline void
l2tun_update_if_trunk_counter(struct vsw_counter *to,
                              struct tunnel_stats *in_from,
                              struct tunnel_stats *out_from) {
  tunnel_update_counter(to, in_from, out_from);
  to->in_octets = in_from->inner_vlan_tagged_pkt_bytes;
  to->out_octets = out_from->inner_vlan_tagged_pkt_bytes;
}

static inline void
l2tun_update_vif_counter(struct vsw_counter *to,
                         struct tunnel_stats *in_from,
                         struct tunnel_stats *out_from) {
  tunnel_update_counter(to, in_from, out_from);
  // following errors are not counted in L2 VIF
  to->in_errors = 0;
  to->in_unknown_protos = 0;
  to->out_errors = 0;
}

#endif // _LAGOPUS_MODULES_L2TUN_H
