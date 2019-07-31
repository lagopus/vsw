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

#ifndef VXLAN_METADATA_H
#define VXLAN_METADATA_H

#include "vxlan_includes.h"
#include "fdb.h"

/* metadata of mbuf.
 *          +---+----------------------+---------------------+---
 * rte_mbuf |...| tunnel_mbuf_metadata | vxlan_mbuf_metadata |...
 *          +---+----------------------+---------------------+---
 *              ^
 *              |
 *              vsw_packet_metadata.udata
 */

struct vxlan_mbuf_metadata {
  struct ether_hdr *inner_ether_hdr;
  struct ip *outer_ip;
  struct fdb_entry entry;
} __rte_cache_aligned;
TUNNEL_ASSERT(sizeof(struct tunnel_mbuf_metadata) +
              sizeof(struct vxlan_mbuf_metadata) <=
              PACKET_METADATA_SIZE);

static inline struct vxlan_mbuf_metadata *
get_priv(const struct rte_mbuf *m) {
  struct vsw_packet_metadata *lm = VSW_MBUF_METADATA(m);
  return (struct vxlan_mbuf_metadata *) ((void *) (lm->udata) +
         sizeof(struct tunnel_mbuf_metadata));
}

/* metadata of iface. */

#define VXLAN_IFACE_METADATA(iface)                                 \
  ((struct vxlan_iface_metadata *) L2TUN_IFACE_METADATA((iface)))

struct vxlan_traffic;

typedef lagopus_result_t
(*prepare_one_packet_proc_t)(struct rte_mbuf **);

struct vxlan_iface_metadata {
  struct fdb *fdb;
  prepare_one_packet_proc_t prepare_one_packet_proc;
};
TUNNEL_ASSERT(sizeof(struct vxlan_iface_metadata) <=
              L2TUN_IFACE_METADATA_SIZE);

/* metadata of control param. */

#define VXLAN_CTRL_PARAM_METADATA(param)                                \
  ((struct vxlan_ctrl_param_metadata *) L2TUN_CTRL_PARAM_METADATA((param)))

struct vxlan_ctrl_param_metadata {
  struct fdb_entry entry;
};
TUNNEL_ASSERT(sizeof(struct vxlan_ctrl_param_metadata) <=
              L2TUN_CTRL_PARAM_METADATA_SIZE);

#endif /* VXLAN_METADATA_H */
