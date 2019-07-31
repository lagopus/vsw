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

#ifndef IFACES_H
#define IFACES_H

#define IFACES_GET_ATTR(ifaces, index) ((ifaces)->attr[(index)])
#define IFACES_CURRENT(ifaces) (IFACES_GET_ATTR((ifaces), (ifaces)->current))
#define IFACES_MODIFIED(ifaces) (IFACES_GET_ATTR((ifaces), ((ifaces)->current + 1) % 2))

typedef struct tunnel_stats iface_stats_t;

struct iface {
  TAILQ_ENTRY(iface) entry;
  vrfindex_t vrf_index;
  vifindex_t vif_index;
  struct rte_ring *input;
  struct rte_ring *output;
  uint8_t ttl;
  int8_t tos;
};

TAILQ_HEAD(iface_list, iface);

lagopus_result_t
ifaces_push_config(struct ifaces *ifaces,
                   struct iface *iface_array,
                   size_t num_iface_array);

lagopus_result_t
ifaces_get_stats(struct ifaces *ifaces,
                 vifindex_t vif_index,
                 iface_stats_t **stats);

struct iface *
ifaces_alloc_array(size_t size);

void
ifaces_free_array(struct iface *iface_array);

static inline void
iface_stats_update(iface_stats_t *stats, struct rte_mbuf *pkt) {
  struct tunnel_mbuf_metadata *metadata = get_tunnel_mbuf_metadata(pkt);

  /* update dst ehter address type packet. */
  tunnel_update_ether_addr_type_pkts(stats, ETHER_ADDR_TYPE_UNICAST);

  /* update inner packet bytes. */
  tunnel_update_inner_pkt_bytes(stats, metadata->inner_pkt_bytes);
}

static inline void
iface_stats_update_dropped(iface_stats_t *stats) {
  /* update dropped. */
  tunnel_update_dropped(stats);

  /* update dropped ether address type. */
  tunnel_update_ether_addr_type_dropped(stats, ETHER_ADDR_TYPE_UNICAST);
}

static inline void
iface_stats_update_unknown_protos(iface_stats_t *stats) {
  tunnel_update_unknown_protos(stats);
}

static inline void
iface_stats_update_errors(iface_stats_t *stats) {
  tunnel_update_errors(stats);
}

#endif /* IFACES_H */
