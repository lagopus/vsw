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

#ifndef IFACES_H
#define IFACES_H

#define IFACES_GET_ATTR(ifaces, index) ((ifaces)->attr[(index)])
#define IFACES_CURRENT(ifaces) (IFACES_GET_ATTR((ifaces), (ifaces)->current))
#define IFACES_MODIFIED(ifaces) (IFACES_GET_ATTR((ifaces), ((ifaces)->current + 1) % 2))

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

struct iface *
ifaces_alloc_array(size_t size);

void
ifaces_free_array(struct iface *iface_array);

#endif /* IFACES_H */
