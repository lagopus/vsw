/*
 * Copyright 2018-2019 Nippon Telegraph and Telephone Corporation.
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

#ifndef ESP_H
#define ESP_H

#include "ifaces.h"

uint16_t
ipsec_esp_inbound(const pthread_t tid, struct sa_ctx *sad,
                  struct rte_mbuf *pkts[],
                  size_t nb_pkts, const lagopus_chrono_t now,
                  uint16_t len, iface_stats_t *stats);

uint16_t
ipsec_esp_outbound(const pthread_t tid, struct sa_ctx *sad,
                   struct rte_mbuf *pkts[],
                   uint32_t sa_idx[],
                   size_t nb_pkts, const lagopus_chrono_t now,
                   uint16_t len, iface_stats_t *stats);

#endif /* ESP_H */
