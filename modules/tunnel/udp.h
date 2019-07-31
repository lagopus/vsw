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

/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef UDP_H
#define UDP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "lagopus_types.h"
#include "lagopus_error.h"
#include "tunnel.h"
#include "hash.h"

/*
 * UDP.
 */

/**
 * Insert checksum for TCP/UDP.
 *
 * @param[in] ether_type  ether type (big-endian).
 * @param[in] l3_hdr      A pointer to a L3 header.
 * @param[in] l4_hdr      A pointer to a L4 header.
 *
 * @retval checksum.
 */
static inline uint16_t
udptcp_cal_checksum(uint16_t ether_type, void *l3_hdr, void *l4_hdr) {
  if (ether_type == ETHER_TYPE_IPv4_BE) {
    // IPv4.
    return rte_ipv4_udptcp_cksum((const struct ipv4_hdr *) l3_hdr,
                                 (const void *) l4_hdr);
  } else {
    // IPv6.
    return rte_ipv6_udptcp_cksum((const struct ipv6_hdr *) l3_hdr,
                                 (const void *) l4_hdr);
  }
}

/**
 * Valid checksum for UDP.
 *
 * @param[in] ether_type  ether type (big-endian).
 * @param[in] l3_hdr      A pointer to a L3 header.
 * @param[in] udp_hdr     A pointer to a L4 header.
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_OBJECT Failed, bad checksum.
 */
static inline lagopus_result_t
udp_valid_checksum(uint16_t ether_type, void *l3_hdr, void *l4_hdr) {
  if (unlikely(udptcp_cal_checksum(ether_type, l3_hdr, l4_hdr) != 0xffff)) {
    TUNNEL_ERROR("Bad checksum.");
    return LAGOPUS_RESULT_INVALID_OBJECT;
  }
  return LAGOPUS_RESULT_OK;
}

/**
 * Generate UDP src port for VXLAN.
 *
 * @param[in] ether_hdr   A pointer to a Ether header.
 * @param[in] min         Min of port.
 * @param[in] max         MAx of port.
 *
 * @retval src port.
 */
static inline uint16_t
udp_gen_src_port(struct ether_hdr *ether_hdr,
                 uint16_t min, uint16_t max) {
  uint32_t hash;
  int range;

  range = (int) (max - min + 1);
  hash = hash_fnv1a32_with_size((void *) ether_hdr, 2 * ETHER_ADDR_LEN);
  hash ^= hash >> 16;
  return (min + (hash % range));
}

/**
 * Insert checksum for UDP.
 *
 * @param[in] udp_hdr     A pointer to a UDP header.
 * @param[in] l3_hdr      A pointer to a L3 header.
 * @param[in] ether_type  ether type (big-endian).
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 */
static inline lagopus_result_t
udp_insert_checksum(struct udp_hdr *udp_hdr, void *l3_hdr,
                    uint16_t ether_type) {
  struct ip *ip;

  if (unlikely(udp_hdr == NULL || l3_hdr == NULL)) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  if (ether_type == ETHER_TYPE_IPv4_BE) {
    ip = (struct ip *) l3_hdr;
    ip->ip_sum = 0;
  }
  udp_hdr->dgram_cksum = 0;
  udp_hdr->dgram_cksum = udptcp_cal_checksum(ether_type, l3_hdr,
                         (void *) udp_hdr);

  return LAGOPUS_RESULT_OK;
}

/**
 * Encap UDP header.
 *
 * @note Need calculate checksum at post process.
 *
 * @param[in] m      mbuf.
 * @param[in] src_port  src port.
 * @param[in] dst_port  dst port.
 * @param[out] out_udp_hdr  A pointer to a outer UDP header returns. (NULL allowed)
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_NO_MEMORY Failed.
 */
static inline lagopus_result_t
encap_udp(struct rte_mbuf *m, uint16_t src_port, uint16_t dst_port,
          struct udp_hdr **out_udp_hdr) {
  struct udp_hdr *udp_hdr;

  if (unlikely(m == NULL)) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  udp_hdr = (struct udp_hdr *) rte_pktmbuf_prepend(m, sizeof(struct udp_hdr));
  if (unlikely(udp_hdr == NULL)) {
    TUNNEL_ERROR("rte_pktmbuf_prepend failed");
    return LAGOPUS_RESULT_NO_MEMORY;
  }

  udp_hdr->src_port = htons(src_port);
  udp_hdr->dst_port = htons(dst_port);
  udp_hdr->dgram_len = htons(m->pkt_len);

  /* NOTE: Need calculate checksum at post process. */

  if (out_udp_hdr != NULL) {
    *out_udp_hdr = udp_hdr;
  }

  return LAGOPUS_RESULT_OK;
}

/**
 * Decap UDP header.
 *
 * @param[in]  m            mbuf.
 * @param[in]  l3           A pointer to a L3 header.
 *                          Use calculate checksum. (NULL allowed)
 * @param[in]  ether_type   ether type (big-endian).
 * @param[in]  is_cal_cksum Enable calculate checksum.
 * @param[out] out_udp_hdr  A pointer to a outer UDP header returns. (NULL allowed)
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_INVALID_OBJECT Failed.
 * @retval LAGOPUS_RESULT_TOO_SHORT Failed.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 */
static inline lagopus_result_t
decap_udp(struct rte_mbuf *m, void *l3,
          uint16_t ether_type, bool is_cal_cksum,
          struct udp_hdr **out_udp_hdr) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct udp_hdr *udp_hdr;

  if (unlikely(m == NULL)) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  if (unlikely(m->pkt_len < sizeof(struct udp_hdr))) {
    TUNNEL_ERROR("Bad packet length");
    return LAGOPUS_RESULT_TOO_SHORT;
  }

  /* outer. */
  udp_hdr = rte_pktmbuf_mtod(m, struct udp_hdr *);

  /* check checksum. */
  if (is_cal_cksum) {
    if (likely(l3 != NULL)) {
      ret = udp_valid_checksum(ether_type, l3, (void *) udp_hdr);
      if (unlikely((ret != LAGOPUS_RESULT_OK))) {
        TUNNEL_ERROR("Bad checksum: %d", ret);
        return ret;
      }
    } else {
      return LAGOPUS_RESULT_INVALID_OBJECT;
    }
  }

  /* inner. */
  if (unlikely(rte_pktmbuf_adj(m, sizeof(struct udp_hdr)) == NULL)) {
    TUNNEL_ERROR("rte_pktmbuf_adj failed");
    return LAGOPUS_RESULT_ANY_FAILURES;
  }

  if (out_udp_hdr != NULL) {
    *out_udp_hdr = udp_hdr;
  }

  return LAGOPUS_RESULT_OK;
}

#endif // UDP_H
