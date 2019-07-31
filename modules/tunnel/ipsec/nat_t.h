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

#ifndef NAT_T_H
#define NAT_T_H

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "udp.h"

#define NAT_T_NON_ESP_MARKER (0x0ULL)
#define NAT_T_KEEPALIVE (0xff)
#define NAT_T_KEEPALIVE_LEN (1)

static inline uint16_t
nat_t_get_payload_len(struct rte_mbuf *m,
                      uint8_t proto,
                      uint16_t off) {
  struct udp_hdr *udp;

  if (proto == IPPROTO_UDP) {
    /* UDP. */
    udp = rte_pktmbuf_mtod_offset(m, struct udp_hdr *, off);
    return ntohs(udp->dgram_len) - sizeof(struct udp_hdr);
  }

  return 0;
}

static inline uint16_t
nat_t_get_len_by_proto(uint8_t proto) {
  if (proto == IPPROTO_UDP) {
    /* UDP. */
    return sizeof(struct udp_hdr);
  }
  return 0;
}

static inline uint16_t
nat_t_get_len_by_sa(struct ipsec_sa *sa) {
  return nat_t_get_len_by_proto(sa->encap_proto);
}

static inline uint16_t
nat_t_get_len_by_ip(struct ip *ip) {
  return nat_t_get_len_by_proto(ip->ip_p);
}

static inline bool
nat_t_is_ike_pkt(struct rte_mbuf *m,
                 uint8_t proto,
                 uint16_t off) {
  uint8_t *payload8;
  uint32_t *payload32;
  uint16_t payload_len;
  uint16_t nat_t_len;

  nat_t_len = nat_t_get_len_by_proto(proto);

  if (nat_t_len != 0) {
    payload_len = nat_t_get_payload_len(m, proto, off);
    payload8 = rte_pktmbuf_mtod_offset(m, uint8_t *,
                                       off + nat_t_len);
    payload32 = (uint32_t *) payload8;

    if (unlikely(((*payload8 == NAT_T_KEEPALIVE &&
                   payload_len == NAT_T_KEEPALIVE_LEN) ||
                  (*payload32 == NAT_T_NON_ESP_MARKER)))) {
      /* NOTE: Not frequent. */
      return true;
    }
  }

  return false;
}

static inline lagopus_result_t
encap_nat_t(struct rte_mbuf *m, struct ipsec_sa *sa) {
  if (likely(sa->encap_proto == IPPROTO_UDP)) {
    return encap_udp(m, sa->encap_src_port, sa->encap_dst_port, NULL);
  }

  TUNNEL_ERROR("Unsupported NAT-T protocol: %"PRIu8,
               sa->encap_proto);
  return LAGOPUS_RESULT_UNKNOWN_PROTO;
}

static inline lagopus_result_t
decap_nat_t(struct rte_mbuf *m, struct ipsec_sa *sa,
            uint8_t upper_proto) {
  if (likely(sa->encap_proto == upper_proto)) {
    return decap_udp(m, NULL,
                     0 /* ether_type is 0, because disable cal checksum */,
                     false, NULL);
  }

  TUNNEL_ERROR("Unsupported NAT-T protocol: "
               "config proto = %"PRIu8", packet proto = %"PRIu8,
               sa->encap_proto, upper_proto);
  return LAGOPUS_RESULT_UNKNOWN_PROTO;
}

#endif /* NAT_T_H */
