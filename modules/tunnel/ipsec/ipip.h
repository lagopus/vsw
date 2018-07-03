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

#ifndef IPIP_H
#define IPIP_H

#include "l3.h"

/* outbound. */

static inline lagopus_result_t
ipip_outbound(struct rte_mbuf *m, uint32_t offset, bool is_ipv4,
              struct ip_addr *src, struct ip_addr *dst,
              uint8_t hop_limit, int8_t tos, void **outip) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct ip *inip4;
  uint8_t new_tos;

  if (likely((ret = set_meta_local(m)) ==
             LAGOPUS_RESULT_OK)) {
    /* inner. */
    inip4 = rte_pktmbuf_mtod(m, struct ip *);

    /* get TOS/TTL in packet or default vals. */
    new_tos = convert_ip_tos(inip4, tos);
    hop_limit = convert_ip_ttl(inip4, hop_limit);

    if (is_ipv4) {
      /* IPv4. */
      ret = encap_ip4(m, offset, IPPROTO_ESP, src, dst, new_tos,
                      inip4->ip_off, hop_limit, false);
    } else {
      /* IPv6. */
      ret = encap_ip6(m, offset, IPPROTO_ESP, src, dst, new_tos,
                      hop_limit);
    }

    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      lagopus_perror(ret);
      return ret;
    }
  } else {
    lagopus_perror(ret);
    return ret;
  }

  /* outer. */
  *outip = rte_pktmbuf_mtod(m, void *);

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
ip4ip_outbound(struct rte_mbuf *m, uint32_t offset,
               struct ip_addr *src, struct ip_addr *dst,
               uint8_t hop_limit, int8_t tos, struct ip **outip) {
  return ipip_outbound(m, offset, true, src, dst,
                       hop_limit, tos, (void **) outip);
}

static inline lagopus_result_t
ip6ip_outbound(struct rte_mbuf *m, uint32_t offset,
               struct ip_addr *src, struct ip_addr *dst,
               uint8_t hop_limit, int8_t tos, struct ip6_hdr **outip) {
  return ipip_outbound(m, offset, false, src, dst,
                       hop_limit, tos, (void **) outip);
}

/* inbound. */

static inline void
ip4_ecn_setup(struct ip *ip4) {
  if (ip4->ip_tos & IPTOS_ECN_MASK) {
    ip4->ip_tos |= IPTOS_ECN_CE;
  }
}

static inline void
ip6_ecn_setup(struct ip6_hdr *ip6) {
  if ((ntohl(ip6->ip6_flow) >> 20) & IPTOS_ECN_MASK) {
    ip6->ip6_flow = htonl(ntohl(ip6->ip6_flow) |
                          (IPTOS_ECN_CE << 20));
  }
}

static inline lagopus_result_t
ipip_inbound(struct rte_mbuf *m, uint32_t offset) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct ip *outip4, *inip4;
  struct ip6_hdr *outip6, *inip6;
  uint32_t set_ecn, ip_len;

  if (likely((ret = set_meta_local(m)) ==
             LAGOPUS_RESULT_OK)) {
    /* outer. */
    outip4 = rte_pktmbuf_mtod(m, struct ip *);

    if (outip4->ip_v == IPVERSION) {
      /* IPv4. */
      set_ecn = ((outip4->ip_tos & IPTOS_ECN_CE) == IPTOS_ECN_CE);
      ip_len = sizeof(struct ip);

      if (unlikely((ret = decap_ip4(m, offset, NULL)) !=
                   LAGOPUS_RESULT_OK)) {
        lagopus_perror(ret);
        return ret;
      }
    } else {
      /* IPv6. */
      outip6 = (struct ip6_hdr *) outip4;
      ip_len = sizeof(struct ip6_hdr);
      set_ecn = ntohl(outip6->ip6_flow) >> 20;
      set_ecn = ((set_ecn & IPTOS_ECN_CE) == IPTOS_ECN_CE);

      if (unlikely((ret = decap_ip6(m, offset, NULL)) !=
                   LAGOPUS_RESULT_OK)) {
        lagopus_perror(ret);
        return ret;
      }
    }

    /* inner. */
    inip4 = rte_pktmbuf_mtod(m, struct ip *);

    /* Check packet is still bigger than IP header (inner) */
    if (unlikely(rte_pktmbuf_pkt_len(m) <= ip_len)) {
      lagopus_msg_error("Bad packet length.\n");
      return LAGOPUS_RESULT_TOO_SHORT;
    }

    /* Check IP version. */
    if (unlikely(inip4->ip_v != IPVERSION && inip4->ip_v != IP6_VERSION)) {
      lagopus_msg_error("Bad IP version in packet.\n");
      return LAGOPUS_RESULT_OUT_OF_RANGE;
    }

    /* RFC4301 5.1.2.1 Note 6 */
    /* checksum recalculation is done in post process. */
    if (inip4->ip_v == IPVERSION) {
      if (set_ecn) {
        ip4_ecn_setup(inip4);
      }
    } else {
      if (set_ecn) {
        inip6 = (struct ip6_hdr *) inip4;
        ip6_ecn_setup(inip6);
      }
    }
  } else {
    lagopus_perror(ret);
    return ret;
  }

  return LAGOPUS_RESULT_OK;
}

#endif /* IPIP_H */
