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

#ifndef __L3_H__
#define __L3_H__

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <rte_ip.h>
#include <rte_mbuf.h>

#include "lagopus_types.h"
#include "lagopus_error.h"
#include "logger.h"
#include "tunnel.h"
#include "ip_id.h"

#define IP6_ADDR_LEN (16)

#define IP_OFF_FULL_MASK (IP_DF | IP_MF | IP_OFFMASK)
#define IS_ATOMIC(_offset) (((_offset) & IP_OFF_FULL_MASK) == IP_DF)

static inline lagopus_result_t
fill_ip_id(struct ip *ip) {
  if (ip == NULL) {
    lagopus_printf("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  /* RFC6864 section 4. */
  if (IS_ATOMIC(ntohs(ip->ip_off))) {
    ip->ip_id = 0;
  } else {
    ip->ip_id = htons(ip_generate_id());
  }

  return LAGOPUS_RESULT_OK;
}

static inline uint8_t
convert_ip_tos(struct ip *ip, int8_t tos)
{
  if (likely(tos >= 0 && tos <= 63)) {
    // ECT fill zero.
    return (uint8_t) tos << 2;
  } else {
    if (ip->ip_v == IPVERSION) {
      return ip->ip_tos;
    } else {
      struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *) ip;
      return ntohl(ipv6_hdr->ip6_flow) >> 20;
    }
  }
}

static inline uint8_t
convert_ip_ttl(struct ip *ip, uint8_t hop_limit)
{
  if (likely(hop_limit == 0)) {
    if (ip->ip_v == IPVERSION) {
      return ip->ip_ttl;
    } else {
      struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *) ip;
      return ipv6_hdr->ip6_hops;
    }
  } else {
    return hop_limit;
  }
}

/**
 * Encap IPv4 header.
 *
 * @param[in] m mbuf.
 * @param[in] offset
 * @param[in] proto
 * @param[in] src
 * @param[in] dst
 * @param[in] tos
 * @param[in] off
 * @param[in] ttl
 * @param[in] is_calc_cksum
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 */
static inline lagopus_result_t
encap_ip4(struct rte_mbuf *m, uint32_t offset, uint8_t proto,
          struct ip_addr *src, struct ip_addr *dst, uint8_t tos,
          uint16_t off, uint8_t ttl, bool is_calc_cksum)
{
  struct ip *out_ip4;

  if (m == NULL) {
    lagopus_printf("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  offset += sizeof(struct ip);
  out_ip4 = (struct ip *) rte_pktmbuf_prepend(m, offset);
  if (out_ip4 == NULL) {
    lagopus_printf("rte_pktmbuf_prepend failed");
    return LAGOPUS_RESULT_NO_MEMORY;
  }

  out_ip4->ip_v = IPVERSION;
  out_ip4->ip_hl = 5;
  out_ip4->ip_tos = tos;
  out_ip4->ip_len = htons(rte_pktmbuf_data_len(m));
  out_ip4->ip_id = 0;
  out_ip4->ip_off = off & htons(IP_DF);
  out_ip4->ip_ttl = ttl;
  out_ip4->ip_p = proto;
  out_ip4->ip_src.s_addr = src->ip.ip4;
  out_ip4->ip_dst.s_addr = dst->ip.ip4;

  fill_ip_id(out_ip4);

  if (is_calc_cksum == true) {
    struct ipv4_hdr *out_ip4_hdr = (struct ipv4_hdr *) out_ip4;
    out_ip4_hdr->hdr_checksum = 0;
    out_ip4_hdr->hdr_checksum = rte_ipv4_cksum(out_ip4_hdr);
  }

  return LAGOPUS_RESULT_OK;
}

/**
 * Decap IPv4 header.
 *
 * @param[in] m mbuf.
 * @param[in] offset header offset.(in bytes, zero allowed.)
 * @param[out] A pointer to a IPv4 header returns.(NULL allowed.)
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 *
 * @details the *out is mbuf pointer, attention is required when operating.
 *
 * @details inner ECN field is not updated.
 */
static inline lagopus_result_t
decap_ip4(struct rte_mbuf *m, uint32_t offset, struct ipv4_hdr **out)
{
  char *next;
  uint32_t hdr_len;
  struct ipv4_hdr *ipv4_hdr;

  if (m == NULL) {
    lagopus_printf("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  ipv4_hdr = rte_pktmbuf_mtod(m, struct ipv4_hdr*);
  if (ipv4_hdr == NULL) {
    lagopus_printf("rte_pktmbuf_mtod failed");
    return LAGOPUS_RESULT_ANY_FAILURES;
  }

  hdr_len = sizeof(struct ipv4_hdr);
  next = rte_pktmbuf_adj(m, offset + hdr_len);
  if (next == NULL) {
    lagopus_printf("rte_pktmbuf_adj failed");
    return LAGOPUS_RESULT_ANY_FAILURES;
  }

  if (out != NULL) {
    *out = ipv4_hdr;
  }

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
encap_ip6(struct rte_mbuf *m, uint32_t offset, uint8_t proto,
          struct ip_addr *src, struct ip_addr *dst,
          uint8_t tos, uint8_t hop_limit)
{
  struct ip6_hdr *out_ip6;

  if (m == NULL) {
    lagopus_printf("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  offset += sizeof(struct ip6_hdr);
  out_ip6 = (struct ip6_hdr *) rte_pktmbuf_prepend(m, offset);
  if (out_ip6 == NULL) {
    lagopus_printf("rte_pktmbuf_prepend failed");
    return LAGOPUS_RESULT_NO_MEMORY;
  }

  out_ip6->ip6_flow = htonl(IP6_VERSION << 28 | tos << 20);
  out_ip6->ip6_plen = htons(rte_pktmbuf_data_len(m) - sizeof(struct ip6_hdr));
  out_ip6->ip6_nxt = proto;
  out_ip6->ip6_hops = hop_limit;
  memcpy(&out_ip6->ip6_src.s6_addr, src, IP6_ADDR_LEN);
  memcpy(&out_ip6->ip6_dst.s6_addr, dst, IP6_ADDR_LEN);

  return LAGOPUS_RESULT_OK;
}

/**
 * Decap IPv6 header.
 *
 * @param[in] m mbuf.
 * @param[in] offset header offset.(in bytes, zero allowed.)
 * @param[out] A pointer to a IPv6 header returns.(NULL allowed.)
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 *
 * @details the *out is mbuf pointer, attention is required when operating.
 *
 * @details inner ECN field is not updated.
 */
static inline lagopus_result_t
decap_ip6(struct rte_mbuf *m, uint32_t offset, struct ipv6_hdr **out)
{
  char *next;
  uint32_t hdr_len;
  struct ipv6_hdr *ipv6_hdr;

  if (m == NULL) {
    lagopus_printf("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  ipv6_hdr = rte_pktmbuf_mtod(m, struct ipv6_hdr*);
  if (ipv6_hdr == NULL) {
    lagopus_printf("rte_pktmbuf_mtod failed");
    return LAGOPUS_RESULT_ANY_FAILURES;
  }

  hdr_len = sizeof(struct ipv6_hdr);
  next = rte_pktmbuf_adj(m, offset + hdr_len);
  if (next == NULL) {
    lagopus_printf("rte_pktmbuf_adj failed");
    return LAGOPUS_RESULT_ANY_FAILURES;
  }

  if (out != NULL) {
    *out = ipv6_hdr;
  }

  return LAGOPUS_RESULT_OK;
}

#endif /* __L3_H__ */
