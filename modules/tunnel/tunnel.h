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

#ifndef __TUNNEL_H__
#define __TUNNEL_H__

#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <time.h>

#include "counter.h"
#include "lagopus_types.h"
#include "lagopus_error.h"
#include "logger.h"
#include "log.h"
#include "packet.h"
#include "ip_id.h"

#define TUNNEL_MODULE_NAME "tunnel"

#define MAX_TUNNELS (2048)
#define MAX_PKT_BURST (1024)
#define MAX_IP_ADDRS (1024)

#define DEFAULT_TTL (0)
#define DEFAULT_TOS (-1)

#define ADDRESS_TYPE_IPV4 (0)
#define ADDRESS_TYPE_IPV6 (1)

#define IP4_ADDR_LEN (4)

#define IP6_VERSION (6)
#define IP6_ADDR_LEN (16)

#define IP_OFF_FULL_MASK (IP_DF | IP_MF | IP_OFFMASK)
#define IS_ATOMIC(_offset) (((_offset) & IP_OFF_FULL_MASK) == IP_DF)

#define IS_FLOODING(mbuf) ((rte_mbuf_refcnt_read((mbuf)) == 1) ? false : true)

#define ETHER_TYPE_IPv4_BE (RTE_BE16(ETHER_TYPE_IPv4)) /* big-endian */
#define ETHER_TYPE_IPv6_BE (RTE_BE16(ETHER_TYPE_IPv6)) /* big-endian */

#if RTE_BYTE_ORDER != RTE_LITTLE_ENDIAN
#define BYTES_TO_UINT64(a, b, c, d, e, f, g, h) \
  (((uint64_t)((a) & 0xff) << 56) | \
   ((uint64_t)((b) & 0xff) << 48) | \
   ((uint64_t)((c) & 0xff) << 40) | \
   ((uint64_t)((d) & 0xff) << 32) | \
   ((uint64_t)((e) & 0xff) << 24) | \
   ((uint64_t)((f) & 0xff) << 16) | \
   ((uint64_t)((g) & 0xff) << 8)  | \
   ((uint64_t)(h) & 0xff))
#else
#define BYTES_TO_UINT64(a, b, c, d, e, f, g, h) \
  (((uint64_t)((h) & 0xff) << 56) | \
   ((uint64_t)((g) & 0xff) << 48) | \
   ((uint64_t)((f) & 0xff) << 40) | \
   ((uint64_t)((e) & 0xff) << 32) | \
   ((uint64_t)((d) & 0xff) << 24) | \
   ((uint64_t)((c) & 0xff) << 16) | \
   ((uint64_t)((b) & 0xff) << 8) | \
   ((uint64_t)(a) & 0xff))
#endif

#define ETHADDR_TO_UINT64(addr) BYTES_TO_UINT64(         \
    (addr).addr_bytes[0], (addr).addr_bytes[1],          \
    (addr).addr_bytes[2], (addr).addr_bytes[3],          \
    (addr).addr_bytes[4], (addr).addr_bytes[5],          \
    0, 0)

#define ETHADDR_FORMAT "%02x:%02x:%02x:%02x:%02x:%02x"

#define ETHADDR_TO_ARRAY(addr)                         \
  (addr).addr_bytes[0], (addr).addr_bytes[1],          \
  (addr).addr_bytes[2], (addr).addr_bytes[3],          \
  (addr).addr_bytes[4], (addr).addr_bytes[5]

#define uint32_t_to_char(ip, a, b, c, d) do {\
    *a = (uint8_t)(ip >> 24 & 0xff);\
    *b = (uint8_t)(ip >> 16 & 0xff);\
    *c = (uint8_t)(ip >> 8 & 0xff);\
    *d = (uint8_t)(ip & 0xff);\
  } while (0)

#define TUNNEL_ASSERT(expr)                                             \
  extern int (*tunnel_assert(void))[                                    \
  sizeof(struct {uint8_t tunnel_assert_failed : (expr) ? 1 : -1;})]

typedef enum {
  TUNNEL_STATS_TYPE_UNKNOWN = 0,
  TUNNEL_STATS_TYPE_INBOUND = 1,
  TUNNEL_STATS_TYPE_OUTBOUND = 2,

  TUNNEL_STATS_TYPE_MAX = 3,
} tunnel_stats_type_t;

static const char *const tunnel_stats_type_strs[TUNNEL_STATS_TYPE_MAX] = {
  "unknown",  /* TUNNEL_STATS_TYPE_UNKNOWN */
  "in",  /* TUNNEL_STATS_TYPE_INBOUND */
  "out", /* TUNNEL_STATS_TYPE_OUTBOUND */
};

typedef enum {
  ETHER_ADDR_TYPE_UNKNOWN = 0,
  ETHER_ADDR_TYPE_UNICAST = 1,
  ETHER_ADDR_TYPE_BROADCAST = 2,
  ETHER_ADDR_TYPE_MULTICAST = 3,

  ETHER_ADDR_TYPE_MAX = 4,
} ether_addr_type_t;

struct ip_addr {
  union {
    uint32_t ip4;
    union {
      uint64_t ip6[2];
      uint8_t ip6_b[16];
    } ip6;
  } ip;
};

struct ip_addrs {
  uint16_t size;
  struct ip_addr addrs[MAX_IP_ADDRS];
};

struct tunnel_stats {
  uint64_t pkts;                                         // total packets received
  uint64_t ether_addr_type_pkts[ETHER_ADDR_TYPE_MAX];    // total ether address type
  uint64_t bytes;                                        // total bytes received
  uint64_t inner_pkt_bytes;                              // total inner bytes received
  uint64_t inner_vlan_tagged_pkt_bytes;                  // total tagged inner bytes received
  uint32_t unknown_protos;                               // unknown protocol packets received
  uint64_t errors;                                       // error packets received
  uint64_t dropped;                                      // no space in ring buffer
  uint64_t ether_addr_type_dropped[ETHER_ADDR_TYPE_MAX]; // no space in ring buffer
};

struct tunnel_mbuf_metadata {
  uint32_t inner_pkt_bytes;
  uint32_t inner_vlan_tagged_pkt_bytes;
  ether_addr_type_t inner_dst_ether_addr_type;
} __rte_cache_aligned;
TUNNEL_ASSERT(sizeof(struct tunnel_mbuf_metadata) <=
              PACKET_METADATA_SIZE);

static inline ether_addr_type_t
get_dst_ether_addr_type(struct rte_mbuf *m) {
  struct ether_hdr *ether_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
  struct ether_addr *daddr = &ether_hdr->d_addr;

  if (is_broadcast_ether_addr(daddr)) {
    return ETHER_ADDR_TYPE_BROADCAST;
  }

  if (is_multicast_ether_addr(daddr)) {
    return ETHER_ADDR_TYPE_MULTICAST;
  }

  return ETHER_ADDR_TYPE_UNICAST;
}

static inline struct tunnel_mbuf_metadata *
get_tunnel_mbuf_metadata(struct rte_mbuf *m) {
  struct vsw_packet_metadata *lm = VSW_MBUF_METADATA(m);
  return (struct tunnel_mbuf_metadata *) &lm->udata;
}

static inline void
set_meta_inner_pkt_bytes(struct rte_mbuf *m) {
  struct tunnel_mbuf_metadata *metadata = get_tunnel_mbuf_metadata(m);
  metadata->inner_pkt_bytes = m->pkt_len;
}

static inline void
set_meta_inner_vlan_tagged_pkt_bytes(struct rte_mbuf *m) {
  struct tunnel_mbuf_metadata *metadata = get_tunnel_mbuf_metadata(m);
  metadata->inner_vlan_tagged_pkt_bytes = m->pkt_len;
}

static inline void
set_meta_inner_dst_ether_addr_type(struct rte_mbuf *m) {
  struct tunnel_mbuf_metadata *metadata = get_tunnel_mbuf_metadata(m);
  metadata->inner_dst_ether_addr_type = get_dst_ether_addr_type(m);
}

static inline void
set_meta_local(struct rte_mbuf *m) {
  struct vsw_packet_metadata *metadata = VSW_MBUF_METADATA(m);
  metadata->common.local = true;
}

static inline void
tunnel_update_pkts(struct tunnel_stats *stats) {
  stats->pkts++;
}

static inline void
tunnel_update_ether_addr_type_pkts(struct tunnel_stats *stats,
                                   ether_addr_type_t ether_addr_type) {
  stats->ether_addr_type_pkts[ether_addr_type]++;
}

static inline void
tunnel_update_bytes(struct tunnel_stats *stats, uint64_t bytes) {
  stats->bytes += bytes;
}

static inline void
tunnel_update_inner_pkt_bytes(struct tunnel_stats *stats,
                              uint64_t inner_pkt_bytes) {
  stats->inner_pkt_bytes += inner_pkt_bytes;
}

static inline void
tunnel_update_inner_vlan_tagged_pkt_bytes(struct tunnel_stats *stats,
    uint64_t inner_vlan_tagged_pkt_bytes) {
  stats->inner_vlan_tagged_pkt_bytes += inner_vlan_tagged_pkt_bytes;
}

static inline void
tunnel_update_unknown_protos(struct tunnel_stats *stats) {
  stats->unknown_protos++;
}

static inline void
tunnel_update_errors(struct tunnel_stats *stats) {
  stats->errors++;
}

static inline void
tunnel_update_dropped(struct tunnel_stats *stats) {
  stats->dropped++;
}

static inline void
tunnel_update_ether_addr_type_dropped(struct tunnel_stats *stats,
                                      ether_addr_type_t ether_addr_type) {
  stats->ether_addr_type_dropped[ether_addr_type]++;
}

static inline void
tunnel_update_counter(struct vsw_counter *to,
                      struct tunnel_stats *in_from,
                      struct tunnel_stats *out_from) {
  // inbound
  to->in_octets = in_from->inner_pkt_bytes;
  to->in_unicast_pkts = in_from->ether_addr_type_pkts[ETHER_ADDR_TYPE_UNICAST] -
    in_from->ether_addr_type_dropped[ETHER_ADDR_TYPE_UNICAST];
  to->in_broadcast_pkts =
    in_from->ether_addr_type_pkts[ETHER_ADDR_TYPE_BROADCAST] -
    in_from->ether_addr_type_dropped[ETHER_ADDR_TYPE_BROADCAST];
  to->in_multicast_pkts =
    in_from->ether_addr_type_pkts[ETHER_ADDR_TYPE_MULTICAST] -
    in_from->ether_addr_type_dropped[ETHER_ADDR_TYPE_MULTICAST];
  to->in_discards = in_from->dropped;
  to->in_errors = in_from->errors;
  to->in_unknown_protos = in_from->unknown_protos;

  // outbound
  to->out_octets = out_from->inner_pkt_bytes;
  to->out_unicast_pkts = out_from->ether_addr_type_pkts[ETHER_ADDR_TYPE_UNICAST] -
    out_from->ether_addr_type_dropped[ETHER_ADDR_TYPE_UNICAST];
  to->out_broadcast_pkts =
    out_from->ether_addr_type_pkts[ETHER_ADDR_TYPE_BROADCAST] -
    out_from->ether_addr_type_dropped[ETHER_ADDR_TYPE_BROADCAST];
  to->out_multicast_pkts =
    out_from->ether_addr_type_pkts[ETHER_ADDR_TYPE_MULTICAST] -
    out_from->ether_addr_type_dropped[ETHER_ADDR_TYPE_MULTICAST];
  to->out_discards = out_from->dropped;
  to->out_errors = out_from->errors;
}

static inline void
tunnel_reset_counter(struct vsw_counter *counter,
                     struct tunnel_stats *in_stats,
                     struct tunnel_stats *out_stats) {
  if (counter != NULL) {
    memset(counter, 0, sizeof(struct vsw_counter));
    counter->last_clear = time(NULL);
  }

  if (in_stats != NULL) {
    memset(in_stats, 0, sizeof(struct tunnel_stats));
  }

  if (out_stats != NULL) {
    memset(out_stats, 0, sizeof(struct tunnel_stats));
  }
}

static inline void
tunnel_debug_print_stats(const char *name, struct tunnel_stats *stats,
                         tunnel_stats_type_t stats_type) {
  if (unlikely(TUNNEL_DEBUG_ENABLED)) {
    if (likely(name != NULL && stats != NULL)) {
      TUNNEL_DEBUG_NOFUNC("[%s] [%s] pkts=%d, un_pkts=%d, u_pkts=%d, b_pkts=%d, m_pkts=%d, "
                          "bytes=%d, inner_bytes=%d, inner_tagged_bytes=%d",
                          name, tunnel_stats_type_strs[stats_type], stats->pkts,
                          stats->ether_addr_type_pkts[ETHER_ADDR_TYPE_UNKNOWN],
                          stats->ether_addr_type_pkts[ETHER_ADDR_TYPE_UNICAST],
                          stats->ether_addr_type_pkts[ETHER_ADDR_TYPE_BROADCAST],
                          stats->ether_addr_type_pkts[ETHER_ADDR_TYPE_MULTICAST],
                          stats->bytes, stats->inner_pkt_bytes,
                          stats->inner_vlan_tagged_pkt_bytes);
      TUNNEL_DEBUG_NOFUNC("[%s] [%s] un_proto=%d, err=%d, drop=%d, "
                          "un_drop=%d, u_drop=%d, b_drop=%d, m_drop=%d",
                          name, tunnel_stats_type_strs[stats_type],
                          stats->unknown_protos, stats->errors, stats->dropped,
                          stats->ether_addr_type_dropped[ETHER_ADDR_TYPE_UNKNOWN],
                          stats->ether_addr_type_dropped[ETHER_ADDR_TYPE_UNICAST],
                          stats->ether_addr_type_dropped[ETHER_ADDR_TYPE_BROADCAST],
                          stats->ether_addr_type_dropped[ETHER_ADDR_TYPE_MULTICAST]);
    }
  }
}

/**
 * Encap Ethernet header.
 *
 * @param[in] m          mbuf.
 * @param[in] ether_type ethertype.
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 */
static inline lagopus_result_t
encap_ether(struct rte_mbuf *m, uint16_t ether_type) {
  struct ether_hdr *out_ether;

  if (m == NULL) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  out_ether = (struct ether_hdr *) rte_pktmbuf_prepend(m, ETHER_HDR_LEN);
  if (out_ether == NULL) {
    TUNNEL_ERROR("rte_pktmbuf_prepend failed");
    return LAGOPUS_RESULT_NO_MEMORY;
  }

  struct ether_addr addr = {0};
  out_ether->d_addr = addr;
  out_ether->s_addr = addr;
  out_ether->ether_type = rte_cpu_to_be_16(ether_type);

  return LAGOPUS_RESULT_OK;
}

/**
 * Decap Ethernet header.
 *
 * @param[in]  m      mbuf.
 * @param[in]  offset header offset.(in bytes, zero allowed.)
 * @param[out] out    A pointer to a Ethernet header returns.(NULL allowed.)
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 *
 * @details the *out is mbuf pointer, attention is required when operating.
 */
static inline lagopus_result_t
decap_ether(struct rte_mbuf *m, struct ether_hdr **out) {
  char *next;
  struct ether_hdr *ether_hdr;

  if (m == NULL) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  ether_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

  next = rte_pktmbuf_adj(m, ETHER_HDR_LEN);
  if (next == NULL) {
    TUNNEL_ERROR("rte_pktmbuf_adj failed");
    return LAGOPUS_RESULT_ANY_FAILURES;
  }

  if (out != NULL) {
    *out = ether_hdr;
  }

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
fill_ip_id(struct ip *ip) {
  if (ip == NULL) {
    TUNNEL_ERROR("invalid args");
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
convert_ip_tos(struct ip *ip, int8_t tos) {
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
convert_ip_ttl(struct ip *ip, uint8_t hop_limit) {
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
 * @param[in] m             mbuf.
 * @param[in] offset        header offset.(in bytes, zero allowed.)
 * @param[in] proto         protocol number.
 * @param[in] src           source IPv4 address.
 * @param[in] dst           destination IPv4 address.
 * @param[in] tos           type of service.
 * @param[in] off           fragment offset.
 * @param[in] ttl           time to live.
 * @param[in] is_calc_cksum Whether to calculate the checksum or not.
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 */
static inline lagopus_result_t
encap_ip4(struct rte_mbuf *m, uint32_t offset, uint8_t proto,
          struct ip_addr *src, struct ip_addr *dst, uint8_t tos,
          uint16_t off, uint8_t ttl, bool is_calc_cksum) {
  struct ip *out_ip4;

  if (m == NULL) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  offset += sizeof(struct ip);
  out_ip4 = (struct ip *) rte_pktmbuf_prepend(m, offset);
  if (out_ip4 == NULL) {
    TUNNEL_ERROR("rte_pktmbuf_prepend failed");
    return LAGOPUS_RESULT_NO_MEMORY;
  }

  out_ip4->ip_v = IPVERSION;
  out_ip4->ip_hl = 5;
  out_ip4->ip_tos = tos;
  out_ip4->ip_len = htons(rte_pktmbuf_pkt_len(m));
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
 * @param[in]  m      mbuf.
 * @param[in]  offset header offset.(in bytes, zero allowed.)
 * @param[out] out    A pointer to a IPv4 header returns.(NULL allowed.)
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 *
 * @details the **out is mbuf pointer, attention is required when operating.
 *
 * @details inner ECN field is not updated.
 */
static inline lagopus_result_t
decap_ip4(struct rte_mbuf *m, uint32_t offset, struct ipv4_hdr **out) {
  char *next;
  uint32_t hdr_len;
  struct ipv4_hdr *ipv4_hdr;

  if (m == NULL) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  ipv4_hdr = rte_pktmbuf_mtod(m, struct ipv4_hdr *);

  hdr_len = sizeof(struct ipv4_hdr);
  next = rte_pktmbuf_adj(m, offset + hdr_len);
  if (next == NULL) {
    TUNNEL_ERROR("rte_pktmbuf_adj failed");
    return LAGOPUS_RESULT_ANY_FAILURES;
  }

  if (out != NULL) {
    *out = ipv4_hdr;
  }

  return LAGOPUS_RESULT_OK;
}

/**
 * Encap IPv6 header.
 *
 * @param[in] m             mbuf.
 * @param[in] offset        header offset.(in bytes, zero allowed.)
 * @param[in] proto         protocol number.
 * @param[in] src           source IPv6 address.
 * @param[in] dst           destination IPv6 address.
 * @param[in] tos           type of service.
 * @param[in] hop_limit     hop limit.
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 */
static inline lagopus_result_t
encap_ip6(struct rte_mbuf *m, uint32_t offset, uint8_t proto,
          struct ip_addr *src, struct ip_addr *dst,
          uint8_t tos, uint8_t hop_limit) {
  struct ip6_hdr *out_ip6;

  if (m == NULL) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  offset += sizeof(struct ip6_hdr);
  out_ip6 = (struct ip6_hdr *) rte_pktmbuf_prepend(m, offset);
  if (out_ip6 == NULL) {
    TUNNEL_ERROR("rte_pktmbuf_prepend failed");
    return LAGOPUS_RESULT_NO_MEMORY;
  }

  out_ip6->ip6_flow = htonl(IP6_VERSION << 28 | tos << 20);
  out_ip6->ip6_plen = htons(rte_pktmbuf_pkt_len(m) - sizeof(struct ip6_hdr));
  out_ip6->ip6_nxt = proto;
  out_ip6->ip6_hops = hop_limit;
  memcpy(&out_ip6->ip6_src.s6_addr, src, IP6_ADDR_LEN);
  memcpy(&out_ip6->ip6_dst.s6_addr, dst, IP6_ADDR_LEN);

  return LAGOPUS_RESULT_OK;
}

/**
 * Decap IPv6 header.
 *
 * @param[in]  m      mbuf.
 * @param[in]  offset header offset.(in bytes, zero allowed.)
 * @param[out] out    A pointer to a IPv6 header returns.(NULL allowed.)
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 *
 * @details the **out is mbuf pointer, attention is required when operating.
 *
 * @details inner ECN field is not updated.
 */
static inline lagopus_result_t
decap_ip6(struct rte_mbuf *m, uint32_t offset, struct ipv6_hdr **out) {
  char *next;
  uint32_t hdr_len;
  struct ipv6_hdr *ipv6_hdr;

  if (m == NULL) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  ipv6_hdr = rte_pktmbuf_mtod(m, struct ipv6_hdr *);

  hdr_len = sizeof(struct ipv6_hdr);
  next = rte_pktmbuf_adj(m, offset + hdr_len);
  if (next == NULL) {
    TUNNEL_ERROR("rte_pktmbuf_adj failed");
    return LAGOPUS_RESULT_ANY_FAILURES;
  }

  if (out != NULL) {
    *out = ipv6_hdr;
  }

  return LAGOPUS_RESULT_OK;
}

#endif /* __TUNNEL_H__ */
