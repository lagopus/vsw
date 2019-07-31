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

#ifndef _LAGOPUS_MODULES_GRE_H
#define _LAGOPUS_MODULES_GRE_H

#include "l2tun.h"
#include "l3tun.h"

#define GRE_MODULE_NAME "gre"
#define L2GRE_MODULE_NAME "l2gre"

#define GRE_FLAGS_CP 0x8000
#define GRE_FLAGS_KP 0x2000
#define GRE_FLAGS_SP 0x1000
#define GRE_FLAGS_MASK (GRE_FLAGS_CP | GRE_FLAGS_KP | GRE_FLAGS_SP)

struct gre_hdr {
  uint16_t flags;
  uint16_t proto;
  uint32_t opts[0];
};

/**
 * Encap GRE header.
 *
 * @param[in] m      mbuf.
 * @param[in] proto  encapsulated payload.
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_NO_MEMORY Failed.
 */
static inline lagopus_result_t
encap_gre(struct rte_mbuf *m, uint16_t proto) {
  struct gre_hdr *gre_hdr = NULL;
  uint32_t hdr_len = 0;
  uint16_t flags = 0;
#if defined(GRE_ENCAP_CSUM) || defined(GRE_ENCAP_KEY)
  uint32_t *opts = NULL;
#endif /* GRE_ENCAP_CSUM or GRE_ENCAP_KEY */

  if (m == NULL) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  hdr_len += sizeof(struct gre_hdr);

#ifdef GRE_ENCAP_CSUM
  hdr_len += sizeof(uint32_t);
#endif /* GRE_ENCAP_CSUM */

#ifdef GRE_ENCAP_KEY
  hdr_len += sizeof(uint32_t);
#endif /* GRE_ENCAP_KEY */

  gre_hdr = (struct gre_hdr *) rte_pktmbuf_prepend(m, hdr_len);
  if (gre_hdr == NULL) {
    TUNNEL_ERROR("rte_pktmbuf_prepend failed");
    return LAGOPUS_RESULT_NO_MEMORY;
  }

#ifdef GRE_ENCAP_CSUM
  flags |= GRE_FLAGS_CP;
#endif /* GRE_ENCAP_CSUM */

#ifdef GRE_ENCAP_KEY
  flags |= GRE_FLAGS_KP;
#endif /* GRE_ENCAP_KEY */

  gre_hdr->flags = htons(flags);
  gre_hdr->proto = htons(proto);
#if defined(GRE_ENCAP_CSUM) || defined(GRE_ENCAP_KEY)
  opts = gre_hdr->opts;
#endif /* GRE_ENCAP_CSUM or GRE_ENCAP_KEY */

#ifdef GRE_ENCAP_CSUM
  *opts++ = 0;
#endif /* GRE_ENCAP_CSUM */

#ifdef GRE_ENCAP_KEY
  uint32_t key = 100;
  *opts++ = htonl(key);
#endif /* GRE_ENCAP_KEY */

#ifdef GRE_ENCAP_CSUM
  uint16_t cal_csum = rte_raw_cksum(gre_hdr, m->pkt_len);
  cal_csum = ~cal_csum & 0xffff;
  *(uint16_t *)gre_hdr->opts = cal_csum;
#endif /* GRE_ENCAP_CSUM */

  return LAGOPUS_RESULT_OK;
}

/**
 * Decap GRE header.
 *
 * @param[in]  m      mbuf.
 * @param[out] out    A pointer to a Ethernet header returns.(NULL allowed.)
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_TOO_SHORT Failed.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 *
 * @details the **out is mbuf pointer, attention is required when operating.
 */
static inline lagopus_result_t
decap_gre(struct rte_mbuf *m, struct gre_hdr **out) {
  struct gre_hdr *gre_hdr = NULL;
  uint32_t hdr_len = 0;
  uint16_t flags = 0;
  uint32_t *opts = NULL;
  uint16_t opt_csum = 0;
  uint32_t opt_key = 0;
  uint32_t opt_seq = 0;
  uint16_t cal_csum = 0;
  char *next = NULL;

  if (m == NULL) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  gre_hdr = rte_pktmbuf_mtod(m, struct gre_hdr *);
  if (gre_hdr == NULL) {
    TUNNEL_ERROR("rte_pktmbuf_mtod failed");
    return LAGOPUS_RESULT_ANY_FAILURES;
  }

  hdr_len = sizeof(struct gre_hdr);
  flags = ntohs(gre_hdr->flags);
  opts = gre_hdr->opts;

  if (flags & GRE_FLAGS_CP) {
    // Checksum field + Reserved1 field
    hdr_len += sizeof(uint16_t) * 2;

    if (hdr_len > m->pkt_len) {
      TUNNEL_ERROR("packet too short(csum)");
      return LAGOPUS_RESULT_TOO_SHORT;
    }

    opt_csum = (ntohl(*(uint32_t *)gre_hdr->opts) & 0xffff0000) >> 16;
    opts++;

    TUNNEL_DEBUG("gre opt csum: 0x%x", opt_csum);

    if (opt_csum == 0) {
      TUNNEL_ERROR("invalid checksum option: 0x%x", opt_csum);
      return LAGOPUS_RESULT_ANY_FAILURES;
    }

    cal_csum = rte_raw_cksum(gre_hdr, m->pkt_len);
    if (cal_csum != 0xffff) {
      TUNNEL_ERROR("invalid checksum: 0x%x", cal_csum);
      return LAGOPUS_RESULT_ANY_FAILURES;
    }
  }

  if (flags & GRE_FLAGS_KP) {
    hdr_len += sizeof(uint32_t);

    if (hdr_len > m->pkt_len) {
      TUNNEL_ERROR("packet too short(key)");
      return LAGOPUS_RESULT_TOO_SHORT;
    }

    opt_key = ntohl(*opts);
    opts++;

    TUNNEL_DEBUG("gre opt key: %d", opt_key);
  }

  if (flags & GRE_FLAGS_SP) {
    hdr_len += sizeof(uint32_t);

    if (hdr_len > m->pkt_len) {
      TUNNEL_ERROR("packet too short(seq)");
      return LAGOPUS_RESULT_TOO_SHORT;
    }

    opt_seq = ntohl(*opts);
    opts++;

    TUNNEL_DEBUG("gre opt seq: %d", opt_seq);
  }

  next = rte_pktmbuf_adj(m, hdr_len);
  if (next == NULL) {
    TUNNEL_ERROR("rte_pktmbuf_adj failed");
    return LAGOPUS_RESULT_ANY_FAILURES;
  }

  if (out != NULL) {
    *out = gre_hdr;
  }

  return LAGOPUS_RESULT_OK;
}

extern struct vsw_runtime_ops gre_inbound_runtime_ops;
extern struct vsw_runtime_ops gre_outbound_runtime_ops;

extern struct vsw_runtime_ops l2gre_inbound_runtime_ops;
extern struct vsw_runtime_ops l2gre_outbound_runtime_ops;

#endif // _LAGOPUS_MODULES_GRE_H
