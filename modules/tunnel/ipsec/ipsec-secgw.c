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

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <numa.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include "module.h"
#include "ipsec.h"
#include "esp.h"
#include "sp4.h"
#include "sp6.h"
#include "ipsecvsw.h"
#include "nat_t.h"

/* For performance improvement(inline expansion). */
#include "ifaces.c"

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	3

#define ETHADDR(a, b, c, d, e, f) (BYTES_TO_UINT64(a, b, c, d, e, f, 0, 0))

struct ethaddr_info ethaddr_tbl[RTE_MAX_ETHPORTS] = {0};

struct traffic_type {
  const uint8_t *data[MAX_PKT_BURST * 2];
  struct rte_mbuf *pkts[MAX_PKT_BURST * 2];
  uint32_t res[MAX_PKT_BURST * 2];
  uint32_t num;
};

struct ipsec_traffic {
  struct traffic_type ipsec;
  struct traffic_type ip4;
  struct traffic_type ip6;
  struct traffic_type ike;
};

typedef lagopus_result_t
(*prepare_one_packet_proc_t)(struct rte_mbuf *pkt,
                             uint8_t *proto,
                             size_t size_of_ip,
                             struct traffic_type *t_ipsec,
                             struct traffic_type *t_ike,
                             struct traffic_type *t_ip);

typedef void
(*prepare_tx_pkt_proc_t)(struct rte_mbuf *pkt, iface_stats_t *stats);

struct ipsec_data {
  pthread_t tid;
  ipsecvsw_queue_role_t role;
  uint32_t socket_id;
  bool is_core_bind;
  uint64_t core_mask;
  cpu_set_t cpu_set;
  vrfindex_t vrf_index; /* current VRF Index. */
  vifindex_t vif_index; /* current VIF Index. */
  lagopus_chrono_t now;
  struct sa_ctx *sad; /* current sad with VRF.*/
  struct sa_ctx *sads[VRF_MAX_ENTRY];
  struct spd4 *spd4; /* current spd4 with VRF.*/
  struct spd4 *spd4s[VRF_MAX_ENTRY];
  struct spd6 *spd6; /* current spd6 with VRF.*/
  struct spd6 *spd6s[VRF_MAX_ENTRY];
  struct iface *iface;
  struct ifaces *ifaces;
  prepare_one_packet_proc_t prepare_one_packet_proc;
  prepare_tx_pkt_proc_t prepare_tx_pkt_proc;
  bool running;
  ipsecvsw_session_gc_ctx_record session_gc_ctx;
};

lagopus_result_t
prepare_one_packet_inbound(struct rte_mbuf *pkt,
                           uint8_t *proto,
                           size_t size_of_ip,
                           struct traffic_type *t_ipsec,
                           struct traffic_type *t_ike,
                           struct traffic_type *t_ip) {
  struct vsw_packet_metadata *metadata = VSW_MBUF_METADATA(pkt);
  struct ipsec_mbuf_metadata *priv = get_priv(pkt);
  uint16_t nat_t_len;

  if (unlikely(nat_t_is_ike_pkt(pkt, *proto,
                                ETHER_HDR_LEN + size_of_ip))) {
    /* IKE packet. */
    /* NOTE: Not frequent. */
    metadata->common.to_tap = true;
    t_ike->pkts[(t_ike->num)++] = pkt;
    return LAGOPUS_RESULT_OK;
  }

  /* ESP(Normal, NAT-T) packet.*/
  if (likely(rte_pktmbuf_adj(pkt, ETHER_HDR_LEN) != NULL)) {
    if (*proto == IPPROTO_ESP) {
      /* ESP. */
      IPSEC_SET_NAT_T_LEN(priv, 0);
    } else if ((nat_t_len = nat_t_get_len_by_proto(*proto)) != 0) {
      /* NAT-T. */
      IPSEC_SET_NAT_T_LEN(priv, nat_t_len);
    } else {
      TUNNEL_ERROR("Unsupported packet type(%d).", *proto);
      return LAGOPUS_RESULT_UNKNOWN_PROTO;
    }

    t_ipsec->pkts[(t_ipsec->num)++] = pkt;
    return LAGOPUS_RESULT_OK;
  }

  TUNNEL_ERROR("No memory.");
  return LAGOPUS_RESULT_NO_MEMORY;
}

lagopus_result_t
prepare_one_packet_outbound(struct rte_mbuf *pkt,
                            uint8_t *proto,
                            size_t size_of_ip,
                            struct traffic_type *t_ipsec,
                            struct traffic_type *t_ike,
                            struct traffic_type *t_ip) {
  struct ipsec_mbuf_metadata *priv = get_priv(pkt);

  /* IP packet. */
  if (likely(rte_pktmbuf_adj(pkt, ETHER_HDR_LEN) != NULL)) {
    t_ip->data[t_ip->num] = proto;
    t_ip->pkts[(t_ip->num)++] = pkt;
    IPSEC_SET_NAT_T_LEN(priv, 0);

    /* set inner packet bytes(for stats). */
    set_meta_inner_pkt_bytes(pkt);

    return LAGOPUS_RESULT_OK;
  }

  TUNNEL_ERROR("No memory.");
  return LAGOPUS_RESULT_NO_MEMORY;
}

static inline void
prepare_one_packet(struct module *myself,
                   struct rte_mbuf *pkt,
                   struct ipsec_traffic *t,
                   uint8_t ttl, int8_t tos,
                   iface_stats_t *stats) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct ipsec_data *data = myself->context;
  struct ipsec_mbuf_metadata *priv = get_priv(pkt);
  struct ether_hdr *eth;
  struct ip *ip;

  /* Flooding packet. */
  if (unlikely(IS_FLOODING(pkt) == true)) {
    /* Flooding packet: drop the packet */
    TUNNEL_ERROR("Flooding packet.");
    ret = LAGOPUS_RESULT_UNSUPPORTED;
    goto done;
  }

  /* Linearize mbuf. */
  /* NOTE: Crypto PMD doesn't support segmented mbuf. */
  if (unlikely(rte_pktmbuf_linearize(pkt) != 0)) {
    /* not enough tailroom: drop the packet. */
    TUNNEL_ERROR("Not enough tailroom.");
    ret = LAGOPUS_RESULT_NO_MEMORY;
    goto done;
  }

  /* Set TTL/TOS. */
  priv->ttl = ttl;
  priv->tos = tos;

  eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
  ip = rte_pktmbuf_mtod_offset(pkt, struct ip *, sizeof(struct ether_hdr));

  if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
    /* IPv4. */
    ret = data->prepare_one_packet_proc(pkt, &ip->ip_p,
                                        sizeof(struct ip),
                                        &t->ipsec, &t->ike, &t->ip4);
  } else if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
    /* IPv6. */
    struct ip6_hdr *ip6 = (struct ip6_hdr *) ip;
    ret = data->prepare_one_packet_proc(pkt, &ip6->ip6_nxt,
                                        sizeof(struct ip6_hdr),
                                        &t->ipsec, &t->ike, &t->ip6);
  } else {
    /* Unknown/Unsupported type. */
    TUNNEL_ERROR("Unsupported packet type.");
    ret = LAGOPUS_RESULT_UNKNOWN_PROTO;
  }

done:
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    /* drop packet. */
    if (ret == LAGOPUS_RESULT_UNKNOWN_PROTO) {
      iface_stats_update_unknown_protos(stats);
    } else {
      iface_stats_update_errors(stats);
    }
    rte_pktmbuf_free(pkt);
  }
}

static inline void
prepare_traffic(struct module *myself, struct rte_mbuf **pkts,
                struct ipsec_traffic *t, uint16_t nb_pkts,
                iface_stats_t *stats) {
  struct ipsec_data *data = myself->context;
  int32_t i;
  uint8_t ttl;
  int8_t tos;

  t->ipsec.num = 0;
  t->ip4.num = 0;
  t->ip6.num = 0;
  t->ike.num = 0;

  ttl = iface_get_ttl(data->iface);
  tos = iface_get_tos(data->iface);

  for (i = 0; i < (nb_pkts - PREFETCH_OFFSET); i++) {
    rte_prefetch0(rte_pktmbuf_mtod(pkts[i + PREFETCH_OFFSET],
                                   void *));
    prepare_one_packet(myself, pkts[i], t, ttl, tos, stats);
  }
  /* Process left packets */
  for (; i < nb_pkts; i++) {
    prepare_one_packet(myself, pkts[i], t, ttl, tos, stats);
  }
}

void
prepare_tx_pkt_inbound(struct rte_mbuf *pkt, iface_stats_t *stats) {
  /* set inner packet bytes(for stats). */
  set_meta_inner_pkt_bytes(pkt);
  /* update stats. */
  iface_stats_update(stats, pkt);
  return;
}

void
prepare_tx_pkt_outbound(struct rte_mbuf *pkt, iface_stats_t *stats) {
  /* update stats. */
  iface_stats_update(stats, pkt);
  return;
}

static inline void
prepare_tx_pkt(struct module *myself, struct rte_mbuf *pkt,
               iface_stats_t *stats) {
  struct ipsec_data *data = myself->context;
  struct ip *ip;
  struct ether_hdr *ethhdr;

  data->prepare_tx_pkt_proc(pkt, stats);

  ip = rte_pktmbuf_mtod(pkt, struct ip *);

  ethhdr = (struct ether_hdr *)rte_pktmbuf_prepend(pkt, ETHER_HDR_LEN);

  if (ip->ip_v == IPVERSION) {
    struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *) ip;

    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
    pkt->ol_flags |= PKT_TX_IPV4;
    pkt->l3_len = sizeof(struct ip);
    pkt->l2_len = ETHER_HDR_LEN;

    ethhdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
  } else {
    pkt->ol_flags |= PKT_TX_IPV6;
    pkt->l3_len = sizeof(struct ip6_hdr);
    pkt->l2_len = ETHER_HDR_LEN;

    ethhdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);
  }

  memset(&ethhdr->s_addr, 0, sizeof(struct ether_addr));
  memset(&ethhdr->d_addr, 0, sizeof(struct ether_addr));
}

static inline void
prepare_tx_burst(struct module *myself,
                 struct rte_mbuf *pkts[],
                 uint16_t nb_pkts,
                 iface_stats_t *stats) {
  int32_t i;
  const int32_t prefetch_offset = 2;

  for (i = 0; i < (nb_pkts - prefetch_offset); i++) {
    rte_mbuf_prefetch_part2(pkts[i + prefetch_offset]);
    prepare_tx_pkt(myself, pkts[i], stats);
  }
  /* Process left packets */
  for (; i < nb_pkts; i++) {
    prepare_tx_pkt(myself, pkts[i], stats);
  }
}

static inline void
inbound_sp_sa(struct module *module,
              void *spd,
              sp_classify_spd_proc_t classify_proc,
              sp_set_lifetime_current_proc_t set_lifetime_proc,
              struct traffic_type *ip,
              uint16_t lim,
              iface_stats_t *stats) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct ipsec_data *data = module->context;
  struct rte_mbuf *m;
  uint32_t i, j, res, sa_idx;

  if (ip->num == 0) {
    return;
  }

  if (likely((ret = classify_proc(spd, ip->data,
                                  ip->res, ip->num)) == LAGOPUS_RESULT_OK)) {
    j = 0;
    for (i = 0; i < ip->num; i++) {
      m = ip->pkts[i];
      res = ip->res[i];
      sa_idx = ip->res[i] & PROTECT_MASK;

      if (unlikely((ret = set_lifetime_proc(spd, sa_idx,
                                            data->now)) !=
                   LAGOPUS_RESULT_OK)) {
        TUNNEL_PERROR(ret);
        return;
      }

      if (res & BYPASS) {
        ip->pkts[j++] = m;
        continue;
      }
      if (res & RESERVED) {
        TUNNEL_ERROR("Used RESERVED rules(%"PRIu32").", res);
        iface_stats_update_errors(stats);
        rte_pktmbuf_free(m);
        continue;
      }
      if (res & DISCARD || i < lim) {
        TUNNEL_DEBUG("DISCARD(%"PRIu32").", res);
        iface_stats_update_errors(stats);
        rte_pktmbuf_free(m);
        continue;
      }
      /* Only check SPI match for processed IPSec packets */
      if (sa_idx == 0 || !inbound_sa_check(data->sad, m, sa_idx)) {
        TUNNEL_DEBUG("DISCARD(%"PRIu32").", sa_idx);
        iface_stats_update_errors(stats);
        rte_pktmbuf_free(m);
        continue;
      }
      ip->pkts[j++] = m;
    }
    ip->num = j;
  } else {
    TUNNEL_PERROR(ret);
    for (i = 0; i < ip->num; i++) {
      iface_stats_update_errors(stats);
      rte_pktmbuf_free(ip->pkts[i]);
    }
  }
}

static inline void
process_pkts_inbound(struct module *module,
                     const pthread_t tid,
                     struct ipsec_traffic *traffic,
                     iface_stats_t *stats) {
  struct ipsec_data *data = module->context;
  struct rte_mbuf *m;
  uint32_t idx;
  uint16_t nb_pkts_in, i, n_ip4, n_ip6;
  struct ip *ip;

  nb_pkts_in = ipsec_esp_inbound(tid, data->sad,
                                 traffic->ipsec.pkts,
                                 traffic->ipsec.num,
                                 data->now, MAX_PKT_BURST,
                                 stats);

  n_ip4 = (uint16_t)traffic->ip4.num;
  n_ip6 = (uint16_t)traffic->ip6.num;

  /* SP/ACL Inbound check ipsec and ip4 */
  for (i = 0; i < nb_pkts_in; i++) {
    m = traffic->ipsec.pkts[i];
    ip = rte_pktmbuf_mtod(m, struct ip *);
    if (ip->ip_v == IPVERSION) {
      idx = traffic->ip4.num++;
      traffic->ip4.pkts[idx] = m;
      traffic->ip4.data[idx] = rte_pktmbuf_mtod_offset(m,
                               uint8_t *, offsetof(struct ip, ip_p));
    } else if (ip->ip_v == IP6_VERSION) {
      idx = traffic->ip6.num++;
      traffic->ip6.pkts[idx] = m;
      traffic->ip6.data[idx] = rte_pktmbuf_mtod_offset(m,
                               uint8_t *,
                               offsetof(struct ip6_hdr, ip6_nxt));
    } else {
      iface_stats_update_unknown_protos(stats);
      rte_pktmbuf_free(m);
    }
  }

  inbound_sp_sa(module, (void *)data->spd4, sp4_classify_spd_in,
                sp4_set_lifetime_current, &traffic->ip4, n_ip4, stats);
  inbound_sp_sa(module, (void *)data->spd6, sp6_classify_spd_in,
                sp6_set_lifetime_current, &traffic->ip6, n_ip6, stats);
}

static inline void
outbound_sp(struct module *module,
            void *spd,
            sp_classify_spd_proc_t classify_proc,
            sp_set_lifetime_current_proc_t set_lifetime_proc,
            struct traffic_type *ip,
            struct traffic_type *ipsec,
            iface_stats_t *stats) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct ipsec_data *data = module->context;
  struct rte_mbuf *m = NULL;
  struct ipsec_mbuf_metadata *priv;
  uint32_t i, j, sa_idx;

  if (ip->num == 0) {
    return;
  }

  if (likely((ret = classify_proc(spd, ip->data,
                                  ip->res, ip->num)) == LAGOPUS_RESULT_OK)) {
    j = 0;
    for (i = 0; i < ip->num; i++) {
      m = ip->pkts[i];
      sa_idx = ip->res[i] & PROTECT_MASK;
      priv = get_priv(m);

      if (unlikely((ret = set_lifetime_proc(spd, sa_idx,
                                            data->now)) !=
                   LAGOPUS_RESULT_OK)) {
        TUNNEL_PERROR(ret);
        return;
      }

      if ((ip->res[i] == 0) || (ip->res[i] & DISCARD)) {
        TUNNEL_DEBUG("DISCARD(%"PRIu32").", ip->res[i]);
        iface_stats_update_errors(stats);
        rte_pktmbuf_free(m);
      } else if (ip->res[i] & RESERVED) {
        TUNNEL_ERROR("Used RESERVED rules(%"PRIu32").", ip->res[i]);
        iface_stats_update_errors(stats);
        rte_pktmbuf_free(m);
      } else if (ip->res[i] & BYPASS) {
        ip->pkts[j++] = m;
        priv->sp_entry_id = DATA2SP_ENTRY_ID(ip->res[i]);
        TUNNEL_DEBUG("OK BYPASS(%"PRIu32").", ip->res[i]);
      } else if (sa_idx != 0 && sa_idx < IPSEC_SA_MAX_ENTRIES) {
        ipsec->res[ipsec->num] = sa_idx;
        ipsec->pkts[ipsec->num++] = m;
        priv->sp_entry_id = DATA2SP_ENTRY_ID(ip->res[i]);
        TUNNEL_DEBUG("OK, sa index = %"PRIu32
                     ", entry id = %"PRIu32".",
                     sa_idx, priv->sp_entry_id);
      } else {
        TUNNEL_ERROR("Bad SA entry(%"PRIu32").", ip->res[i]);
        iface_stats_update_errors(stats);
        rte_pktmbuf_free(m);
      }
    }
    ip->num = j;
  } else {
    TUNNEL_PERROR(ret);
    for (i = 0; i < ip->num; i++) {
      iface_stats_update_errors(stats);
      rte_pktmbuf_free(ip->pkts[i]);
    }
  }
}

static inline void
process_pkts_outbound(struct module *module,
                      const pthread_t tid,
                      struct ipsec_traffic *traffic,
                      iface_stats_t *stats) {
  struct ipsec_data *data = module->context;
  struct rte_mbuf *m;
  uint32_t idx;
  uint16_t nb_pkts_out, i;
  struct ip *ip;

  /* Drop any IPsec traffic from protected ports */
  for (i = 0; i < traffic->ipsec.num; i++) {
    iface_stats_update_errors(stats);
    rte_pktmbuf_free(traffic->ipsec.pkts[i]);
  }

  traffic->ipsec.num = 0;

  outbound_sp(module, (void *) data->spd4, sp4_classify_spd_out,
              sp4_set_lifetime_current, &traffic->ip4, &traffic->ipsec, stats);

  outbound_sp(module, (void *) data->spd6, sp6_classify_spd_out,
              sp6_set_lifetime_current, &traffic->ip6, &traffic->ipsec, stats);

  nb_pkts_out = ipsec_esp_outbound(tid, data->sad,
                                   traffic->ipsec.pkts,
                                   traffic->ipsec.res,
                                   traffic->ipsec.num,
                                   data->now, MAX_PKT_BURST,
                                   stats);

  for (i = 0; i < nb_pkts_out; i++) {
    m = traffic->ipsec.pkts[i];
    ip = rte_pktmbuf_mtod(m, struct ip *);
    if (ip->ip_v == IPVERSION) {
      idx = traffic->ip4.num++;
      traffic->ip4.pkts[idx] = m;
    } else {
      idx = traffic->ip6.num++;
      traffic->ip6.pkts[idx] = m;
    }
  }
}

static inline lagopus_result_t
ipsec_pre_process(struct ipsec_data *data) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  data->spd4 = data->spd4s[data->vrf_index];
  data->spd6 = data->spd6s[data->vrf_index];
  data->sad = data->sads[data->vrf_index];

  if (unlikely((ret = sad_pre_process(data->sad, data->role, data->tid,
                                      &(data->session_gc_ctx)))
               != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    goto done;
  }
  if (unlikely((ret = sp4_pre_process(data->spd4)) != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    goto done;
  }
  if (unlikely((ret = sp6_pre_process(data->spd6)) != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    goto done;
  }

done:
  return ret;
}

static inline lagopus_result_t
ipsec_post_process(struct ipsec_data *data) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (unlikely((ret = sp4_post_process(data->spd4)) != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    goto done;
  }
  if (unlikely((ret = sp6_post_process(data->spd6)) != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    goto done;
  }
  if (unlikely((ret = sad_post_process(data->sad)) != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    goto done;
  }

done:
  return ret;
}

static inline lagopus_result_t
core_affinity(pthread_t tid,
              cpu_set_t *cpu_set) {
  int r;

  r = pthread_setaffinity_np(tid, sizeof(cpu_set_t), cpu_set);
  if (unlikely(r < 0)) {
    TUNNEL_ERROR("failed pthread_setaffinity_np(): %s",
                 strerror(errno));
    return LAGOPUS_RESULT_POSIX_API_ERROR;
  }

  return LAGOPUS_RESULT_OK;
}

#define BIT_LSB (0x1ULL)
#define BIT_MASK_LSB (BIT_LSB)

static inline void
set_cpu_set(uint64_t core_mask, cpu_set_t *cpu_set) {
  uint64_t mask, i;

  CPU_ZERO(cpu_set);
  for (mask = core_mask, i = 0ULL; mask != 0ULL; mask >>= BIT_LSB, i++) {
    if (mask & BIT_MASK_LSB) {
      /* set cup_set. */
      CPU_SET((int) i, cpu_set);
    }
  }
}

static inline uint32_t
get_socket_id(uint64_t core_mask) {
  int socket_id = SOCKET_ID_ANY;
  uint64_t mask, i;

  for (mask = core_mask, i = 0ULL; mask != 0ULL; mask >>= BIT_LSB, i++) {
    if (mask & BIT_MASK_LSB) {
      if (socket_id == SOCKET_ID_ANY) {
        socket_id = numa_node_of_cpu((int) i);
        continue;
      }
      if (socket_id != numa_node_of_cpu((int) i)) {
        socket_id = SOCKET_ID_ANY;
        break;
      }
    }
  }

  if (socket_id == SOCKET_ID_ANY) {
    socket_id = DEFAULT_SOCKET_ID;
  }

  return (uint32_t) socket_id;
}

static inline lagopus_result_t
ipsec_setup_cdevqs(struct module *myself) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct ipsec_data *data = myself->context;
  size_t n_qs;
  size_t n_actual = 0;

  /*
   * FIXME:
   *   For single-threaded operation, we need to scan whole the
   *   cdevqs for get.
   */
  ret = ipsecvsw_get_cdevqs_no(data->role);
  if (likely((ret > 0))) {
    n_qs = (size_t)ret;
    ret = ipsecvsw_acquire_cdevqs_for_get(data->tid, data->role,
                                          n_qs, &n_actual);
    if (unlikely((size_t)ret != n_qs)) {
      if (ret < 0) {
        TUNNEL_PERROR(ret);
        TUNNEL_ERROR("can't acquire crypto device queues to get.");
        goto done;
      } else {
        /* Modified to "ERROR".                                    */
        /* Original code is "WARNING":                             */
        /*   Because it considered "cdevqs" was added dynamically. */
        ret = LAGOPUS_RESULT_INVALID_OBJECT;
        TUNNEL_PERROR(ret);
        TUNNEL_ERROR("can't acquire all cyrpto device queues "
                     "to get.");
        goto done;
      }
    }
  }

  ipsecvsw_session_gc_initialize(data->tid,
                                 &(data->session_gc_ctx));
  ret = LAGOPUS_RESULT_OK;

done:
  return ret;
}

static inline lagopus_result_t
ipsec_setup(struct module *myself) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct ipsec_data *data = myself->context;
  int r;

  /* get thread ID. */
  data->tid = pthread_self();

  /* set name of thread. */
  r = pthread_setname_np(data->tid, data->role == ipsecvsw_queue_role_inbound ?
                         "ipsec-inbound" : "ipsec-outbound");
  if (unlikely(r < 0)) {
    TUNNEL_ERROR("failed pthread_setname_np(): %s",
                 strerror(errno));
    ret = LAGOPUS_RESULT_POSIX_API_ERROR;
    TUNNEL_PERROR(ret);
    goto done;
  }

  /* CPU core affinity.  */
  if (data->is_core_bind) {
    TUNNEL_DEBUG("IPsec core_affinity: %s : core mask = 0x%"PRIx64","
                 " socket_id = %d.",
                 data->role == ipsecvsw_queue_role_inbound ?
                 "inbound" : "outbound",
                 data->core_mask, data->socket_id);
    ret = core_affinity(data->tid, &data->cpu_set);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      goto done;
    }
  }

  TUNNEL_DEBUG("setup cdevqs.");
  ret = ipsec_setup_cdevqs(myself);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    goto done;
  }

  ret = LAGOPUS_RESULT_OK;

done:
  return ret;
}





static pthread_once_t s_cdev_once = PTHREAD_ONCE_INIT;

static void
s_cdevq_init_once(void) {
  lagopus_result_t r = ipsecvsw_setup_cdevq(NULL);
  if (unlikely(r != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(r);
    TUNNEL_ERROR("can't initialize DPDK crypto device(s).");
  }
}

lagopus_result_t
ipsec_configure(struct module *myself, void *p) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct ipsec_data *data = myself->context;
  struct ipsec_params *params = p;
  size_t i;

  data->role = params->role;
  if (likely(data->role == ipsecvsw_queue_role_inbound ||
             data->role == ipsecvsw_queue_role_outbound)) {
    if (data->role == ipsecvsw_queue_role_inbound) {
      data->prepare_one_packet_proc = prepare_one_packet_inbound;
      data->prepare_tx_pkt_proc = prepare_tx_pkt_inbound;
      data->core_mask = params->inbound_core_mask;
    } else {
      data->prepare_one_packet_proc = prepare_one_packet_outbound;
      data->prepare_tx_pkt_proc = prepare_tx_pkt_outbound;
      data->core_mask = params->outbound_core_mask;
    }

    data->is_core_bind = params->is_core_bind;
    if (data->is_core_bind) {
      /* set cpu_set. */
      set_cpu_set(data->core_mask, &data->cpu_set);
      /* get socket_id. */
      data->socket_id = get_socket_id(data->core_mask);
    } else {
      data->socket_id = DEFAULT_SOCKET_ID;
    }

    (void)pthread_once(&s_cdev_once, s_cdevq_init_once);

    /* assumed single core per module. */
    ret = ifaces_initialize(&data->ifaces);
    TUNNEL_DEBUG("initialize ifaces.");
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      goto done;
    }

    TUNNEL_DEBUG("initialize SAD/SPD.");
    for (i = 0; i < VRF_MAX_ENTRY; i++) {
      ret = sad_init(&data->sads[i], data->socket_id, data->role);
      if (unlikely(ret != LAGOPUS_RESULT_OK)) {
        TUNNEL_PERROR(ret);
        goto done;
      }

      ret = sp4_initialize(&data->spd4s[i], data->socket_id);
      if (unlikely(ret != LAGOPUS_RESULT_OK)) {
        TUNNEL_PERROR(ret);
        goto done;
      }

      ret = sp6_initialize(&data->spd6s[i], data->socket_id);
      if (unlikely(ret != LAGOPUS_RESULT_OK)) {
        TUNNEL_PERROR(ret);
        goto done;
      }
    }

    data->running = false;

    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

done:
  return ret;
}

void
ipsec_unconfigure(struct module *myself) {
  struct ipsec_data *data = myself->context;
  size_t i;

  for (i = 0; i < VRF_MAX_ENTRY; i++) {
    sp4_finalize(&data->spd4s[i]);
    sp6_finalize(&data->spd6s[i]);
    sad_finalize(data->sads[i], data->role,
                 data->tid, &(data->session_gc_ctx));
  }
  ifaces_finalize(&data->ifaces);
}

static inline size_t
ipsec_input(struct module *myself, struct rte_mbuf **mbufs, size_t n_mbufs) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct ipsec_data *data = myself->context;
  struct ipsec_traffic traffic;
  iface_stats_t *stats = NULL;
  uint32_t i, send4 = 0, send6 = 0, sendike = 0;

  if (unlikely(data->tid != pthread_self())) {
    TUNNEL_ERROR("thread is changed from the first execution of this "
                 "function which is strongly unacceptable.");
    ret = LAGOPUS_RESULT_INVALID_OBJECT;
    TUNNEL_PERROR(ret);
    goto free;
  }

  if (unlikely(data->prepare_one_packet_proc == NULL)) {
    TUNNEL_ERROR("prepare_one_packet_proc is NULL");
    ret = LAGOPUS_RESULT_INVALID_OBJECT;
    TUNNEL_PERROR(ret);
    goto free;
  }

  if (unlikely(data->prepare_tx_pkt_proc == NULL)) {
    TUNNEL_ERROR("prepare_tx_pkt_proc is NULL");
    ret = LAGOPUS_RESULT_INVALID_OBJECT;
    TUNNEL_PERROR(ret);
    goto free;
  }

  if (unlikely((stats = ifaces_get_stats_internal(
          data->ifaces, data->vif_index)) == NULL)) {
    TUNNEL_ERROR("stats is NULL");
    ret = LAGOPUS_RESULT_INVALID_OBJECT;
    TUNNEL_PERROR(ret);
    goto free;
  }

  WHAT_TIME_IS_IT_NOW_IN_NSEC(data->now);

  // pre.
  if (unlikely((ret = ipsec_pre_process(data)) != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    goto free;
  }

  ipsecvsw_session_ctx_gc(data->tid, &(data->session_gc_ctx));

  prepare_traffic(myself, mbufs, &traffic, (uint16_t)n_mbufs, stats);

  if (data->role == ipsecvsw_queue_role_inbound) {
    process_pkts_inbound(myself, data->tid, &traffic, stats);
  } else if (data->role == ipsecvsw_queue_role_outbound) {
    process_pkts_outbound(myself, data->tid, &traffic, stats);
  } else {
    TUNNEL_DEBUG("drop");
  }

  // send next module.
  if (likely(traffic.ip4.num != 0)) {
    prepare_tx_burst(myself, (struct rte_mbuf **)traffic.ip4.pkts,
                     (uint16_t)traffic.ip4.num, stats);
    send4 = rte_ring_enqueue_burst(iface_get_output(data->iface),
                                   (void **)traffic.ip4.pkts,
                                   traffic.ip4.num,
                                   NULL);
  }
  if (likely(traffic.ip6.num != 0)) {
    prepare_tx_burst(myself, (struct rte_mbuf **)traffic.ip6.pkts,
                     (uint16_t)traffic.ip6.num, stats);
    send6 = rte_ring_enqueue_burst(iface_get_output(data->iface),
                                   (void **)traffic.ip6.pkts,
                                   traffic.ip6.num,
                                   NULL);
  }
  if (likely(traffic.ike.num != 0)) {
    sendike = rte_ring_enqueue_burst(iface_get_output(data->iface),
                                     (void **)traffic.ike.pkts,
                                     traffic.ike.num,
                                     NULL);
  }

  // free.
  if (unlikely(traffic.ip4.num != send4)) {
    for (i = send4; i < traffic.ip4.num; i++) {
      /* drop packets. */
      iface_stats_update_dropped(stats);
      rte_pktmbuf_free(traffic.ip4.pkts[i]);
    }
  }
  if (unlikely(traffic.ip6.num != send6)) {
    for (i = send6; i < traffic.ip6.num; i++) {
      /* drop packets. */
      iface_stats_update_dropped(stats);
      rte_pktmbuf_free(traffic.ip6.pkts[i]);
    }
  }
  if (unlikely(traffic.ike.num != sendike)) {
    for (i = sendike; i < traffic.ike.num; i++) {
      /* drop packets. */
      iface_stats_update_dropped(stats);
      rte_pktmbuf_free(traffic.ike.pkts[i]);
    }
  }

  tunnel_debug_print_stats("ipsec", stats,
                           data->role == ipsecvsw_queue_role_inbound ?
                           TUNNEL_STATS_TYPE_INBOUND: TUNNEL_STATS_TYPE_OUTBOUND);

  // post.
  if (unlikely((ret = ipsec_post_process(data)) != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    goto done;
  }

free:
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    for (i = 0; i < n_mbufs; i++) {
      if (stats != NULL) {
        iface_stats_update_errors(stats);
      }
      /* In this case, stats can't be updated. */
      rte_pktmbuf_free(mbufs[i]);
    }
  }

done:
  return ret;
}

uint32_t
spi2sa_index(uint32_t spi) {
  return SPI2IDX(spi);
}

struct spd4 *
ipsec_get_spd4(struct module *module, vrfindex_t vrf_index) {
  struct ipsec_data *data = NULL;

  if (module != NULL) {
    data = module->context;
    return data->spd4s[vrf_index];
  }
  return NULL;
}

struct spd6 *
ipsec_get_spd6(struct module *module, vrfindex_t vrf_index) {
  struct ipsec_data *data = NULL;

  if (module != NULL) {
    data = module->context;
    return data->spd6s[vrf_index];
  }
  return NULL;
}

struct sa_ctx **
ipsec_get_sad(struct module *module, vrfindex_t vrf_index) {
  struct ipsec_data *data = NULL;

  if (module != NULL) {
    data = module->context;
    return &data->sads[vrf_index];
  }
  return NULL;
}

struct ifaces *
ipsec_get_ifaces(struct module *module) {
  struct ipsec_data *data = NULL;

  if (module != NULL) {
    data = module->context;
    return data->ifaces;
  }
  return NULL;
}

/* TODO: temp. */
lagopus_result_t
ipsec_add_ethaddr(uint8_t port,
                  struct ethaddr_info *info) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct ether_addr mac;

  if (port < RTE_MAX_ETHPORTS) {
    ethaddr_tbl[port] = *info;
    if (ethaddr_tbl[port].src == 0) {
      rte_eth_macaddr_get(port, &mac);
      ethaddr_tbl[port].src = ETHADDR_TO_UINT64(mac);
    }
    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_OUT_OF_RANGE;
    TUNNEL_PERROR(ret);
  }
  return ret;
}

lagopus_result_t
ipsec_mainloop(struct module *myself) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct ipsec_data *data = myself->context;
  struct rte_mbuf *mbufs[MAX_PKT_BURST];
  struct iface_list *active_ifaces;
  struct iface *iface;
  uint32_t n_mbufs;


  /* setup. */
  if (unlikely((ret = ipsec_setup(myself)) !=
               LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    goto done;
  }

  data->running = true;
  mbar();
  while (data->running) {
    // pre.
    if (unlikely((ret = ifaces_pre_process(data->ifaces,
                                           &active_ifaces)) !=
                 LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      goto done;
    }

    TAILQ_FOREACH(iface, active_ifaces, entry) {
      data->iface = iface;
      data->vrf_index = iface_get_vrf_index(iface);
      data->vif_index = iface_get_vif_index(iface);

      n_mbufs = (uint32_t) rte_ring_dequeue_burst(iface_get_input(data->iface),
                (void **)mbufs, MAX_PKT_BURST, NULL);
      if (n_mbufs > 0) {
        ret = ipsec_input(myself, mbufs, (size_t) n_mbufs);
        if (ret != LAGOPUS_RESULT_OK) {
          TUNNEL_PERROR(ret);
          goto done;
        }
      }
    }

    // post.
    if (unlikely((ret = ifaces_post_process(data->ifaces)) !=
                 LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      goto done;
    }

    ret = LAGOPUS_RESULT_OK;
  }

done:
  return ret;
}

void
ipsec_stop(struct module *myself) {
  struct ipsec_data *data = myself->context;
  data->running = false;
  mbar();
}

struct moduleconf ipsec = {
  MODULE_NAME,
  sizeof(struct ipsec_data),
};

REGISTER_MODULECONF(ipsec);
