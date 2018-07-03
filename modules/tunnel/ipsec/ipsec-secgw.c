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
#include <rte_ip.h>
#include <rte_mbuf.h>

#include "module.h"
#include "ipsec.h"
#include "sp4.h"
#include "sp6.h"
#include "ipsecvsw.h"

/* For performance improvement(inline expansion). */
#include "ifaces.c"

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	3

#if RTE_BYTE_ORDER != RTE_LITTLE_ENDIAN
#define __BYTES_TO_UINT64(a, b, c, d, e, f, g, h) \
  (((uint64_t)((a) & 0xff) << 56) | \
   ((uint64_t)((b) & 0xff) << 48) | \
   ((uint64_t)((c) & 0xff) << 40) | \
   ((uint64_t)((d) & 0xff) << 32) | \
   ((uint64_t)((e) & 0xff) << 24) | \
   ((uint64_t)((f) & 0xff) << 16) | \
   ((uint64_t)((g) & 0xff) << 8)  | \
   ((uint64_t)(h) & 0xff))
#else
#define __BYTES_TO_UINT64(a, b, c, d, e, f, g, h) \
  (((uint64_t)((h) & 0xff) << 56) | \
   ((uint64_t)((g) & 0xff) << 48) | \
   ((uint64_t)((f) & 0xff) << 40) | \
   ((uint64_t)((e) & 0xff) << 32) | \
   ((uint64_t)((d) & 0xff) << 24) | \
   ((uint64_t)((c) & 0xff) << 16) | \
   ((uint64_t)((b) & 0xff) << 8) | \
   ((uint64_t)(a) & 0xff))
#endif
#define ETHADDR(a, b, c, d, e, f) (__BYTES_TO_UINT64(a, b, c, d, e, f, 0, 0))

#define ETHADDR_TO_UINT64(addr) __BYTES_TO_UINT64( \
    addr.addr_bytes[0], addr.addr_bytes[1], \
    addr.addr_bytes[2], addr.addr_bytes[3], \
    addr.addr_bytes[4], addr.addr_bytes[5], \
    0, 0)

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
};

struct ipsec_data {
  pthread_t tid;
  bool is_first;
  bool is_succeeded;
  ipsecvsw_queue_role_t role;
  uint32_t socket_id;
  vrfindex_t vrf_index; /* current VRF Index. */
  lagopus_chrono_t now;
  struct sa_ctx *sad; /* current sad with VRF.*/
  struct sa_ctx *sads[VRF_MAX_ENTRY];
  struct spd4 *spd4; /* current spd4 with VRF.*/
  struct spd4 *spd4s[VRF_MAX_ENTRY];
  struct spd6 *spd6; /* current spd6 with VRF.*/
  struct spd6 *spd6s[VRF_MAX_ENTRY];
  struct iface *iface;
  struct ifaces *ifaces;
  bool running;
  ipsecvsw_session_gc_ctx_record session_gc_ctx;
};

static inline void
prepare_one_packet(struct rte_mbuf *pkt, struct ipsec_traffic *t,
                   uint8_t ttl, int8_t tos) {
  uint8_t *nlp;
  struct ether_hdr *eth;
  struct ipsec_mbuf_metadata *priv = get_priv(pkt);

  /* Set TTL/TOS. */
  priv->ttl = ttl;
  priv->tos = tos;

  eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);

  if (unlikely(IS_FLOODING(pkt) == true)) {
    /* Flooding packet: drop the packet */
    lagopus_msg_error("Flooding packet.\n");
    rte_pktmbuf_free(pkt);
  } else if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
    nlp = (uint8_t *)rte_pktmbuf_adj(pkt, ETHER_HDR_LEN);
    nlp = RTE_PTR_ADD(nlp, offsetof(struct ip, ip_p));
    if (*nlp == IPPROTO_ESP) {
      t->ipsec.pkts[(t->ipsec.num)++] = pkt;
    } else {
      t->ip4.data[t->ip4.num] = nlp;
      t->ip4.pkts[(t->ip4.num)++] = pkt;
    }
  } else if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
    nlp = (uint8_t *)rte_pktmbuf_adj(pkt, ETHER_HDR_LEN);
    nlp = RTE_PTR_ADD(nlp, offsetof(struct ip6_hdr, ip6_nxt));
    if (*nlp == IPPROTO_ESP) {
      t->ipsec.pkts[(t->ipsec.num)++] = pkt;
    } else {
      t->ip6.data[t->ip6.num] = nlp;
      t->ip6.pkts[(t->ip6.num)++] = pkt;
    }
  } else {
    /* Unknown/Unsupported type: drop the packet */
    lagopus_msg_error("Unsupported packet type.\n");
    rte_pktmbuf_free(pkt);
  }
}

static inline void
prepare_traffic(struct module *myself, struct rte_mbuf **pkts,
                struct ipsec_traffic *t, uint16_t nb_pkts) {
  struct ipsec_data *data = myself->context;
  int32_t i;
  uint8_t ttl;
  int8_t tos;

  t->ipsec.num = 0;
  t->ip4.num = 0;
  t->ip6.num = 0;

  ttl = iface_get_ttl(data->iface);
  tos = iface_get_tos(data->iface);

  for (i = 0; i < (nb_pkts - PREFETCH_OFFSET); i++) {
    rte_prefetch0(rte_pktmbuf_mtod(pkts[i + PREFETCH_OFFSET],
                                   void *));
    prepare_one_packet(pkts[i], t, ttl, tos);
  }
  /* Process left packets */
  for (; i < nb_pkts; i++) {
    prepare_one_packet(pkts[i], t, ttl, tos);
  }
}

static inline void
prepare_tx_pkt(struct rte_mbuf *pkt) {
  struct ip *ip;
  struct ether_hdr *ethhdr;

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
prepare_tx_burst(struct rte_mbuf *pkts[], uint16_t nb_pkts) {
  int32_t i;
  const int32_t prefetch_offset = 2;

  for (i = 0; i < (nb_pkts - prefetch_offset); i++) {
    rte_mbuf_prefetch_part2(pkts[i + prefetch_offset]);
    prepare_tx_pkt(pkts[i]);
  }
  /* Process left packets */
  for (; i < nb_pkts; i++) {
    prepare_tx_pkt(pkts[i]);
  }
}

static inline void
inbound_sp_sa(struct module *module,
              void *spd,
              sp_classify_spd_proc_t classify_proc,
              sp_set_lifetime_current_proc_t set_lifetime_proc,
              struct traffic_type *ip,
              uint16_t lim) {
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
        lagopus_perror(ret);
        return;
      }

      if (res & BYPASS) {
        ip->pkts[j++] = m;
        continue;
      }
      if (res & RESERVED) {
        lagopus_msg_error("Used RESERVED rules.\n");
        rte_pktmbuf_free(m);
        continue;
      }
      if (res & DISCARD || i < lim) {
        rte_pktmbuf_free(m);
        continue;
      }
      /* Only check SPI match for processed IPSec packets */
      if (sa_idx == 0 || !inbound_sa_check(data->sad, m, sa_idx)) {
        rte_pktmbuf_free(m);
        continue;
      }
      ip->pkts[j++] = m;
    }
    ip->num = j;
  } else {
    lagopus_perror(ret);
    for (i = 0; i < ip->num; i++) {
      rte_pktmbuf_free(ip->pkts[i]);
    }
  }
}

static inline void
process_pkts_inbound(struct module *module,
                     const pthread_t tid,
                     struct ipsec_traffic *traffic) {
  struct ipsec_data *data = module->context;
  struct rte_mbuf *m;
  uint32_t idx;
  uint16_t nb_pkts_in, i, n_ip4, n_ip6;
  struct ip *ip;

  nb_pkts_in = ipsec_esp_inbound(tid, data->sad,
                                 traffic->ipsec.pkts,
                                 traffic->ipsec.num,
                                 data->now, MAX_PKT_BURST);

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
      rte_pktmbuf_free(m);
    }
  }

  inbound_sp_sa(module, (void *)data->spd4, sp4_classify_spd_in,
                sp4_set_lifetime_current, &traffic->ip4, n_ip4);
  inbound_sp_sa(module, (void *)data->spd6, sp6_classify_spd_in,
                sp6_set_lifetime_current, &traffic->ip6, n_ip6);
}

static inline void
outbound_sp(struct module *module,
            void *spd,
            sp_classify_spd_proc_t classify_proc,
            sp_set_lifetime_current_proc_t set_lifetime_proc,
            struct traffic_type *ip,
            struct traffic_type *ipsec) {
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
        lagopus_perror(ret);
        return;
      }

      if ((ip->res[i] == 0) || (ip->res[i] & DISCARD)) {
        rte_pktmbuf_free(m);
      } else if (ip->res[i] & RESERVED) {
        lagopus_msg_error("Used RESERVED rules.\n");
        rte_pktmbuf_free(m);
      } else if (sa_idx != 0 && sa_idx < IPSEC_SA_MAX_ENTRIES) {
        ipsec->res[ipsec->num] = sa_idx;
        ipsec->pkts[ipsec->num++] = m;
        priv->sp_entry_id = DATA2SP_ENTRY_ID(ip->res[i]);
        lagopus_msg_debug(1, "OK, sa index = %"PRIu32
                          ", entry id = %"PRIu32".\n",
                          sa_idx, priv->sp_entry_id);
      } else {/* BYPASS */
        ip->pkts[j++] = m;
        priv->sp_entry_id = DATA2SP_ENTRY_ID(ip->res[i]);
      }
    }
    ip->num = j;
  } else {
    lagopus_perror(ret);
    for (i = 0; i < ip->num; i++) {
      rte_pktmbuf_free(ip->pkts[i]);
    }
  }
}

static inline void
process_pkts_outbound(struct module *module,
                      const pthread_t tid,
                      struct ipsec_traffic *traffic) {
  struct ipsec_data *data = module->context;
  struct rte_mbuf *m;
  uint32_t idx;
  uint16_t nb_pkts_out, i;
  struct ip *ip;

  /* Drop any IPsec traffic from protected ports */
  for (i = 0; i < traffic->ipsec.num; i++) {
    rte_pktmbuf_free(traffic->ipsec.pkts[i]);
  }

  traffic->ipsec.num = 0;

  outbound_sp(module, (void *) data->spd4, sp4_classify_spd_out,
              sp4_set_lifetime_current, &traffic->ip4, &traffic->ipsec);

  outbound_sp(module, (void *) data->spd6, sp6_classify_spd_out,
              sp6_set_lifetime_current, &traffic->ip6, &traffic->ipsec);

  nb_pkts_out = ipsec_esp_outbound(tid, data->sad,
                                   traffic->ipsec.pkts,
                                   traffic->ipsec.res,
                                   traffic->ipsec.num,
                                   data->now, MAX_PKT_BURST);

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
    lagopus_perror(ret);
    goto done;
  }
  if (unlikely((ret = sp4_pre_process(data->spd4)) != LAGOPUS_RESULT_OK)) {
    lagopus_perror(ret);
    goto done;
  }
  if (unlikely((ret = sp6_pre_process(data->spd6)) != LAGOPUS_RESULT_OK)) {
    lagopus_perror(ret);
    goto done;
  }

done:
  return ret;
}

static inline lagopus_result_t
ipsec_post_process(struct ipsec_data *data) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (unlikely((ret = sp4_post_process(data->spd4)) != LAGOPUS_RESULT_OK)) {
    lagopus_perror(ret);
    goto done;
  }
  if (unlikely((ret = sp6_post_process(data->spd6)) != LAGOPUS_RESULT_OK)) {
    lagopus_perror(ret);
    goto done;
  }
  if (unlikely((ret = sad_post_process(data->sad)) != LAGOPUS_RESULT_OK)) {
    lagopus_perror(ret);
    goto done;
  }

done:
  return ret;
}





static pthread_once_t s_cdev_once = PTHREAD_ONCE_INIT;

static void
s_cdevq_init_once(void) {
  lagopus_result_t r = ipsecvsw_setup_cdevq(NULL);
  if (unlikely(r != LAGOPUS_RESULT_OK)) {
    lagopus_perror(r);
    lagopus_msg_error("can't initialize DPDK crypto device(s).\n");
  }
}


lagopus_result_t
ipsec_configure(struct module *myself, void *p) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  size_t i;
  struct ipsec_data *data = myself->context;
  struct ipsec_param *param = p;

  /*
   * FIXME:
   *	It's kinda useless to decide where to allocate SA/SP tables at
   *	this moment, tho;
   */
  uint32_t socket_id = rte_socket_id();
  if (socket_id == LCORE_ID_ANY) {
    socket_id = 0;
  }

  if (param->role == ipsecvsw_queue_role_inbound ||
      param->role == ipsecvsw_queue_role_outbound) {
    data->socket_id = socket_id;
    data->role = param->role;
    data->running = false;
    data->is_first = true;

    (void)pthread_once(&s_cdev_once, s_cdevq_init_once);

    // assumed single core per module.
    ifaces_initialize(&data->ifaces);
    lagopus_msg_debug(1, "sad_init()\n");
    for (i = 0; i < VRF_MAX_ENTRY; i++) {
      ret = sad_init(&data->sads[i], data->socket_id, data->role);
      if (unlikely(ret != LAGOPUS_RESULT_OK)) {
        lagopus_perror(ret);
        goto done;
      }

      sp4_initialize(&data->spd4s[i], socket_id);
      sp6_initialize(&data->spd6s[i], socket_id);
    }
    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    lagopus_perror(ret);
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
  uint32_t i, send4, send6;

  if (unlikely(data->is_first == true)) {
    size_t n_qs;
    size_t n_actual = 0;
    bool succeeded = false;

    data->tid = pthread_self();
    /*
     * FIXME:
     *	For single-threaded operation, we need to scan whole the
     *	cdevqs for get.
     */
    ret = ipsecvsw_get_cdevqs_no(data->role);
    if (likely((ret > 0))) {
      n_qs = (size_t)ret;
      ret = ipsecvsw_acquire_cdevqs_for_get(data->tid, data->role,
                                            n_qs, &n_actual);
      if (likely((size_t)ret == n_qs)) {
        succeeded = true;
      } else {
        if (ret < 0) {
          lagopus_perror(ret);
          lagopus_msg_error("can't acquire crypto device queues to get.\n");
        } else {
          lagopus_msg_warning("can't acquire all cyrpto device queues "
                              "to get.\n");
        }
      }
    }

    ipsecvsw_session_gc_initialize(data->tid,
                                   &(data->session_gc_ctx));

    data->is_first = false;
    data->is_succeeded = succeeded;
  }

  if (likely(data->is_succeeded == true)) {

    if (unlikely(data->tid != pthread_self())) {
      lagopus_exit_fatal("thread is changed from the first execution of this "
                         "function which is strongly unacceptable.\n");
    }

    WHAT_TIME_IS_IT_NOW_IN_NSEC(data->now);

    // pre.
    if (unlikely((ret = ipsec_pre_process(data)) != LAGOPUS_RESULT_OK)) {
      lagopus_perror(ret);
      goto done;
    }

    ipsecvsw_session_ctx_gc(data->tid, &(data->session_gc_ctx));

    prepare_traffic(myself, mbufs, &traffic, (uint16_t)n_mbufs);

    if (data->role == ipsecvsw_queue_role_inbound) {
      process_pkts_inbound(myself, data->tid, &traffic);
      prepare_tx_burst((struct rte_mbuf **)mbufs, (uint16_t)n_mbufs);
    } else if (data->role == ipsecvsw_queue_role_outbound) {
      process_pkts_outbound(myself, data->tid, &traffic);
      prepare_tx_burst((struct rte_mbuf **)mbufs, (uint16_t)n_mbufs);
    } else {
      lagopus_msg_debug(1,"drop\n");
    }

    // send next module.
    if (likely(traffic.ip4.num != 0)) {
      send4 = rte_ring_enqueue_burst(iface_get_output(data->iface),
                                     (void **)traffic.ip4.pkts,
                                     traffic.ip4.num,
                                     NULL);
    }
    if (likely(traffic.ip6.num != 0)) {
      send6 = rte_ring_enqueue_burst(iface_get_output(data->iface),
                                     (void **)traffic.ip6.pkts,
                                     traffic.ip6.num,
                                     NULL);
    }

    // free.
    if (unlikely(traffic.ip4.num != send4)) {
      for (i = send4; i < traffic.ip4.num; i++) {
        rte_pktmbuf_free(traffic.ip4.pkts[i]);
      }
    }
    if (unlikely(traffic.ip6.num != send6)) {
      for (i = send6; i < traffic.ip6.num; i++) {
        rte_pktmbuf_free(traffic.ip6.pkts[i]);
       }
    }

    // post.
    if (unlikely((ret = ipsec_post_process(data)) != LAGOPUS_RESULT_OK)) {
      lagopus_perror(ret);
      goto done;
    }
  }

done:
  return (ret >= 0) ? (size_t)ret : 0;
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
    lagopus_perror(ret);
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

  data->running = true;
  mbar();
  while (data->running) {
    // pre.
    if (unlikely((ret = ifaces_pre_process(data->ifaces,
                                           &active_ifaces)) !=
                 LAGOPUS_RESULT_OK)) {
      lagopus_perror(ret);
      goto done;
    }

    TAILQ_FOREACH(iface, active_ifaces, entry) {
      data->iface = iface;
      data->vrf_index = iface_get_vrf_index(iface);

      n_mbufs = (uint32_t) rte_ring_dequeue_burst(iface_get_input(data->iface),
                (void **)mbufs, MAX_PKT_BURST, NULL);
      if (n_mbufs > 0) {
        ret = ipsec_input(myself, mbufs, (size_t) n_mbufs);
        if (ret != LAGOPUS_RESULT_OK) {
          lagopus_perror(ret);
          goto done;
        }
      }
    }

    // post.
    if (unlikely((ret = ifaces_post_process(data->ifaces)) !=
                 LAGOPUS_RESULT_OK)) {
      lagopus_perror(ret);
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
