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

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <fcntl.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_random.h>
#include <rte_byteorder.h>
#include <rte_esp.h>

#include "ipsec.h"
#include "sa.h"
#include "ipip.h"

#include "lagopus_apis.h"
#include "ipsecvsw.h"

static int
esp_inbound(struct rte_mbuf *m, struct ipsec_sa *sa,
            struct rte_crypto_op *cop) {
  struct ip *ip4;
  struct rte_crypto_sym_op *sym_cop;
  int32_t payload_len, ip_hdr_len;
  struct cnt_blk *icb;
  uint8_t *aad;
  uint8_t *iv, *iv_ptr;

  RTE_ASSERT(m != NULL);
  RTE_ASSERT(sa != NULL);
  RTE_ASSERT(cop != NULL);

  ip4 = rte_pktmbuf_mtod(m, struct ip *);
  if (likely(ip4->ip_v == IPVERSION)) {
    ip_hdr_len = ip4->ip_hl * 4;
  } else if (ip4->ip_v == IP6_VERSION)
    /* XXX No option headers supported */
  {
    ip_hdr_len = sizeof(struct ip6_hdr);
  } else {
    lagopus_msg_error("invalid IP packet type %d\n",
                      ip4->ip_v);
    return -EINVAL;
  }

  payload_len = (int32_t)((uint64_t)rte_pktmbuf_pkt_len(m)
                          - (uint64_t)ip_hdr_len - sizeof(struct esp_hdr)
                          - (uint64_t)sa->iv_len - (uint64_t)sa->digest_len);

  if ((payload_len & (sa->block_size - 1)) || (payload_len <= 0)) {
    lagopus_msg_debug(1, "payload %d not multiple of %u\n",
                      payload_len, sa->block_size);
    return -EINVAL;
  }

  sym_cop = get_sym_cop(cop);
  sym_cop->m_src = m;

  if (sa->aead_algo == RTE_CRYPTO_AEAD_AES_GCM) {
    sym_cop->aead.data.offset = ip_hdr_len + sizeof(struct esp_hdr) +
                                sa->iv_len;
    sym_cop->aead.data.length = payload_len;

    iv = RTE_PTR_ADD(ip4, ip_hdr_len + sizeof(struct esp_hdr));

    icb = get_cnt_blk(m);
    icb->salt = sa->salt;
    memcpy(&icb->iv, iv, 8);
    icb->cnt = rte_cpu_to_be_32(1);

    aad = get_aad(m);
    memcpy(aad, iv - sizeof(struct esp_hdr), 8);
    sym_cop->aead.aad.data = aad;
    sym_cop->aead.aad.phys_addr =
      rte_pktmbuf_iova_offset(m,
                              aad - rte_pktmbuf_mtod(m, uint8_t *));

    sym_cop->aead.digest.data =
      rte_pktmbuf_mtod_offset(m, void *,
                              rte_pktmbuf_pkt_len(m) - sa->digest_len);
    sym_cop->aead.digest.phys_addr =
      rte_pktmbuf_iova_offset(m,
                              rte_pktmbuf_pkt_len(m) - sa->digest_len);
  } else {
    sym_cop->cipher.data.offset =
      (uint32_t)((uint64_t)ip_hdr_len + sizeof(struct esp_hdr) + sa->iv_len);
    sym_cop->cipher.data.length = (uint32_t)payload_len;

    iv = RTE_PTR_ADD(ip4, (uint64_t)(ip_hdr_len) + sizeof(struct esp_hdr));
    iv_ptr = rte_crypto_op_ctod_offset(cop,
                                       uint8_t *, IV_OFFSET);

    switch (sa->cipher_algo) {
      case RTE_CRYPTO_CIPHER_NULL:
      case RTE_CRYPTO_CIPHER_AES_CBC:
        /* Copy IV at the end of crypto operation */
        rte_memcpy(iv_ptr, iv, sa->iv_len);
        break;
      case RTE_CRYPTO_CIPHER_AES_CTR:
        icb = get_cnt_blk(m);
        icb->salt = sa->salt;
        memcpy(&icb->iv, iv, 8);
        icb->cnt = rte_cpu_to_be_32(1);
        break;
      default:
        lagopus_msg_error("unsupported cipher algorithm %u\n",
                          sa->cipher_algo);
        return -EINVAL;
    }

    switch (sa->auth_algo) {
      case RTE_CRYPTO_AUTH_NULL:
      case RTE_CRYPTO_AUTH_SHA1_HMAC:
      case RTE_CRYPTO_AUTH_SHA256_HMAC:
        sym_cop->auth.data.offset = (uint32_t) ip_hdr_len;
        sym_cop->auth.data.length = (uint32_t) (sizeof(struct esp_hdr) +
                                                (uint64_t) (sa->iv_len + payload_len));
        break;
      default:
        lagopus_msg_error("unsupported auth algorithm %u\n",
                          sa->auth_algo);
        return -EINVAL;
    }

    sym_cop->auth.digest.data =
      rte_pktmbuf_mtod_offset(m, void *,
                              rte_pktmbuf_pkt_len(m) - sa->digest_len);
    sym_cop->auth.digest.phys_addr =
      rte_pktmbuf_iova_offset(m,
                              rte_pktmbuf_pkt_len(m) - sa->digest_len);
  }

  return 0;
}

static int
esp_inbound_post(struct rte_mbuf *m, struct ipsec_sa *sa,
                 struct rte_crypto_op *cop) {
  struct ip *ip4, *ip;
  struct ip6_hdr *ip6;
  uint8_t *nexthdr, *pad_len;
  uint8_t *padding;
  uint16_t i;

  RTE_ASSERT(m != NULL);
  RTE_ASSERT(sa != NULL);
  RTE_ASSERT(cop != NULL);

  if (cop->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
    lagopus_msg_error("failed crypto op\n");
    return -1;
  }

  nexthdr = rte_pktmbuf_mtod_offset(m, uint8_t *,
                                    rte_pktmbuf_pkt_len(m) - sa->digest_len - 1);
  pad_len = nexthdr - 1;

  padding = pad_len - *pad_len;
  for (i = 0; i < *pad_len; i++) {
    if (padding[i] != i + 1) {
      lagopus_msg_error("invalid padding\n");
      return -EINVAL;
    }
  }

  if (rte_pktmbuf_trim(m, (uint16_t)(*pad_len + 2 + sa->digest_len))) {
    lagopus_msg_error("failed to remove pad_len + digest\n");
    return -EINVAL;
  }

  if (unlikely(sa->flags == TRANSPORT)) {
    ip = rte_pktmbuf_mtod(m, struct ip *);
    ip4 = (struct ip *)rte_pktmbuf_adj(m,
                                       (uint16_t)(sizeof(struct esp_hdr) + sa->iv_len));
    if (likely(ip->ip_v == IPVERSION)) {
      memmove(ip4, ip, (size_t)(ip->ip_hl * 4));
      ip4->ip_p = *nexthdr;
      ip4->ip_len = htons(rte_pktmbuf_data_len(m));
    } else {
      ip6 = (struct ip6_hdr *)ip4;
      /* XXX No option headers supported */
      memmove(ip6, ip, sizeof(struct ip6_hdr));
      ip6->ip6_nxt = *nexthdr;
      ip6->ip6_plen = htons(rte_pktmbuf_data_len(m) -
                            sizeof(struct ip6_hdr));
    }
  } else {
    if (unlikely(ipip_inbound(m,
                              (uint32_t)(sizeof(struct esp_hdr) + sa->iv_len)) !=
                 LAGOPUS_RESULT_OK)) {
      return -EINVAL;
    }
  }

  return 0;
}

static int
esp_outbound(struct rte_mbuf *m, struct ipsec_sa *sa,
             struct rte_crypto_op *cop) {
  struct ip *ip4;
  struct ip6_hdr *ip6;
  struct ipsec_mbuf_metadata *priv;
  struct esp_hdr *esp = NULL;
  uint8_t *padding = NULL, *new_ip, nlp;
  struct rte_crypto_sym_op *sym_cop;
  int32_t i;
  uint16_t pad_payload_len, pad_len, ip_hdr_len;
  uint8_t *aad;
  struct cnt_blk *icb;
  uint64_t *iv;

  RTE_ASSERT(m != NULL);
  RTE_ASSERT(sa != NULL);
  RTE_ASSERT(cop != NULL);

  priv = get_priv(m);
  ip_hdr_len = 0;

  ip4 = rte_pktmbuf_mtod(m, struct ip *);
  if (likely(ip4->ip_v == IPVERSION)) {
    if (unlikely(sa->flags == TRANSPORT)) {
      ip_hdr_len = (uint16_t)(ip4->ip_hl * 4);
      nlp = ip4->ip_p;
    } else {
      nlp = IPPROTO_IPIP;
    }
  } else if (ip4->ip_v == IP6_VERSION) {
    if (unlikely(sa->flags == TRANSPORT)) {
      /* XXX No option headers supported */
      ip_hdr_len = sizeof(struct ip6_hdr);
      ip6 = (struct ip6_hdr *)ip4;
      nlp = ip6->ip6_nxt;
    } else {
      nlp = IPPROTO_IPV6;
    }
  } else {
    lagopus_msg_error("invalid IP packet type %d\n",
                      ip4->ip_v);
    return -EINVAL;
  }

  /* Padded payload length */
  pad_payload_len =
    (uint16_t)(RTE_ALIGN_CEIL((uint16_t)(rte_pktmbuf_pkt_len(m) - ip_hdr_len + 2),
                              (uint16_t)(sa->block_size)));
  pad_len = (uint16_t)(pad_payload_len + ip_hdr_len - (uint16_t)
                       rte_pktmbuf_pkt_len(m));

  RTE_ASSERT(sa->flags == IP4_TUNNEL || sa->flags == IP6_TUNNEL ||
             sa->flags == TRANSPORT);

  if (likely(sa->flags == IP4_TUNNEL)) {
    ip_hdr_len = sizeof(struct ip);
  } else if (sa->flags == IP6_TUNNEL) {
    ip_hdr_len = sizeof(struct ip6_hdr);
  } else if (sa->flags != TRANSPORT) {
    lagopus_msg_error("Unsupported SA flags: 0x%x\n",
                      sa->flags);
    return -EINVAL;
  }

  /* Check maximum packet size */
  if (unlikely(ip_hdr_len + sizeof(struct esp_hdr) + sa->iv_len +
               pad_payload_len + sa->digest_len > IP_MAXPACKET)) {
    lagopus_msg_error("ipsec packet is too big, %lu > MAX(%d)\n",
                      ip_hdr_len + sizeof(struct esp_hdr) + sa->iv_len + pad_payload_len +
                      sa->digest_len, IP_MAXPACKET);
    lagopus_msg_error("esp_hdr:%lu, iv_len:%d, pad_payload_len:%d, sa_digest_len:%d\n",
                      sizeof(struct esp_hdr), sa->iv_len, pad_payload_len, sa->digest_len);
    return -EINVAL;
  }

  padding = (uint8_t *)rte_pktmbuf_append(m,
                                          (uint16_t)(pad_len + sa->digest_len));
  if (unlikely(padding == NULL)) {
    lagopus_msg_error("not enough mbuf trailing space\n");
    return -ENOSPC;
  }
  rte_prefetch0(padding);

  switch (sa->flags) {
    case IP4_TUNNEL:
      if (likely(ip4ip_outbound(m, (uint32_t)(sizeof(struct esp_hdr) + sa->iv_len),
                                &sa->src, &sa->dst, priv->ttl,
                                priv->tos, &ip4) == LAGOPUS_RESULT_OK)) {
        esp = (struct esp_hdr *)(ip4 + 1);
      } else {
        return -EINVAL;
      }
      break;
    case IP6_TUNNEL:
      if (likely(ip6ip_outbound(m, (uint32_t)(sizeof(struct esp_hdr) + sa->iv_len),
                                &sa->src, &sa->dst, priv->ttl,
                                priv->tos, &ip6) == LAGOPUS_RESULT_OK)) {
        esp = (struct esp_hdr *)(ip6 + 1);
      } else {
        return -EINVAL;
      }
      break;
    case TRANSPORT:
      new_ip = (uint8_t *)rte_pktmbuf_prepend(m,
                                              (uint16_t)(sizeof(struct esp_hdr) + sa->iv_len));
      memmove(new_ip, ip4, ip_hdr_len);
      esp = (struct esp_hdr *)(new_ip + ip_hdr_len);
      if (likely(ip4->ip_v == IPVERSION)) {
        ip4 = (struct ip *)new_ip;
        ip4->ip_p = IPPROTO_ESP;
        ip4->ip_len = htons(rte_pktmbuf_data_len(m));
      } else {
        ip6 = (struct ip6_hdr *)new_ip;
        ip6->ip6_nxt = IPPROTO_ESP;
        ip6->ip6_plen = htons(rte_pktmbuf_data_len(m) -
                              sizeof(struct ip6_hdr));
      }
  }

  sa->seq++;
  esp->spi = rte_cpu_to_be_32(sa->spi);
  esp->seq = rte_cpu_to_be_32((uint32_t)sa->seq);

  /* set iv */
  iv = (uint64_t *)(esp + 1);
  if (sa->aead_algo == RTE_CRYPTO_AEAD_AES_GCM) {
    *iv = rte_cpu_to_be_64(sa->seq);
  } else {
    switch (sa->cipher_algo) {
      case RTE_CRYPTO_CIPHER_NULL:
      case RTE_CRYPTO_CIPHER_AES_CBC:
        memset(iv, 0, sa->iv_len);
        break;
      case RTE_CRYPTO_CIPHER_AES_CTR:
        *iv = rte_cpu_to_be_64(sa->seq);
        break;
      default:
        lagopus_msg_error("unsupported cipher algorithm %u\n",
                          sa->cipher_algo);
        return -EINVAL;
    }
  }

  sym_cop = get_sym_cop(cop);
  sym_cop->m_src = m;

  if (sa->aead_algo == RTE_CRYPTO_AEAD_AES_GCM) {
    sym_cop->aead.data.offset = (uint32_t) (ip_hdr_len +
                                            sizeof(struct esp_hdr) +
                                            sa->iv_len);
    sym_cop->aead.data.length = pad_payload_len;

    /* Fill pad_len using default sequential scheme */
    for (i = 0; i < pad_len - 2; i++) {
      padding[i] = (uint8_t) (i + 1);
    }
    padding[pad_len - 2] = (uint8_t) (pad_len - 2);
    padding[pad_len - 1] = nlp;

    icb = get_cnt_blk(m);
    icb->salt = sa->salt;
    icb->iv = rte_cpu_to_be_64(sa->seq);
    icb->cnt = rte_cpu_to_be_32(1);

    aad = get_aad(m);
    memcpy(aad, esp, 8);
    sym_cop->aead.aad.data = aad;
    sym_cop->aead.aad.phys_addr =
      rte_pktmbuf_iova_offset(m,
                              aad - rte_pktmbuf_mtod(m, uint8_t *));
    sym_cop->aead.digest.data = rte_pktmbuf_mtod_offset(m, uint8_t *,
                                rte_pktmbuf_pkt_len(m) - sa->digest_len);
    sym_cop->aead.digest.phys_addr = rte_pktmbuf_iova_offset(m,
                                     rte_pktmbuf_pkt_len(m) - sa->digest_len);
  } else {
    switch (sa->cipher_algo) {
      case RTE_CRYPTO_CIPHER_NULL:
      case RTE_CRYPTO_CIPHER_AES_CBC:
        sym_cop->cipher.data.offset = (uint32_t) (ip_hdr_len +
                                      sizeof(struct esp_hdr));
        sym_cop->cipher.data.length = (uint32_t) (pad_payload_len + sa->iv_len);
        break;
      case RTE_CRYPTO_CIPHER_AES_CTR:
        sym_cop->cipher.data.offset = (uint32_t) (ip_hdr_len +
                                      sizeof(struct esp_hdr) + sa->iv_len);
        sym_cop->cipher.data.length = pad_payload_len;
        break;
      default:
        lagopus_msg_error("unsupported cipher algorithm %u\n",
                          sa->cipher_algo);
        return -EINVAL;
    }

    /* Fill pad_len using default sequential scheme */
    for (i = 0; i < pad_len - 2; i++) {
      padding[i] = (uint8_t)(i + 1);
    }
    padding[pad_len - 2] = (uint8_t)(pad_len - 2);
    padding[pad_len - 1] = nlp;

    icb = get_cnt_blk(m);
    icb->salt = sa->salt;
    icb->iv = rte_cpu_to_be_64(sa->seq);
    icb->cnt = rte_cpu_to_be_32(1);

    switch (sa->auth_algo) {
      case RTE_CRYPTO_AUTH_NULL:
      case RTE_CRYPTO_AUTH_SHA1_HMAC:
      case RTE_CRYPTO_AUTH_SHA256_HMAC:
        sym_cop->auth.data.offset = ip_hdr_len;
        sym_cop->auth.data.length = (uint32_t) (sizeof(struct esp_hdr) +
                                                sa->iv_len + pad_payload_len);
        break;
      default:
        lagopus_msg_error("unsupported auth algorithm %u\n",
                          sa->auth_algo);
        return -EINVAL;
    }

    sym_cop->auth.digest.data =
      rte_pktmbuf_mtod_offset(m, uint8_t *,
                              rte_pktmbuf_pkt_len(m) - sa->digest_len);
    sym_cop->auth.digest.phys_addr =
      rte_pktmbuf_iova_offset(m,
                              rte_pktmbuf_pkt_len(m) - sa->digest_len);
  }

  return 0;
}

static int
esp_outbound_post(struct rte_mbuf *m,
                  struct ipsec_sa *sa,
                  struct rte_crypto_op *cop) {
  RTE_ASSERT(m != NULL);
  RTE_ASSERT(sa != NULL);
  RTE_ASSERT(cop != NULL);

  if (cop->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
    lagopus_msg_error("Failed crypto op\n");
    return -1;
  }

  return 0;
}





uint16_t
ipsec_esp_inbound(const pthread_t tid, struct sa_ctx *sad,
                  struct rte_mbuf *pkts[],
                  size_t nb_pkts, const lagopus_chrono_t now, uint16_t len) {
  uint16_t ret = 0;
  lagopus_result_t r;
  ipsecvsw_session_ctx_t sctxs[nb_pkts];
  const ipsecvsw_queue_role_t role = ipsecvsw_queue_role_inbound;

  inbound_sa_lookup(tid, sad,
                    (const struct rte_mbuf **)pkts,
                    nb_pkts, now, sctxs);

  r = ipsecvsw_cdevq_put(tid, role,
                         esp_inbound, pkts, sctxs,
                         nb_pkts);
  if (likely(r > 0)) {
    r = ipsecvsw_cdevq_get(tid, role,
                           esp_inbound_post,
                           pkts, (size_t)len);
    if (likely(r > 0)) {
      ret = (uint16_t)r;
    }
  }

  return ret;
}

uint16_t
ipsec_esp_outbound(const pthread_t tid, struct sa_ctx *sad,
                   struct rte_mbuf *pkts[], uint32_t sa_idx[],
                   size_t nb_pkts, const lagopus_chrono_t now, uint16_t len) {
  uint16_t ret = 0;
  lagopus_result_t r;
  ipsecvsw_session_ctx_t sctxs[nb_pkts];
  const ipsecvsw_queue_role_t role = ipsecvsw_queue_role_outbound;

  outbound_sa_lookup(tid, sad,
                     sa_idx, (const struct rte_mbuf **)pkts,
                     nb_pkts, now, sctxs);

  r = ipsecvsw_cdevq_put(tid, role,
                         esp_outbound, pkts, sctxs,
                         nb_pkts);
  if (likely(r > 0)) {
    r = ipsecvsw_cdevq_get(tid, role,
                           esp_outbound_post,
                           pkts, (size_t)len);
    if (likely(r > 0)) {
      ret = (uint16_t)r;
    }
  }

  return ret;
}


const char *
ipsecvsw_get_xform_funcname(ipsecvsw_xform_proc_t proc) {
  if (likely(proc != NULL)) {
    if (proc == esp_inbound) {
      return "esp_inbound";
    } else if (proc == esp_inbound_post) {
      return "esp_inbound_post";
    } else if (proc == esp_outbound) {
      return "esp_outbound";
    } else if (proc == esp_outbound_post) {
      return "esp_outbound_post";
    } else {
      return "UNKNOWN";
    }
  } else {
    return "NULL";
  }
}
