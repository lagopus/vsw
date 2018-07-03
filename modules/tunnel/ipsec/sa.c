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
/*
 * Security Associations
 */
#include <time.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <rte_memzone.h>
#include <rte_byteorder.h>
#include <rte_esp.h>

#include "lagopus_apis.h"
#include "sa.h"
#include "ipsec.h"
#include "ipsecvsw.h"

#define SA_DEBUG_PRINT_LEN 1024

const struct supported_cipher_algo cipher_algos[] = {
  {
    .keyword = "null",
    .algo = RTE_CRYPTO_CIPHER_NULL,
    .iv_len = 0,
    .block_size = 4,
    .key_len = 0
  },
  {
    .keyword = "aes-128-cbc",
    .algo = RTE_CRYPTO_CIPHER_AES_CBC,
    .iv_len = 16,
    .block_size = 16,
    .key_len = 16
  },
  {
    .keyword = "aes-128-ctr",
    .algo = RTE_CRYPTO_CIPHER_AES_CTR,
    .iv_len = 8,
    .block_size = 4,
    .key_len = 20
  }
};

const struct supported_auth_algo auth_algos[] = {
  {
    .keyword = "null",
    .algo = RTE_CRYPTO_AUTH_NULL,
    .digest_len = 0,
    .key_len = 0,
    .key_not_req = 1
  },
  {
    .keyword = "sha1-hmac",
    .algo = RTE_CRYPTO_AUTH_SHA1_HMAC,
    .digest_len = 12,
    .key_len = 20
  },
  {
    .keyword = "sha256-hmac",
    .algo = RTE_CRYPTO_AUTH_SHA256_HMAC,
    .digest_len = 12,
    .key_len = 32
  }
};

const struct supported_aead_algo aead_algos[] = {
  {
    .keyword = "aes-128-gcm",
    .algo = RTE_CRYPTO_AEAD_AES_GCM,
    .iv_len = 8,
    .block_size = 4,
    .key_len = 20,
    .digest_len = 16,
    .aad_len = 8,
  }
};

// called by go-plane at only first
const struct supported_cipher_algo *
get_supported_cipher_algos(size_t *len) {
  *len = RTE_DIM(cipher_algos);
  return cipher_algos;
}

// called by go-plane at only first
const struct supported_auth_algo *
get_supported_auth_algos(size_t *len) {
  *len = RTE_DIM(auth_algos);
  return auth_algos;
}

// called by go-plane at only first
const struct supported_aead_algo *
get_supported_aead_algos(size_t *len) {
  *len = RTE_DIM(aead_algos);
  return aead_algos;
}

// for debug
static inline void
s_format_sa(char *buffer, const ipsec_sa_t sa, const size_t len) {
  uint32_t i;
  uint8_t a, b, c, d;
  size_t idx = 0;
  if (likely(sa != NULL)) {
    idx += (size_t)snprintf(&buffer[idx], len - idx,  "spi(%10u):", sa->spi);

    for (i = 0; i < RTE_DIM(cipher_algos); i++) {
      if (cipher_algos[i].algo == sa->cipher_algo) {
        idx += (size_t)snprintf(&buffer[idx], len - idx, "%s ",
                                cipher_algos[i].keyword);
        break;
      }
    }

    for (i = 0; i < RTE_DIM(auth_algos); i++) {
      if (auth_algos[i].algo == sa->auth_algo) {
        idx += (size_t)snprintf(&buffer[idx], len - idx, "%s ", auth_algos[i].keyword);
        break;
      }
    }

    for (i = 0; i < RTE_DIM(aead_algos); i++) {
      if (aead_algos[i].algo == sa->aead_algo) {
        idx += (size_t)snprintf(&buffer[idx], len - idx, "%s ",
                                aead_algos[i].keyword);
        break;
      }
    }

    idx += (size_t)snprintf(&buffer[idx], len - idx, "mode:");

    switch (sa->flags) {
      case IP4_TUNNEL:
        idx += (size_t)snprintf(&buffer[idx], len - idx, "IP4Tunnel ");
        uint32_t_to_char(sa->src.ip.ip4, &a, &b, &c, &d);
        idx += (size_t)snprintf(&buffer[idx], len - idx, "%hhu.%hhu.%hhu.%hhu ", d, c,
                                b, a);
        uint32_t_to_char(sa->dst.ip.ip4, &a, &b, &c, &d);
        (size_t)snprintf(&buffer[idx], len - idx, "%hhu.%hhu.%hhu.%hhu", d, c, b, a);
        break;
      case IP6_TUNNEL:
        idx += (size_t)snprintf(&buffer[idx], len - idx, "IP6Tunnel ");
        for (i = 0; i < 16; i++) {
          if (i % 2 && i != 15) {
            idx += (size_t)snprintf(&buffer[idx], len - idx, "%.2x:",
                                    sa->src.ip.ip6.ip6_b[i]);
          } else {
            idx += (size_t)snprintf(&buffer[idx], len - idx, "%.2x",
                                    sa->src.ip.ip6.ip6_b[i]);
          }
        }
        idx += (size_t)snprintf(&buffer[idx], len - idx, " ");
        for (i = 0; i < 16; i++) {
          if (i % 2 && i != 15) {
            idx += (size_t)snprintf(&buffer[idx], len - idx, "%.2x:",
                                    sa->dst.ip.ip6.ip6_b[i]);
          } else {
            idx += (size_t)snprintf(&buffer[idx], len - idx, "%.2x",
                                    sa->dst.ip.ip6.ip6_b[i]);
          }
        }
        break;
      case TRANSPORT:
        (size_t)snprintf(&buffer[idx], len - idx, "%s", "Transport");
        break;
    }
  } else {
    (size_t)snprintf(&buffer[idx], len - idx, "NULL");
  }
}

// called once per packet unlikely (at only first useing of SA)
static inline ipsecvsw_session_ctx_t
s_create_session(const pthread_t tid, const ipsecvsw_queue_role_t role,
                 ipsec_sa_t sa) {
  ipsecvsw_session_ctx_t ret = NULL;
  lagopus_result_t r = ipsecvsw_create_session_ctx(tid, role, sa, &ret);

  if (unlikely(r != LAGOPUS_RESULT_OK)) {
    lagopus_perror(r);
    lagopus_msg_error("can't create a session context.\n");
  }

  return ret;
}

// called once per packet unlikely (at only expireing of SA)
static inline void
s_dispose_session(const pthread_t tid, const ipsecvsw_queue_role_t role,
                  ipsecvsw_session_ctx_t s, ipsecvsw_session_gc_ctx_t gctx) {
  lagopus_result_t r = ipsecvsw_dispose_session_ctx(tid, role, s, gctx);

  if (unlikely(r != LAGOPUS_RESULT_OK)) {
    lagopus_perror(r);
    lagopus_msg_error("can't dispose a session context.\n");
  }
}

// called when finalize
static inline void
s_sad_t_detach_all(sad_t sad,
                   const ipsecvsw_queue_role_t role,
                   const pthread_t tid,
                   ipsecvsw_session_gc_ctx_t gctx) {
  for (size_t i = 0; i < IPSEC_SA_MAX_ENTRIES; i++) {
    if (sad->session_ctx[i] != NULL) {
      s_dispose_session(tid, role, sad->session_ctx[i], gctx);
    }
  }
}


// called when initialize
static lagopus_result_t
s_sad_create(sad_t *sad, const char *name, const uint32_t socket_id) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  sad_t ctx = NULL;

  if (unlikely(sad == NULL)) {
    lagopus_msg_error("sad %s is NULL\n", name);
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    goto done;
  }

  /* Create SA array table */
  ctx = (sad_t )lagopus_malloc_on_numanode(sizeof(struct sa_ctx), socket_id);
  if (unlikely(ctx == NULL)) {
    lagopus_msg_error("Failed to create SAD\n");
    ret = LAGOPUS_RESULT_NO_MEMORY;
    goto done;
  }
  lagopus_msg_debug(1000, "created SAD %s %p\n", name, ctx);

  // initalize
  memset(ctx->sadb, 0, 2 * sizeof(struct ipsec_sadb));
  memset(ctx->lifetime, 0,
         IPSEC_SA_MAX_ENTRIES * sizeof(struct ipsec_sa_lifetime));
  memset(ctx->acquire, 0, IPSEC_SA_MAX_ENTRIES * sizeof(struct sadb_acquire));
  memset((void *)(ctx->session_ctx), 0, sizeof(ctx->session_ctx));
  ctx->current = 0;
  rte_atomic16_init(&SAD_CURRENT(ctx).refs);
  rte_atomic16_init(&SAD_MODIFIED(ctx).refs);
  rte_atomic64_init(&ctx->seq);

  ret = LAGOPUS_RESULT_OK;
  *sad = ctx;

done:
  return ret;
}

// called once per packet
static inline void
s_single_inbound_lookup(const sad_t sad,
                        const struct rte_mbuf *pkt,
                        size_t *ret,
                        ipsec_sa_t *ret_sa) {
  struct esp_hdr *esp;
  struct ip *ip;
  uint32_t *src4_addr;
  uint8_t *src6_addr;
  ipsec_sa_t sa;
  uint32_t sa_idx;

  *ret = 0;
  *ret_sa = NULL;

  ip = rte_pktmbuf_mtod(pkt, struct ip *);
  if (ip->ip_v == IPVERSION) {
    esp = (struct esp_hdr *)(ip + 1);
  } else {
    esp = (struct esp_hdr *)(((struct ip6_hdr *)ip) + 1);
  }

  if (unlikely(esp->spi == INVALID_SPI)) {
    lagopus_msg_warning("Not found(invalid spi) spi:%u\n", esp->spi);
    return;
  }

  sa_idx = SPI2IDX(rte_be_to_cpu_32(esp->spi));
  sa = &SAD_CURRENT(sad).db[sa_idx];
  if (unlikely(rte_be_to_cpu_32(esp->spi) != sa->spi)) {
    lagopus_msg_warning("Not found(spi not match) esp-spi:%u, sa-spi:%u\n",
                        rte_be_to_cpu_32(esp->spi), sa->spi);
    return;
  }

  switch (sa->flags) {
    case IP4_TUNNEL:
      src4_addr = RTE_PTR_ADD(ip, offsetof(struct ip, ip_src));
      if (likely((ip->ip_v == IPVERSION) &&
                 (sa->src.ip.ip4 == *src4_addr) &&
                 (sa->dst.ip.ip4 == *(src4_addr + 1)))) {
        *ret = sa_idx;
        *ret_sa = sa;
      } else {
        lagopus_msg_warning("Not found(ip4 not match)\n");
      }
      break;
    case IP6_TUNNEL:
      src6_addr = RTE_PTR_ADD(ip, offsetof(struct ip6_hdr, ip6_src));
      if (likely((ip->ip_v == IP6_VERSION) &&
                 !memcmp(&sa->src.ip.ip6.ip6, src6_addr, 16) &&
                 !memcmp(&sa->dst.ip.ip6.ip6, src6_addr + 16, 16))) {
        *ret = sa_idx;
        *ret_sa = sa;
      } else {
        lagopus_msg_warning("Not found(ip6 not match)\n");
      }
      break;
    case TRANSPORT:
      *ret = sa_idx;
      *ret_sa = sa;
  }
}

// called once per packet
static inline void
s_update_sa_atomically(sad_t sad,
                       const size_t sa_idx,
                       const lagopus_chrono_t now,
                       const uint64_t inc_bytes) {
  sad->lifetime[sa_idx].time_current = now;
  sad->lifetime[sa_idx].byte_current += inc_bytes;
  mbar();
  lagopus_msg_debug(1, "update SA[%lu]: current life time: %ld, byte: %lu\n",
                    sa_idx,
                    sad->lifetime[sa_idx].time_current,
                    sad->lifetime[sa_idx].byte_current);
}

// called once per packet unlikely
static inline lagopus_result_t
s_sadb_acquire(sad_t sad, size_t sa_idx, const struct rte_mbuf *pkt) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  uint32_t *src4, *dst4;
  uint8_t *src6, *dst6;
  struct ip *ip = rte_pktmbuf_mtod(pkt, struct ip *);
  struct sadb_acquire acquire;
  struct ipsec_mbuf_metadata *priv;

  if (likely(sad != NULL && pkt != NULL)) {
    acquire.ip_ver = ip->ip_v;
    priv = get_priv((struct rte_mbuf *) pkt);

    acquire.sp_entry_id = priv->sp_entry_id;
    if (ip->ip_v == IPVERSION) { // IPv4
      src4 = RTE_PTR_ADD(ip, offsetof(struct ip, ip_src));
      dst4 = src4 + 1;
      acquire.src.ip.ip4 = *src4;
      acquire.dst.ip.ip4 = *dst4;
    } else { // IPv6
      src6 = RTE_PTR_ADD(ip, offsetof(struct ip6_hdr, ip6_src));
      dst6 = src6 + 16;
      memcpy(&acquire.src.ip.ip6.ip6_b, src6, 16);
      memcpy(&acquire.dst.ip.ip6.ip6_b, dst6, 16);
    }
    lagopus_msg_debug(100, "sadb_acquire IPv%u\n", acquire.ip_ver);
    sad->acquire[sa_idx] = acquire;
    mbar();

    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    lagopus_perror(ret);
  }

  return ret;
}

/* public. */

// called when initialize
lagopus_result_t
sad_init(sad_t *sad, const uint32_t socket_id,
         const ipsecvsw_queue_role_t role) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  const char *name = (role == ipsecvsw_queue_role_inbound) ? "sa_in" : "sa_out";
  if (likely(sad != NULL)) {
    if (likely(role == ipsecvsw_queue_role_inbound
               || role == ipsecvsw_queue_role_outbound)) {
      lagopus_msg_debug(1000, "%s for socket %u initialize\n", name, socket_id);

      // if not using rte_memzone_reserve, 'name' and 'socket_id' is not needed.
      ret = s_sad_create(sad, name, socket_id);
      if (likely(ret == LAGOPUS_RESULT_OK)) {
        lagopus_msg_debug(1000, "%s created. %p\n", name, *sad);
      } else {
        lagopus_msg_error("Fail to create %s for socket %u\n", name, socket_id);
        ret = LAGOPUS_RESULT_NO_MEMORY;
      }
    } else {
      lagopus_msg_error("invalid role %u\n", role);
      ret = LAGOPUS_RESULT_INVALID_ARGS;
    }
  } else {
    lagopus_msg_error("sad is NULL\n");
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}

// called when finalize
void
sad_finalize(sad_t sad,
             const ipsecvsw_queue_role_t role,
             const pthread_t tid,
             ipsecvsw_session_gc_ctx_t gctx) {
  if (likely(sad != NULL)) {
    s_sad_t_detach_all(sad, role, tid, gctx);
    lagopus_free_on_numanode(sad);
    sad = NULL;
  }
}

// called once per some packets
lagopus_result_t
sad_pre_process(sad_t sad,
                const ipsecvsw_queue_role_t role,
                const pthread_t tid,
                ipsecvsw_session_gc_ctx_t gctx) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  if (likely(sad != NULL)) {
    // switch.
    sad->current = (uint64_t) rte_atomic64_read(&sad->seq) % 2;
    // set referenced.
    rte_atomic16_inc(&SAD_CURRENT(sad).refs);

    // detach if needed
    for (size_t i = 0; i < IPSEC_SA_MAX_ENTRIES; i++) {
      if (likely(sad->session_ctx[i] != NULL)) {
        if (unlikely((SAD_CURRENT(sad).db[i].spi == INVALID_SPI) ||
                     (SAD_CURRENT(sad).db[i].hash != sad->session_ctx[i]->m_sa.hash))) {
          lagopus_msg_debug(1, "detach SA[%lu](%u) %p\n",
                            i, SAD_CURRENT(sad).db[i].spi, sad->session_ctx[i]);
          s_dispose_session(tid, role, sad->session_ctx[i], gctx);
          sad->session_ctx[i] = NULL;
          sad->lifetime[i].time_current = 0;
          sad->lifetime[i].byte_current = 0;
        }
      }
    }

    ret = LAGOPUS_RESULT_OK;
  } else {
    lagopus_msg_error("sad is NULL\n");
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}

// called once per some packets
lagopus_result_t
sad_post_process(sad_t sad) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  if (likely(sad != NULL)) {
    // unset referenced.
    rte_atomic16_dec(&SAD_CURRENT(sad).refs);
    ret = LAGOPUS_RESULT_OK;
  } else {
    lagopus_msg_error("sad is NULL\n");
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}

// called by go-plane
lagopus_result_t
sad_push(sad_t sad,
         const struct ipsec_sa entries[],
         const size_t nb_entries,
         const ipsecvsw_queue_role_t role) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  ipsec_sa_t sa = NULL;
  uint32_t idx = 0;
  uint16_t iv_length;
  uint64_t next_modified;
  char sa_str[SA_DEBUG_PRINT_LEN] = "";
  bool do_dbg = (lagopus_log_get_debug_level() >= 50) ? true : false;

  if (likely(sad != NULL)) {
    next_modified = (uint64_t) (rte_atomic64_read(&sad->seq) + 1) % 2;
    if (rte_atomic16_read(&SAD_GET_DB(sad, next_modified).refs) == 0) {
      // reset sadb.
      memset(&SAD_GET_DB(sad, next_modified), 0, sizeof(struct ipsec_sadb));

      for (size_t i = 0; i < nb_entries; i++) {
        idx = SPI2IDX(entries[i].spi);
        sa = &SAD_GET_DB(sad, next_modified).db[idx]; /* insert to next SAD */
        *sa = entries[i];

        switch (sa->flags) {
          case IP4_TUNNEL:
            sa->src.ip.ip4 = rte_cpu_to_be_32(sa->src.ip.ip4);
            sa->dst.ip.ip4 = rte_cpu_to_be_32(sa->dst.ip.ip4);
        }

        if (unlikely(do_dbg == true)) {
          s_format_sa(sa_str, sa, SA_DEBUG_PRINT_LEN);
          lagopus_msg_debug(50, "push(%lu/%lu) SAD(%p) SA[%3d] %s %p\n",
                            i + 1, nb_entries, sad, idx, sa_str, sad->session_ctx[idx]);
        }
      }
      lagopus_msg_debug(1, "Updated SAD(%p), %lu entries.\n", sad, nb_entries);

      rte_atomic64_inc(&sad->seq);
    }
    ret = LAGOPUS_RESULT_OK;
  } else {
    lagopus_msg_error("sad is NULL\n");
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}

// called by go-plane
lagopus_result_t
sad_get_acquires(sad_t sad, struct sadb_acquire *buf) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(sad != NULL && buf != NULL)) {
    // copy.
    memcpy(buf, &sad->acquire, IPSEC_SA_MAX_ENTRIES * sizeof(struct sadb_acquire));
    // reset.
    memset(&sad->acquire, 0, IPSEC_SA_MAX_ENTRIES * sizeof(struct sadb_acquire));
    mbar();
    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    lagopus_perror(ret);
  }
  return ret;
}

// called once per packet
bool
inbound_sa_check(const sad_t sad,
                 const struct rte_mbuf *m,
                 const uint32_t sa_idx) {
  struct ipsec_mbuf_metadata *priv;
  ipsecvsw_session_ctx_t ctx;

  priv = get_priv((struct rte_mbuf *) m);
  if (likely((ctx = priv->session_ctx) != NULL)) {
    return (SAD_CURRENT(sad).db[sa_idx].spi == ctx->m_sa.spi);
  } else {
    return false;
  }
}


// called once per some packets
void
inbound_sa_lookup(const pthread_t tid,
                  sad_t sad,
                  const struct rte_mbuf *pkts[],
                  const size_t nb_pkts,
                  const lagopus_chrono_t now,
                  ipsecvsw_session_ctx_t sctx[]) {
  char sa_str[SA_DEBUG_PRINT_LEN];
  bool do_dbg = (lagopus_log_get_debug_level() >= 10) ? true : false;
  size_t sa_idx;
  ipsec_sa_t sa;

  for (size_t i = 0; i < nb_pkts; i++) {
    // lookup
    s_single_inbound_lookup(sad, pkts[i], &sa_idx, &sa);
    if (likely(sa != NULL && sa->spi != INVALID_SPI)) {
      if (likely(sad->session_ctx[sa_idx] != NULL)) {
        sctx[i] = sad->session_ctx[sa_idx];
      } else {
        sctx[i] = sad->session_ctx[sa_idx] =
                    s_create_session(tid, ipsecvsw_queue_role_inbound,
                                     &SAD_CURRENT(sad).db[sa_idx]);
        if (unlikely(sctx[i] == NULL)) {
          lagopus_msg_error("can't attach cdev queue/session for an inbound "
                            "SA[" PFSZ(u) "].\n",
                            sa_idx);
        }
      }
      // update lifetime
      if (likely(sctx[i] != NULL)) {
        s_update_sa_atomically(sad, sa_idx, now, pkts[i]->data_len); // pkt_len?
      }
      // debug
      if (unlikely(do_dbg == true)) {
        s_format_sa(sa_str, sa, SA_DEBUG_PRINT_LEN);
        lagopus_msg_debug(10, "inbound SAD(%p) lookup(%lu/%lu)[%lu]\t%s %p\n",
                          sad, i + 1, nb_pkts, sa_idx, sa_str, sctx[i]);
      }
    } else {
      sctx[i] = NULL;
      // memo: SADB_ACQUIRE is triggered by outbound packet only.
      lagopus_msg_warning("inbound SAD(%p) lookup(%lu/%lu) Not found\n",
                          sad, i + 1, nb_pkts);
    }
  }
}

// called once per some packets
void
outbound_sa_lookup(const pthread_t tid,
                   sad_t sad,
                   const uint32_t sa_idxes[],
                   const struct rte_mbuf *pkts[],
                   const size_t nb_pkts,
                   const lagopus_chrono_t now,
                   ipsecvsw_session_ctx_t sctx[]) {
  char sa_str[SA_DEBUG_PRINT_LEN];
  bool do_dbg = (lagopus_log_get_debug_level() >= 10) ? true : false;
  size_t sa_idx;
  ipsec_sa_t sa;

  for (size_t i = 0; i < nb_pkts; i++) {
    // lookup
    sa_idx = sa_idxes[i];
    sa = &SAD_CURRENT(sad).db[sa_idx];
    if (likely(sa != NULL && sa->spi != INVALID_SPI)) {
      if (likely(sad->session_ctx[sa_idx] != NULL)) {
        sctx[i] = sad->session_ctx[sa_idx];
      } else {
        sctx[i] = sad->session_ctx[sa_idx] =
                    s_create_session(tid, ipsecvsw_queue_role_outbound, sa);
        if (unlikely(sctx[i] == NULL)) {
          lagopus_msg_error("can't attach cdev queue/session for an outbound "
                            "SA[" PFSZ(u) "].\n",
                            sa_idx);
        }
      }
      // update lifetime
      if (likely(sctx[i] != NULL)) {
        s_update_sa_atomically(sad, sa_idx, now, pkts[i]->data_len); // pkt_len?
      }
      // debug
      if (unlikely(do_dbg == true)) {
        s_format_sa(sa_str, sa, SA_DEBUG_PRINT_LEN);
        lagopus_msg_debug(10, "outbound SAD(%p) lookup(%lu/%lu)[%lu]\t%s %p\n",
                          sad, i + 1, nb_pkts, sa_idx, sa_str, sctx[i]);
      }
    } else {
      sctx[i] = NULL;
      (void) s_sadb_acquire(sad, sa_idx, pkts[i]);
      lagopus_msg_warning("outbound SAD(%p) lookup(%lu/%lu)[" PFSZ(u)
                          "] Not found\n",
                          sad, i + 1, nb_pkts, sa_idx);
    }
  }
}
