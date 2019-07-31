/*
 * Copyright 2018-2019 Nippon Telegraph and Telephone Corporation.
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

#include "lagopus_apis.h"
#include "ipsec.h"
#include "ipsecvsw.h"
#include "dpdk_glue.h"





static inline void
s_lock_gc(ipsecvsw_session_gc_ctx_t gctx) {
  if (likely(gctx != NULL)) {
    rte_spinlock_lock(&(gctx->m_gc_lock));
  }
}


static inline void
s_unlock_gc(ipsecvsw_session_gc_ctx_t gctx) {
  if (likely(gctx != NULL)) {
    rte_spinlock_unlock(&(gctx->m_gc_lock));
  }
}





static inline void
s_init_session_gc_ctx(pthread_t tid, ipsecvsw_session_gc_ctx_t gctx) {
  if (likely(tid != LAGOPUS_INVALID_THREAD &&
             gctx != NULL)) {
    gctx->m_tid = tid;
    rte_spinlock_init(&(gctx->m_gc_lock));
    TAILQ_INIT(&(gctx->m_gc_list));
  }
}





static inline ipsecvsw_session_ctx_t
s_create_session_ctx(pthread_t tid,
                     ipsec_sa_t sa,
                     ipsecvsw_queue_role_t role,
                     ipsecvsw_cdevq_t q,
                     ipsecvsw_session_ctx_t *ctx_ptr) {
  ipsecvsw_session_ctx_t ret = NULL;
  uint16_t iv_length;
  uint16_t q_id;
  struct rte_cryptodev_info cdev_info;
  struct rte_mempool *session_pool;

  if (likely(sa != NULL &&
             q != NULL &&
             ctx_ptr != NULL && *ctx_ptr == NULL)) {
    if (unlikely((q_id = ipsecvsw_cdevq_get_queue_id(q)) < 0)) {
      *ctx_ptr = NULL;
      return ret;
    }
    if (unlikely((ipsecvsw_cdevq_get_session_pool(q, &session_pool) !=
                  LAGOPUS_RESULT_OK))) {
      *ctx_ptr = NULL;
      return ret;
    }

    ret = (ipsecvsw_session_ctx_t)lagopus_malloc_on_numanode(
            sizeof(*ret),
            (unsigned int)ipsecvsw_cdevq_get_numanode(q));
    if (likely(ret != NULL)) {
      /*
       * Deep-copy the SA.
       */
      (void)memcpy((void *)&(ret->m_sa), (void *)sa, sizeof(*sa));

      if (ret->m_sa.aead_algo == RTE_CRYPTO_AEAD_AES_GCM) {
        iv_length = AEAD_AES_GCM_IV_LENGTH;
        ret->a.type = RTE_CRYPTO_SYM_XFORM_AEAD;
        ret->a.aead.algo = ret->m_sa.aead_algo;
        ret->a.aead.key.data = ret->m_sa.cipher_key;
        ret->a.aead.key.length =
          ret->m_sa.cipher_key_len;
        ret->a.aead.op = (role == ipsecvsw_queue_role_inbound) ?
                         RTE_CRYPTO_AEAD_OP_DECRYPT :
                         RTE_CRYPTO_AEAD_OP_ENCRYPT;
        ret->a.next = NULL;
        ret->a.aead.iv.offset = IV_OFFSET;
        ret->a.aead.iv.length = iv_length;
        ret->a.aead.aad_length =
          ret->m_sa.aad_len;
        ret->a.aead.digest_length =
          ret->m_sa.digest_len;
        ret->m_sa.xforms = &(ret->a);
      } else {
        switch (ret->m_sa.cipher_algo) {
          case RTE_CRYPTO_CIPHER_NULL:
          case RTE_CRYPTO_CIPHER_3DES_CBC:
          case RTE_CRYPTO_CIPHER_AES_CBC:
            iv_length = ret->m_sa.iv_len;
            break;
          case RTE_CRYPTO_CIPHER_AES_CTR:
            iv_length = CIPHER_AES_CTR_IV_LENGTH;
            break;
          default:
            TUNNEL_FATAL("must not happen.");
            break;
        }

        switch (role) {
          case ipsecvsw_queue_role_inbound: {
            ret->b.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
            ret->b.cipher.algo = ret->m_sa.cipher_algo;
            ret->b.cipher.key.data = ret->m_sa.cipher_key;
            ret->b.cipher.key.length = ret->m_sa.cipher_key_len;
            ret->b.cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
            ret->b.next = NULL;
            ret->b.cipher.iv.offset = IV_OFFSET;
            ret->b.cipher.iv.length = iv_length;

            ret->a.type = RTE_CRYPTO_SYM_XFORM_AUTH;
            ret->a.auth.algo = ret->m_sa.auth_algo;
            ret->a.auth.key.data = ret->m_sa.auth_key;
            ret->a.auth.key.length = ret->m_sa.auth_key_len;
            ret->a.auth.digest_length = ret->m_sa.digest_len;
            ret->a.auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;
            break;
          }
          case ipsecvsw_queue_role_outbound: {
            ret->a.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
            ret->a.cipher.algo = ret->m_sa.cipher_algo;
            ret->a.cipher.key.data = ret->m_sa.cipher_key;
            ret->a.cipher.key.length = ret->m_sa.cipher_key_len;
            ret->a.cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
            ret->a.next = NULL;
            ret->a.cipher.iv.offset = IV_OFFSET;
            ret->a.cipher.iv.length = iv_length;

            ret->b.type = RTE_CRYPTO_SYM_XFORM_AUTH;
            ret->b.auth.algo = ret->m_sa.auth_algo;
            ret->b.auth.key.data = ret->m_sa.auth_key;
            ret->b.auth.key.length = ret->m_sa.auth_key_len;
            ret->b.auth.digest_length = ret->m_sa.digest_len;
            ret->b.auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;
            break;
          }
          default:
            TUNNEL_FATAL("must not happen.");
            break;
        }
        ret->a.next = &(ret->b);
        ret->b.next = NULL;
        ret->m_sa.xforms = &(ret->a);
      }
      ret->m_ref_cnt = 0;
      ret->m_tid = tid;
      ret->m_dev_id = (uint8_t)ipsecvsw_cdevq_get_dev_id(q);
      ret->m_role = role;
      ret->m_q = q;
      ret->m_session = rte_cryptodev_sym_session_create(session_pool);
      *ctx_ptr = ret;
      if (likely(ret->m_session != NULL)) {
        if (likely(rte_cryptodev_sym_session_init(ret->m_dev_id,
                   ret->m_session, ret->m_sa.xforms,
                   session_pool) == 0)) {
          rte_cryptodev_info_get(ret->m_dev_id,
                                 &cdev_info);
          cryptodev_attach_sym_session(&cdev_info, q_id, ctx_ptr);
        } else {
          lagopus_free_on_numanode((void *)ret);
          *ctx_ptr = NULL;
        }
      } else {
        lagopus_free_on_numanode((void *)ret);
        *ctx_ptr = NULL;
      }
    }
  }

  return ret;
}


static inline ipsecvsw_session_ctx_t
s_destroy_session_ctx(ipsecvsw_session_ctx_t ctx) {
  ipsecvsw_session_ctx_t ret = NULL;
  lagopus_result_t r;
  struct rte_cryptodev_info cdev_info;

  if (likely(ctx != NULL &&
             __sync_add_and_fetch(&(ctx->m_ref_cnt), 0) == 0)) {
    if (ctx->m_session != NULL) {
      rte_cryptodev_info_get(ctx->m_dev_id,
                             &cdev_info);

      cryptodev_detach_sym_session(&cdev_info, ctx);
      (void)rte_cryptodev_sym_session_free(ctx->m_session);
      ctx->m_session = NULL;
    }
    if (ctx->m_q != NULL) {
      r = ipsecvsw_release_cdevq_for_put(ctx->m_tid, ctx->m_role, ctx->m_q);
      if (likely(r == LAGOPUS_RESULT_OK)) {
        lagopus_free_on_numanode((void *)ctx);
        ret = ctx;
      } else {
        TUNNEL_PERROR(r);
        TUNNEL_WARNING("can't release cdevq.");
      }
    }
  }

  return ret;
}


static inline lagopus_result_t
s_dispose_session_ctx(ipsecvsw_session_ctx_t ctx,
                      ipsecvsw_session_gc_ctx_t gctx) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(ctx != NULL && gctx != NULL)) {

    s_lock_gc(gctx);
    {
      TAILQ_INSERT_TAIL(&(gctx->m_gc_list), ctx, m_elem);
    }
    s_unlock_gc(gctx);

    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}


static inline void
s_gc_session_ctx(pthread_t tid, ipsecvsw_session_gc_ctx_t gctx) {
  ipsecvsw_session_ctx_t ctx;
  ipsecvsw_session_ctx_t next;

  if (likely(gctx != NULL &&
             tid != LAGOPUS_INVALID_THREAD)) {

    s_lock_gc(gctx);
    {
      ctx = TAILQ_FIRST(&(gctx->m_gc_list));
      while (ctx != NULL) {
        next = TAILQ_NEXT(ctx, m_elem);
        if (__sync_add_and_fetch(&(ctx->m_ref_cnt), 0) == 0 &&
            tid == ctx->m_tid) {
          TAILQ_REMOVE(&(gctx->m_gc_list), ctx, m_elem);
          s_destroy_session_ctx(ctx);
        }
        ctx = next;
      }
    }
    s_unlock_gc(gctx);

  }
}





void
ipsecvsw_session_gc_initialize(pthread_t tid,
                               ipsecvsw_session_gc_ctx_t gctx) {
  s_init_session_gc_ctx(tid, gctx);
}


lagopus_result_t
ipsecvsw_create_session_ctx_body(pthread_t tid,
                                 ipsec_sa_t sa,
                                 ipsecvsw_queue_role_t role,
                                 ipsecvsw_cdevq_t q,
                                 ipsecvsw_session_ctx_t *ctx_ptr) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(sa != NULL)) {
    if (likely(s_create_session_ctx(tid, sa, role, q, ctx_ptr) != NULL)) {
      ret = LAGOPUS_RESULT_OK;
    } else {
      ret = LAGOPUS_RESULT_NO_MEMORY;
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}


lagopus_result_t
ipsecvsw_dispose_session_ctx_body(ipsecvsw_session_ctx_t ctx,
                                  ipsecvsw_session_gc_ctx_t gctx) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(ctx != NULL)) {
    ret = s_dispose_session_ctx(ctx, gctx);
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}


void
ipsecvsw_session_ctx_gc(pthread_t tid, ipsecvsw_session_gc_ctx_t gctx) {
  s_gc_session_ctx(tid, gctx);
}
