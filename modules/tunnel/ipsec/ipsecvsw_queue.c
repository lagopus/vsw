/*
 * Copyright 2018 Nippon Telegraph and Telephone Corporation.
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
#include "sa.h"
#include "hash.h"
#include "ipsecvsw.h"




typedef struct rte_cryptodev_info *rte_cryptodev_info_t;
struct cdevq_list_record;


typedef struct ipsecvsw_q_record {
  rte_spinlock_t m_lock;

  pthread_t m_put_tid;
  pthread_t m_get_tid;
  size_t m_n_put_ref;	/* must be equivalent to a # of SAs to be
                         * handled in this Q. */

  const char const m_dev_name[32];
  int m_numa_node;
  uint8_t m_dev_id;
  uint16_t m_q_id;

  rte_cop_t *m_q_put_entries;	/* must be allocated on the
                                 * m_numa_node. */
  rte_cop_t *m_q_get_entries;	/* must be allocated on the
                                 * m_numa_node. */
  size_t m_n_max_entries;

  size_t m_n_cur_entries;

  bool m_is_accelerator;	/* true if the m_dev_id is H/W. */
  uint32_t m_cipher_capa;
  uint32_t m_auth_capa;
  uint32_t m_aead_capa;

  struct rte_mempool *session_pool;
} ipsecvsw_q_record;
#define cdevq_priority(cdevq)                                           \
  ((uint32_t)(((cdevq->m_is_accelerator == false) ? 0 : (1 << 24)) |    \
              (uint32_t)(cdevq->m_dev_id << 16) |                       \
              (uint32_t)(cdevq->m_q_id)))

typedef struct cdevq_list_record {
  rte_crypto_cipher_t m_cipher;
  rte_crypto_auth_t m_auth;
  rte_crypto_aead_t m_aead;
  bool m_is_fully_occupied;

  ipsecvsw_cdevq_t *m_qs;
  size_t m_n_qs;
} cdevq_list_record;
typedef struct cdevq_list_record *cdevq_list_t;

/*
 * Per-thread cdevq list
 */
typedef struct cdevq_elem_record {
  TAILQ_ENTRY(cdevq_elem_record) m_elem;
  ipsecvsw_cdevq_t m_q;
} cdevq_elem_record;
typedef struct cdevq_elem_record *cdevq_elem_t;

TAILQ_HEAD(cdevq_per_thread_list_record, cdevq_elem_record);
typedef struct cdevq_per_thread_list_record cdevq_per_thread_list_t;

typedef struct cdevq_per_thread_record {
  cdevq_per_thread_list_t m_list;
  ipsecvsw_cdevq_t m_qs[CDEVQ_MAX_QUEUES_PER_THD];
  pthread_t m_tid;
  ipsecvsw_queue_role_t m_role;
  size_t m_n_qs;
  size_t m_mru_q_idx;
} cdevq_per_thread_record;
typedef struct cdevq_per_thread_record *cdevq_per_thread_t;





static rte_spinlock_t s_sched_lock;

static lagopus_hashmap_t s_inbound_q_tbl = NULL;
static lagopus_hashmap_t s_outbound_q_tbl = NULL;

static ipsecvsw_cdevq_t *s_inbound_qs = NULL;
static size_t s_n_inbound_qs = 0;
static ipsecvsw_cdevq_t *s_outbound_qs = NULL;
static size_t s_n_outbound_qs = 0;

static lagopus_hashmap_t s_inbound_thd_q_tbl = NULL;
static lagopus_hashmap_t s_outbound_thd_q_tbl = NULL;




static inline const char *
s_get_driver_enum_string(uint8_t dev_id) {
  const char *ret = NULL;

  if ((ret = rte_cryptodev_name_get(dev_id)) != NULL) {
    return ret;
  } else {
    return "unknown";
  }
}

static inline const char *
s_get_cipher_enum_string(rte_crypto_cipher_t c) {
  if (UNKNOWN_ALGORITHM != c && c < RTE_CRYPTO_CIPHER_LIST_END) {
    return rte_crypto_cipher_algorithm_strings[c];
  } else {
    return "unknown";
  }
}


static inline const char *
s_get_auth_enum_string(rte_crypto_auth_t a) {
  if (UNKNOWN_ALGORITHM != a && a < RTE_CRYPTO_AUTH_LIST_END) {
    return rte_crypto_auth_algorithm_strings[a];
  } else {
    return "unknown";
  }
}

static inline const char *
s_get_aead_enum_string(rte_crypto_aead_t a) {
  if (UNKNOWN_ALGORITHM != a && a < RTE_CRYPTO_AUTH_LIST_END) {
    return rte_crypto_aead_algorithm_strings[a];
  } else {
    return "unknown";
  }
}


static inline void
s_dump_cdevq(ipsecvsw_cdevq_t q) {
  if (likely(q != NULL)) {
    lagopus_msg_debug(2, "\tcdev id %u, q id %u, qlen " PFSZ(u)
                      ", device \"%s\"\n",
                      q->m_dev_id, q->m_q_id, q->m_n_max_entries,
                      q->m_dev_name);
  } else {
    lagopus_msg_debug(1, "trying to dump NULL cdevq.\n");
  }
}


static inline void
s_dump_cdevq_array(ipsecvsw_cdevq_t *qs, size_t n_qs) {
  if (likely(qs != NULL && n_qs > 0)) {
    size_t i;
    for (i = 0; i < n_qs; i++) {
      s_dump_cdevq(qs[i]);
    }
  } else {
    lagopus_msg_debug(1, "trying to dump NULL cdevq array.\n");
  }
}


static inline void
s_dump_cdevq_list(cdevq_list_t l) {
  if (likely(l != NULL &&
             l->m_qs != NULL && l->m_n_qs > 0)) {
    if (l->m_aead == UNKNOWN_ALGORITHM) {
      /* cipher/auth algos. */
      lagopus_msg_debug(1, "cdevq list: cipher %s, auth %s, # of qs " PFSZ(u)
                        " :\n",
                        s_get_cipher_enum_string(l->m_cipher),
                        s_get_auth_enum_string(l->m_auth),
                        l->m_n_qs);
    } else {
      /* aead algos. */
      lagopus_msg_debug(1, "cdevq list: aead %s, # of qs " PFSZ(u)
                        " :\n",
                        s_get_aead_enum_string(l->m_aead),
                        l->m_n_qs);
    }
    s_dump_cdevq_array(l->m_qs, l->m_n_qs);
  } else {
    lagopus_msg_debug(1, "trying to dump NULL cdevq.\n");
  }
}





static inline cdevq_list_t
s_create_cdevq_list(rte_crypto_cipher_t cipher,
                    rte_crypto_auth_t auth,
                    rte_crypto_auth_t aead) {
  cdevq_list_t ret = (cdevq_list_t)malloc(sizeof(*ret));
  if (likely(ret != NULL)) {

    ret->m_cipher = cipher;
    ret->m_auth = auth;
    ret->m_aead = aead;
    ret->m_is_fully_occupied = false;

    ret->m_qs = NULL;
    ret->m_n_qs = 0;
  }
  return ret;
}


static inline void
s_destroy_cdevq_list(cdevq_list_t l) {
  if (likely(l != NULL)) {
    free((void *)l->m_qs);
    free((void *)l);
  }
}


static inline size_t
s_add_cdevq_to_list(cdevq_list_t l, ipsecvsw_cdevq_t q) {
  size_t ret = 0;

  if (likely(l != NULL && q != NULL)) {
    if (l->m_qs == NULL && l->m_n_qs == 0) {
      l->m_qs = (ipsecvsw_cdevq_t *)malloc(sizeof(ipsecvsw_cdevq_t));
    } else {
      l->m_qs = (ipsecvsw_cdevq_t *)realloc((void *)(l->m_qs),
                                            sizeof(ipsecvsw_cdevq_t) *
                                            (l->m_n_qs + 1));
    }
    if (l->m_qs != NULL) {
      l->m_qs[l->m_n_qs] = q;
      l->m_n_qs++;
      ret = l->m_n_qs;
    }
  }

  return ret;
}





static inline cdevq_per_thread_t
s_create_cdevq_per_thread(pthread_t tid, ipsecvsw_queue_role_t role) {
  cdevq_per_thread_t ret = NULL;

  if (likely(tid != LAGOPUS_INVALID_THREAD &&
             role != ipsecvsw_queue_role_unknown)) {
    ret = (cdevq_per_thread_t)malloc(sizeof(*ret));
    if (ret != NULL) {
      TAILQ_INIT(&(ret->m_list));
      (void)memset((void *)(ret->m_qs), 0,
                   sizeof(ipsecvsw_cdevq_t) * CDEVQ_MAX_QUEUES_PER_THD);
      ret->m_tid = tid;
      ret->m_role = role;
      ret->m_n_qs = 0;
      ret->m_mru_q_idx = 0;
    }
  }

  return ret;
}


static inline void
s_destroy_cdevq_per_thread(cdevq_per_thread_t p) {
  if (likely(p != NULL)) {
    cdevq_per_thread_list_t *l = NULL;
    if (p->m_n_qs != 0 &&
        (l = &(p->m_list)) != NULL) {
      cdevq_elem_t e;
      while (!TAILQ_EMPTY(l)) {
        e = TAILQ_FIRST(l);
        TAILQ_REMOVE(l, e, m_elem);
        free((void *)e);
      }
    }
    free((void *)p);
  }
}


static inline cdevq_per_thread_t
s_get_cdevq_per_thread(pthread_t tid, ipsecvsw_queue_role_t role) {
  cdevq_per_thread_t ret = NULL;

  if (likely(tid != LAGOPUS_INVALID_THREAD &&
             role != ipsecvsw_queue_role_unknown)) {
    cdevq_per_thread_t tmp = NULL;
    lagopus_hashmap_t *h = (role == ipsecvsw_queue_role_inbound) ?
                           &s_inbound_thd_q_tbl : &s_outbound_thd_q_tbl;
    lagopus_result_t r;
    pthread_t key = tid;

    if ((r = lagopus_hashmap_find(h, (void *)key, (void **)&tmp)) ==
        LAGOPUS_RESULT_OK &&
        tmp != NULL) {
      ret = tmp;
    } else {
      void *val;
      tmp = s_create_cdevq_per_thread(tid, role);
      val = (void *)tmp;
      if (likely(tmp != NULL &&
                 (r = lagopus_hashmap_add(h, (void *)key, &val, false)) ==
                 LAGOPUS_RESULT_OK)) {
        ret = tmp;
      } else {
        if (tmp != NULL) {
          s_destroy_cdevq_per_thread(tmp);
        }
      }
    }
  }

  return ret;
}


static inline size_t
s_add_cdevq_to_thread(pthread_t tid, ipsecvsw_queue_role_t role,
                      ipsecvsw_cdevq_t q) {
  size_t ret = 0;

  cdevq_per_thread_t l = s_get_cdevq_per_thread(tid, role);
  if (likely(l != NULL)) {
    cdevq_elem_t e;
    bool found = false;

    TAILQ_FOREACH(e, &(l->m_list), m_elem) {
      if (e->m_q == q) {
        found = true;
        break;
      }
    }

    if (found == false) {
      if (likely(l->m_n_qs < CDEVQ_MAX_QUEUES_PER_THD)) {
        size_t i = 0;

        e = (cdevq_elem_t)malloc(sizeof(*e));
        if (likely(e != NULL)) {
          e->m_q = q;
          TAILQ_INSERT_TAIL(&(l->m_list), e, m_elem);
          l->m_n_qs++;
          ret = l->m_n_qs;
        }

        TAILQ_FOREACH(e, &(l->m_list), m_elem) {
          l->m_qs[i++] = e->m_q;
        }
      }

    } else {
      ret = l->m_n_qs;
    }
  }

  return ret;
}


static inline size_t
s_del_cdevq_from_thread(pthread_t tid, ipsecvsw_queue_role_t role,
                        ipsecvsw_cdevq_t q) {
  size_t ret = 0;

  cdevq_per_thread_t l = s_get_cdevq_per_thread(tid, role);
  if (likely(l != NULL)) {
    cdevq_elem_t e;
    bool found = false;

    TAILQ_FOREACH(e, &(l->m_list), m_elem) {
      if (e->m_q == q) {
        found = true;
        break;
      }
    }
    if (found == true) {
      size_t i = 0;

      TAILQ_REMOVE(&(l->m_list), e, m_elem);
      free((void *)e);
      ret = l->m_n_qs;
      l->m_n_qs--;

      TAILQ_FOREACH(e, &(l->m_list), m_elem) {
        l->m_qs[i++] = e->m_q;
      }
    }
  }

  return ret;
}


static inline uint32_t
s_auth2uint32(rte_crypto_auth_t a) {
  return (uint32_t)(1UL << (uint32_t)a);
}


static inline uint32_t
s_cipher2uint32(rte_crypto_cipher_t c) {
  return (uint32_t)(1UL << (uint32_t)c);
}

static inline uint32_t
s_aead2uint32(rte_crypto_aead_t a) {
  return (uint32_t)(1UL << (uint32_t)a);
}


static inline void
s_lock_cdevq(ipsecvsw_cdevq_t q) {
  if (likely(q != NULL)) {
    rte_spinlock_lock(&(q->m_lock));
  }
}


static inline void
s_unlock_cdevq(ipsecvsw_cdevq_t q) {
  if (likely(q != NULL)) {
    rte_spinlock_unlock(&(q->m_lock));
  }
}


static inline ipsecvsw_cdevq_t
s_create_cdevq(const char *name,
               int numa_node, uint8_t dev_id, uint16_t q_id, uint32_t qlen,
               bool is_hw,
               uint32_t cipher, uint32_t auth, uint32_t aead) {
  ipsecvsw_cdevq_t ret = NULL;

  rte_cop_t *put_buf = (rte_cop_t *)lagopus_malloc_on_numanode(
                         qlen * sizeof(rte_cop_t), (unsigned int)numa_node);
  rte_cop_t *get_buf = (rte_cop_t *)lagopus_malloc_on_numanode(
                         qlen * sizeof(rte_cop_t), (unsigned int)numa_node);
  if (likely(put_buf != NULL && get_buf != NULL)) {
    ret = (ipsecvsw_cdevq_t)lagopus_malloc_on_numanode(
            sizeof(*ret), (unsigned int)numa_node);
    if (likely(ret != NULL)) {
      struct rte_cryptodev_qp_conf qp_conf;
      char mp_name[RTE_MEMPOOL_NAMESIZE];
      uint32_t sess_sz;

      sess_sz = rte_cryptodev_get_private_session_size(dev_id);
      snprintf(mp_name, RTE_MEMPOOL_NAMESIZE,
               "sess_mp_%u_%u_%u", numa_node, dev_id, q_id);
      ret->session_pool = rte_mempool_create(mp_name,
                                             CDEV_MP_NB_OBJS,
                                             sess_sz,
                                             CDEV_MP_CACHE_SZ,
                                             0, NULL, NULL, NULL,
                                             NULL, numa_node,
                                             0);
      if (likely(ret->session_pool != NULL)) {
        rte_spinlock_init(&(ret->m_lock));
        ret->m_put_tid = LAGOPUS_INVALID_THREAD;
        ret->m_get_tid = LAGOPUS_INVALID_THREAD;
        ret->m_n_put_ref = 0;
        snprintf((char *)ret->m_dev_name, sizeof(ret->m_dev_name), "%s", name);
        ret->m_numa_node = numa_node;
        ret->m_dev_id = dev_id;
        ret->m_q_id = q_id;
        ret->m_q_put_entries = put_buf;
        ret->m_q_get_entries = get_buf;
        ret->m_n_max_entries = (size_t)qlen;
        ret->m_is_accelerator = is_hw;
        ret->m_cipher_capa = cipher;
        ret->m_auth_capa = auth;
        ret->m_aead_capa = aead;

        qp_conf.nb_descriptors = qlen;
        if (unlikely(rte_cryptodev_queue_pair_setup(
                       dev_id, q_id, &qp_conf, numa_node, ret->session_pool) != 0)) {
          lagopus_free_on_numanode(put_buf);
          lagopus_free_on_numanode(get_buf);
          rte_mempool_free(ret->session_pool);
          lagopus_free_on_numanode(ret);
          ret = NULL;
        }
      } else {
        lagopus_free_on_numanode(put_buf);
        lagopus_free_on_numanode(get_buf);
        lagopus_free_on_numanode(ret);
        ret = NULL;
      }
    } else {
      lagopus_free_on_numanode(put_buf);
      lagopus_free_on_numanode(get_buf);
    }
  }

  return ret;
}


static inline void
s_destroy_cdevq(ipsecvsw_cdevq_t q) {
  if (likely(q != NULL)) {
    lagopus_free_on_numanode(q->m_q_put_entries);
    lagopus_free_on_numanode(q->m_q_get_entries);
    rte_mempool_free(q->session_pool);
    lagopus_free_on_numanode(q);
  }
}


static inline lagopus_result_t
s_setup_cdev(uint8_t dev_id,
             ipsecvsw_cdevq_t *buf,
             size_t buflen) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  size_t n_qs = 0;
  struct rte_cryptodev_info info;
  const char *driver_name;

  (void)memset((void *)&info, 0, sizeof(info));
  rte_cryptodev_info_get(dev_id, &info);
  driver_name = (IS_VALID_STRING(info.driver_name) == true) ?
                info.driver_name : s_get_driver_enum_string(info.driver_id);

  if (info.feature_flags & RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING) {
    const struct rte_cryptodev_capabilities *cidx, *aidx;
    rte_crypto_cipher_t cipher;
    rte_crypto_auth_t auth;
    rte_crypto_aead_t aead;
    uint32_t cipher_capa = 0ULL;
    uint32_t auth_capa = 0ULL;
    uint32_t aead_capa = 0ULL;

    for (cidx = info.capabilities;
         cidx->op != RTE_CRYPTO_OP_TYPE_UNDEFINED;
         cidx++) {
      if (cidx->op == RTE_CRYPTO_OP_TYPE_SYMMETRIC) {
        if (cidx->sym.xform_type == RTE_CRYPTO_SYM_XFORM_CIPHER) {
          /* cipher/auth algos. */
          cipher = cidx->sym.cipher.algo;
          if (is_ipsecvsw_supported_cipher(cipher) == true) {
            cipher_capa |= s_cipher2uint32(cipher);
            for (aidx = info.capabilities;
                 aidx->op != RTE_CRYPTO_OP_TYPE_UNDEFINED;
                 aidx++) {
              if (aidx->op == RTE_CRYPTO_OP_TYPE_SYMMETRIC &&
                  aidx->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AUTH) {
                auth = aidx->sym.auth.algo;
                if (is_ipsecvsw_supported_auth(auth) == true) {
                  auth_capa |= s_auth2uint32(auth);
                }
              }
            }
          }
        } else if (cidx->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AEAD) {
          /* aead algos. */
          aead = cidx->sym.aead.algo;
          if (is_ipsecvsw_supported_aead(aead) == true) {
            aead_capa |= s_aead2uint32(aead);
          }
        }
      }
    }

    if (cipher_capa != 0ULL  &&
        auth_capa != 0ULL) {
      struct rte_cryptodev_config conf;

      conf.socket_id = rte_cryptodev_socket_id(dev_id);
      conf.nb_queue_pairs = (uint16_t)info.max_nb_queue_pairs;

      if (rte_cryptodev_configure(dev_id, &conf) == 0) {
        size_t i;
        bool is_hw =
          ((info.feature_flags & RTE_CRYPTODEV_FF_HW_ACCELERATED) != 0) ?
          true : false;
        ipsecvsw_cdevq_t q;

        for (i = 0; i < (size_t)(info.max_nb_queue_pairs) && i < buflen; i++) {
          q = s_create_cdevq(driver_name,
                             conf.socket_id,
                             dev_id, (uint16_t)i, CDEVQ_MAX_QLEN,
                             is_hw, cipher_capa, auth_capa, aead_capa);
          if (q != NULL) {
            buf[n_qs++] = q;
          } else {
            size_t j;

            for (j = 0; j < n_qs; j++) {
              s_destroy_cdevq(buf[j]);
              buf[j] = NULL;
            }

            ret = LAGOPUS_RESULT_NO_MEMORY;
            goto done;
          }
        }

        if (n_qs > 0) {
          if (rte_cryptodev_start(dev_id) == 0) {
            lagopus_msg_info("cdev %u, total queue %u, driver %s.\n",
                             dev_id, conf.nb_queue_pairs, driver_name);
            ret = (lagopus_result_t)n_qs;
          } else {
            size_t j;

            lagopus_msg_error("can't start cryptodev id %u.\n", dev_id);
            for (j = 0; j < n_qs; j++) {
              s_destroy_cdevq(buf[j]);
              buf[j] = NULL;
            }
            ret = LAGOPUS_RESULT_NOT_FOUND;
          }
        } else {
          ret = LAGOPUS_RESULT_NOT_FOUND;
        }
      } else {
        lagopus_msg_error("can't configure cryptodev id %u.\n", dev_id);
        ret = LAGOPUS_RESULT_NOT_FOUND;
      }
    } else {
      ret = LAGOPUS_RESULT_NOT_FOUND;
    }
  } else {
    ret = LAGOPUS_RESULT_NOT_FOUND;
  }

done:
  return ret;
}

static inline uint64_t
s_gen_hashkey_with_cipher_auth(rte_crypto_cipher_t c, rte_crypto_auth_t a) {
  return hash_fnv1a64((uint64_t)s_cipher2uint32(c) << 32 | (uint64_t)s_auth2uint32(a));
}

static inline uint64_t
s_gen_hashkey_with_aead(rte_crypto_aead_t ae) {
  return hash_fnv1a64((uint64_t)UINT32_MAX << 32 | (uint64_t)s_aead2uint32(ae));
}

static void
s_freeup_list(void *p) {
  s_destroy_cdevq_list((cdevq_list_t)p);
}

static inline lagopus_result_t
s_add_cdevq(lagopus_hashmap_t *h,
            uint32_t cipher_bit,
            uint32_t auth_bit,
            uint32_t aead_bit,
            ipsecvsw_cdevq_t q) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  cdevq_list_t l = NULL;
  uint64_t key;
  void *val;

  if (aead_bit != UNKNOWN_ALGORITHM) {
    // AEAD algos.
    key = s_gen_hashkey_with_aead((rte_crypto_aead_t)aead_bit);
  } else {
    // cipher/auth algos.
    key = s_gen_hashkey_with_cipher_auth((rte_crypto_cipher_t)cipher_bit,
                                         (rte_crypto_auth_t)auth_bit);
  }

  if ((ret = lagopus_hashmap_find(h, (void *) key, (void **) &l)) ==
      LAGOPUS_RESULT_OK && l != NULL) {
    s_add_cdevq_to_list(l, q);
  } else {
    l = s_create_cdevq_list((rte_crypto_cipher_t)cipher_bit,
                            (rte_crypto_auth_t)auth_bit,
                            (rte_crypto_aead_t)aead_bit);
    if (l != NULL) {
      val = (void *)l;
      if ((ret = lagopus_hashmap_add(h, (void *)key, &val,
                                     false)) == LAGOPUS_RESULT_OK) {
        s_add_cdevq_to_list(l, q);
      }
    }
  }

  return ret;
}

static inline lagopus_result_t
s_fill_hash(lagopus_hashmap_t *h,
            ipsecvsw_cdevq_t *qs, size_t n_qs) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(h != NULL)) {
    ipsecvsw_cdevq_t q;
    size_t i;
    uint32_t aead_bit;
    uint32_t auth_bit;
    uint32_t cipher_bit;

    for (i = 0; i < n_qs; i++) {
      q = qs[i];
      /* cipher/auth algos. */
      for (auth_bit = 1; auth_bit < 32; auth_bit++) {
        for (cipher_bit = 1; cipher_bit < 32; cipher_bit++) {
          if ((q->m_cipher_capa &
               s_cipher2uint32((rte_crypto_cipher_t)cipher_bit)) != 0 &&
              (q->m_auth_capa &
               s_auth2uint32((rte_crypto_auth_t)auth_bit)) != 0) {
            if ((ret = s_add_cdevq(h,
                                   cipher_bit,
                                   auth_bit,
                                   UNKNOWN_ALGORITHM, /* aead algos */
                                   q)) != LAGOPUS_RESULT_OK) {
              break;
            }
          }
        }
      }
      /* aead algos. */
      for (aead_bit = 1; aead_bit < 32; aead_bit++) {
        if ((q->m_aead_capa &
             s_aead2uint32((rte_crypto_aead_t)aead_bit)) != 0) {
          if ((ret = s_add_cdevq(h,
                                 UNKNOWN_ALGORITHM, /* cipher algos */
                                 UNKNOWN_ALGORITHM, /* auth algos */
                                 aead_bit,
                                 q)) != LAGOPUS_RESULT_OK) {
            break;
          }
        }
      }
    }
  }

  return ret;
}


static int
s_cdevq_cmp_proc(const void *v0, const void *v1, void *arg) {
  ipsecvsw_cdevq_t q0 = *(ipsecvsw_cdevq_t *)v0;
  ipsecvsw_cdevq_t q1 = *(ipsecvsw_cdevq_t *)v1;
  uint32_t p0 = cdevq_priority(q0);
  uint32_t p1 = cdevq_priority(q1);

  (void)arg;

  if (p0 > p1) {
    return (int)(p0 - p1);
  } else if (p0 == p1) {
    return 0;
  } else {
    return -1 * (int)(p1 - p0);
  }
}


static inline lagopus_result_t
s_sort_cdevq_array(ipsecvsw_cdevq_t *qs, size_t n_qs) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(qs != NULL && n_qs > 0)) {
    lagopus_qsort_r((void *)qs, n_qs, sizeof(ipsecvsw_cdevq_t),
                    s_cdevq_cmp_proc, NULL);
    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}


static bool
s_sort_cdevq_list(void *key, void *val,
                  lagopus_hashentry_t he, void *arg) {
  (void)key;
  (void)he;
  (void)arg;

  if (likely(val != NULL)) {
    cdevq_list_t l = (cdevq_list_t)val;
    if (likely(l->m_qs != NULL && l->m_n_qs > 0)) {
      if (likely(s_sort_cdevq_array(l->m_qs, l->m_n_qs) ==
                 LAGOPUS_RESULT_OK)) {
        s_dump_cdevq_list(l);
        return true;
      }
    }
  }
  lagopus_exit_fatal("cdevq list sort failure.\n");

  /* not reached */
  return false;
}


static inline lagopus_result_t
s_sort_cdevqs_in_hash(lagopus_hashmap_t *h) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(h != NULL)) {
    ret = lagopus_hashmap_iterate(h, s_sort_cdevq_list, NULL);
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}


static inline lagopus_result_t
s_setup(void *arg) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  uint8_t n_devs = rte_cryptodev_count();

  (void)arg;

  if (n_devs > 0) {
    ipsecvsw_cdevq_t cdevqs_tmp[n_devs][CDEVQ_MAX_QUEUES_PER_DEV];
    ipsecvsw_cdevq_t cdevqs_in[n_devs][CDEVQ_MAX_QUEUES_PER_DEV];
    size_t n_cdevqs_in[n_devs];
    ipsecvsw_cdevq_t cdevqs_out[n_devs][CDEVQ_MAX_QUEUES_PER_DEV];
    size_t n_cdevqs_out[n_devs];
    uint8_t i;

    rte_spinlock_init(&s_sched_lock);

    if ((ret = lagopus_hashmap_create(&s_inbound_q_tbl,
                                      LAGOPUS_HASHMAP_TYPE_ONE_WORD,
                                      s_freeup_list)) !=
        LAGOPUS_RESULT_OK) {
      goto done;
    }
    if ((ret = lagopus_hashmap_create(&s_outbound_q_tbl,
                                      LAGOPUS_HASHMAP_TYPE_ONE_WORD,
                                      s_freeup_list)) !=
        LAGOPUS_RESULT_OK) {
      goto done;
    }
    if ((ret = lagopus_hashmap_create(&s_inbound_thd_q_tbl,
                                      LAGOPUS_HASHMAP_TYPE_ONE_WORD,
                                      NULL)) !=
        LAGOPUS_RESULT_OK) {
      goto done;
    }
    if ((ret = lagopus_hashmap_create(&s_outbound_thd_q_tbl,
                                      LAGOPUS_HASHMAP_TYPE_ONE_WORD,
                                      NULL)) !=
        LAGOPUS_RESULT_OK) {
      goto done;
    }

    for (i = 0; i < n_devs; i++) {
      ret = s_setup_cdev(i, &(cdevqs_tmp[i][0]), CDEVQ_MAX_QUEUES_PER_DEV);
      if (ret > 0) {
        n_cdevqs_in[i] = n_cdevqs_out[i] = (size_t)ret / 2;
        (void)memcpy((void *)&(cdevqs_in[i][0]),
                     (void *)&(cdevqs_tmp[i][0]),
                     n_cdevqs_in[i] * sizeof(ipsecvsw_cdevq_t));
        (void)memcpy((void *)&(cdevqs_out[i][0]),
                     (void *)&(cdevqs_tmp[i][n_cdevqs_in[i]]),
                     n_cdevqs_out[i] * sizeof(ipsecvsw_cdevq_t));
        s_n_inbound_qs += n_cdevqs_in[i];
        s_n_outbound_qs += n_cdevqs_out[i];
        if ((ret = s_fill_hash(&s_inbound_q_tbl,
                               &(cdevqs_in[i][0]), n_cdevqs_in[i])) ==
            LAGOPUS_RESULT_OK &&
            (ret = s_fill_hash(&s_outbound_q_tbl,
                               &(cdevqs_out[i][0]), n_cdevqs_out[i])) ==
            LAGOPUS_RESULT_OK) {
          lagopus_msg_info("Added total " PF64(u) " queues into the "
                           "cryptodev queue scheduler for cdev %u.\n",
                           n_cdevqs_in[i] + n_cdevqs_out[i], i);
        } else {
          goto done;
        }
      } else {
        n_cdevqs_in[i] = n_cdevqs_out[i] = 0;
        lagopus_msg_warning("can't create queue on crypto device %u.\n",
                            i);
        lagopus_perror(ret);
      }
    }

    if ((ret = s_sort_cdevqs_in_hash(&s_inbound_q_tbl)) ==
        LAGOPUS_RESULT_OK &&
        (ret = s_sort_cdevqs_in_hash(&s_outbound_q_tbl)) ==
        LAGOPUS_RESULT_OK) {
      /*
       * Finally, made cdevq arrays each for inbound/outbound.
       */
      s_inbound_qs = (ipsecvsw_cdevq_t *)malloc(sizeof(ipsecvsw_cdevq_t) *
                     s_n_inbound_qs);
      s_outbound_qs = (ipsecvsw_cdevq_t *)malloc(sizeof(ipsecvsw_cdevq_t) *
                      s_n_outbound_qs);
      if (s_inbound_qs != NULL &&
          s_outbound_qs != NULL) {
        size_t n_in_qs = 0;
        size_t n_out_qs = 0;
        uint16_t j;

        for (i = 0; i < n_devs; i++) {
          for (j = 0; j < n_cdevqs_in[i]; j++) {
            s_inbound_qs[n_in_qs++] = cdevqs_in[i][j];
          }
          for (j = 0; j < n_cdevqs_out[i]; j++) {
            s_outbound_qs[n_out_qs++] = cdevqs_out[i][j];
          }
        }
        (void)s_sort_cdevq_array(s_inbound_qs, s_n_inbound_qs);
        (void)s_sort_cdevq_array(s_outbound_qs, s_n_outbound_qs);

        lagopus_msg_debug(2, "DUMP all cdev queues:\n");

        s_dump_cdevq_array(s_inbound_qs, s_n_inbound_qs);
        s_dump_cdevq_array(s_outbound_qs, s_n_outbound_qs);

        ret = LAGOPUS_RESULT_OK;
      } else {
        ret = LAGOPUS_RESULT_NO_MEMORY;
      }
    }
  } else {
    ret = LAGOPUS_RESULT_NOT_FOUND;
  }

done:
  return ret;
}





static inline void
s_lock_sched(void) {
  rte_spinlock_lock(&s_sched_lock);
}


static inline void
s_unlock_sched(void) {
  rte_spinlock_unlock(&s_sched_lock);
}


static inline size_t
s_incref_cdevq_for_put(ipsecvsw_cdevq_t q, pthread_t tid) {
  q->m_n_put_ref++;
  q->m_put_tid = tid;
  mbar();

  return q->m_n_put_ref;
}


static inline size_t
s_decref_cdevq_for_put(ipsecvsw_cdevq_t q) {
  q->m_n_put_ref--;
  if (q->m_n_put_ref == 0) {
    q->m_put_tid = LAGOPUS_INVALID_THREAD;
  }

  return q->m_n_put_ref;
}


static inline lagopus_result_t
s_acquire_cdevq_for_put(pthread_t tid,
                        ipsecvsw_queue_role_t role,
                        ipsec_sa_t sa,
                        ipsecvsw_cdevq_t *qptr) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(tid != LAGOPUS_INVALID_THREAD &&
             role != ipsecvsw_queue_role_unknown &&
             qptr != NULL)) {
    uint64_t key;
    cdevq_list_t l = NULL;
    lagopus_hashmap_t *h = (role == ipsecvsw_queue_role_inbound) ?
                           &s_inbound_q_tbl : &s_outbound_q_tbl;

    if (sa->aead_algo != UNKNOWN_ALGORITHM) {
      key = s_gen_hashkey_with_aead(sa->aead_algo);
    } else {
      key = s_gen_hashkey_with_cipher_auth(sa->cipher_algo, sa->auth_algo);
    }

    *qptr = NULL;

    if (likely((ret = lagopus_hashmap_find_no_lock(h,
                      (void *)key,
                      (void **)&l)) ==
               LAGOPUS_RESULT_OK &&
               l != NULL &&
               l->m_qs != NULL &&
               l->m_n_qs > 0)) {
      size_t i;
      ipsecvsw_cdevq_t q;
      size_t min_idx = ULLONG_MAX;

      s_lock_sched();
      {
        for (i = 0; i < l->m_n_qs; i++) {
          q = l->m_qs[i];

          s_lock_cdevq(q);
          {
            mbar();

            if (q->m_n_put_ref == 0) {
              /*
               * The fastest case: the list has a vacant queue at
               * least.
               */
              (void)s_incref_cdevq_for_put(q, tid);

              /*
               * Unlock the queue.
               */
              s_unlock_cdevq(q);

              *qptr = q;
              ret = LAGOPUS_RESULT_OK;
              goto unlock_sched;

            } else {
              if (q->m_put_tid == tid) {
                /*
                 * Find a least used queue that has a given tid.
                 */
                if (min_idx > q->m_n_put_ref) {
                  min_idx = i;
                }
              }
            }
          }
          s_unlock_cdevq(q);

        }

        if (min_idx != ULLONG_MAX) {
          /*
           * Found used one.
           */
          q = l->m_qs[min_idx];

          s_lock_cdevq(q);
          {
            (void)s_incref_cdevq_for_put(q, tid);
          }
          s_unlock_cdevq(q);

          *qptr = q;
          ret = LAGOPUS_RESULT_OK;
        } else {
          ret = LAGOPUS_RESULT_NOT_FOUND;
        }
      }
    unlock_sched:
      s_unlock_sched();

      if (likely(ret == LAGOPUS_RESULT_OK)) {
        if (unlikely(s_add_cdevq_to_thread(tid, role, *qptr) == 0)) {
          *qptr = NULL;
          ret = LAGOPUS_RESULT_NO_MEMORY;
        }
      }

    } else {
      ret = LAGOPUS_RESULT_NOT_FOUND;
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}


static inline lagopus_result_t
s_release_cdevq_for_put(pthread_t tid,
                        ipsecvsw_queue_role_t role,
                        ipsecvsw_cdevq_t q) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(tid != LAGOPUS_INVALID_THREAD && q != NULL)) {
    size_t n_ref = 0;

    s_lock_cdevq(q);
    {
      if (q->m_put_tid == tid) {
        n_ref = s_decref_cdevq_for_put(q);
        ret = LAGOPUS_RESULT_OK;
      } else {
        ret = LAGOPUS_RESULT_NOT_OWNER;
      }
    }
    s_unlock_cdevq(q);

    if (likely(ret == LAGOPUS_RESULT_OK &&
               n_ref == 0)) {
      if (unlikely(s_del_cdevq_from_thread(tid, role, q) == 0)) {
        ret = LAGOPUS_RESULT_NOT_FOUND;
      }
    }

  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}


static inline void
s_incref_cdevq_for_get(ipsecvsw_cdevq_t q, pthread_t tid) {
  q->m_get_tid = tid;
  mbar();
}


static inline void
s_decref_cdevq_for_get(ipsecvsw_cdevq_t q) {
  q->m_get_tid = LAGOPUS_INVALID_THREAD;
  mbar();
}


static inline lagopus_result_t
s_acquire_cdevq_for_get(pthread_t tid,
                        ipsecvsw_queue_role_t role,
                        ipsecvsw_cdevq_t *qptr) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(tid != LAGOPUS_INVALID_THREAD &&
             role != ipsecvsw_queue_role_unknown &&
             qptr != NULL)) {
    ipsecvsw_cdevq_t *qs = (role == ipsecvsw_queue_role_inbound) ?
                           s_inbound_qs : s_outbound_qs;
    size_t n_qs = (role == ipsecvsw_queue_role_inbound) ?
                  s_n_inbound_qs : s_n_outbound_qs;
    size_t i;
    ipsecvsw_cdevq_t q;

    *qptr = NULL;

    s_lock_sched();
    {
      for (i = 0; i < n_qs; i++) {
        q = qs[i];

        s_lock_cdevq(q);
        {
          if (q->m_get_tid == LAGOPUS_INVALID_THREAD) {
            s_incref_cdevq_for_get(q, tid);

            /*
             * Unlock the queue.
             */
            s_unlock_cdevq(q);

            *qptr = q;
            ret = LAGOPUS_RESULT_OK;

            goto unlock_sched;
          }
        }
        s_unlock_cdevq(q);
      }

      ret = LAGOPUS_RESULT_NOT_FOUND;
    }
  unlock_sched:
    s_unlock_sched();

    if (likely(ret == LAGOPUS_RESULT_OK)) {
      if (unlikely(s_add_cdevq_to_thread(tid, role, *qptr) == 0)) {
        *qptr = NULL;
        ret = LAGOPUS_RESULT_NO_MEMORY;
      }
    }

  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}


static inline lagopus_result_t
s_release_cdevq_for_get(pthread_t tid,
                        ipsecvsw_queue_role_t role,
                        ipsecvsw_cdevq_t q) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(tid != LAGOPUS_INVALID_THREAD &&
             role != ipsecvsw_queue_role_unknown &&
             q != NULL)) {

    s_lock_cdevq(q);
    {
      if (q->m_get_tid == tid) {
        s_decref_cdevq_for_get(q);
        ret = LAGOPUS_RESULT_OK;
      } else {
        ret = LAGOPUS_RESULT_NOT_OWNER;
      }
    }
    s_unlock_cdevq(q);

    if (likely(ret == LAGOPUS_RESULT_OK)) {
      if (unlikely(s_del_cdevq_from_thread(tid, role, q) == 0)) {
        ret = LAGOPUS_RESULT_NOT_FOUND;
      }
    }

  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}


static inline lagopus_result_t
s_acquire_cdevqs_for_get(pthread_t tid,
                         ipsecvsw_queue_role_t role,
                         size_t n,
                         size_t *n_actual) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(tid != LAGOPUS_INVALID_THREAD &&
             role != ipsecvsw_queue_role_unknown &&
             n > 0 &&
             n_actual != NULL)) {
    size_t i;
    ipsecvsw_cdevq_t q;
    size_t n_total = 0;

    *n_actual = 0;

    for (i = 0; i < n; i++) {
      if (likely((ret = s_acquire_cdevq_for_get(tid, role, &q)) ==
                 LAGOPUS_RESULT_OK &&
                 q != NULL)) {
        n_total++;
      } else {
        break;
      }
    }

    *n_actual = n_total;
    if (likely(n == n_total)) {
      ret = (lagopus_result_t)n_total;
    }

  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}


static inline lagopus_result_t
s_release_cdevqs_for_get(pthread_t tid,
                         ipsecvsw_queue_role_t role) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(tid != LAGOPUS_INVALID_THREAD &&
             role != ipsecvsw_queue_role_unknown)) {
    cdevq_per_thread_t l = s_get_cdevq_per_thread(tid, role);

    if (likely(l != NULL)) {
      size_t i;

      for (i = 0; i < l->m_n_qs; i++) {
        (void)s_release_cdevq_for_get(tid, role, l->m_qs[i]);
      }

      ret = LAGOPUS_RESULT_OK;
    } else {
      ret = LAGOPUS_RESULT_NOT_FOUND;
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}


static inline lagopus_result_t
s_get_cdevqs_no(ipsecvsw_queue_role_t role) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(role != ipsecvsw_queue_role_unknown)) {
    ret = (role == ipsecvsw_queue_role_inbound) ?
          (lagopus_result_t)s_n_inbound_qs :
          (lagopus_result_t)s_n_outbound_qs;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}





static inline lagopus_result_t
s_create_session(pthread_t tid,
                 ipsecvsw_queue_role_t role,
                 ipsec_sa_t sa,
                 ipsecvsw_session_ctx_t *ctx_ptr) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  ipsecvsw_cdevq_t q = NULL;

  if (likely(tid != LAGOPUS_INVALID_THREAD &&
             role != ipsecvsw_queue_role_unknown &&
             sa != NULL &&
             ctx_ptr != NULL && *ctx_ptr == NULL)) {
    ret = s_acquire_cdevq_for_put(tid, role, sa, &q);
    if (likely(ret == LAGOPUS_RESULT_OK)) {
      ret = ipsecvsw_create_session_ctx_body(tid, sa, role, q, ctx_ptr);
      if (likely(ret == LAGOPUS_RESULT_OK)) {
        if (unlikely(lagopus_log_get_debug_level() > 0)) {
          lagopus_msg_debug(1, "A session context created for SA %p, "
                            "session %p.\n",
                            sa, *ctx_ptr);
        }
      } else {
        lagopus_perror(ret);
        lagopus_msg_error("can't create session for SA %p.\n",
                          sa);
      }
    } else {
      lagopus_perror(ret);
      lagopus_msg_error("can't create session for SA %p.\n",
                        sa);
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}


static inline lagopus_result_t
s_dispose_session(pthread_t tid,
                  ipsecvsw_queue_role_t role,
                  ipsecvsw_session_ctx_t sctx,
                  ipsecvsw_session_gc_ctx_t gctx) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(tid != LAGOPUS_INVALID_THREAD &&
             role != ipsecvsw_queue_role_unknown &&
             sctx != NULL)) {
    ret = ipsecvsw_dispose_session_ctx_body(sctx, gctx);
    if (likely(ret == LAGOPUS_RESULT_OK)) {
      if (unlikely(lagopus_log_get_debug_level() > 0)) {
        lagopus_msg_debug(1, "A session context disposed for "
                          "session %p.\n", sctx);
      }
    } else {
      lagopus_perror(ret);
      lagopus_msg_error("Can't destroy a session contxt for "
                        "session %p.\n", sctx);
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}





static inline size_t
s_flush_queue(ipsecvsw_cdevq_t q) {
  uint16_t n_put;
  uint16_t n_total_put = 0;
  size_t n_calls = 0;
  size_t ret;

  while (n_total_put < q->m_n_cur_entries && n_calls < q->m_n_cur_entries) {
    /*
     * Keep on putting until all the cops are enqueued.
     */
    n_put = rte_cryptodev_enqueue_burst(
              q->m_dev_id,
              q->m_q_id,
              &(q->m_q_put_entries[n_total_put]),
              (uint16_t)((uint16_t)(q->m_n_cur_entries) - n_total_put));
    n_total_put = (uint16_t)(n_total_put + n_put);
  }
  ret = (size_t)n_total_put;

  if (unlikely(q->m_n_cur_entries != (size_t)n_total_put)) {
    size_t i;

    for (i = n_total_put; i < q->m_n_cur_entries; i++) {
      rte_pktmbuf_free(q->m_q_put_entries[i]->sym->m_src);
    }

    if (unlikely(n_calls >= q->m_n_cur_entries)) {
      lagopus_msg_error("Too many enqueu retry. Check crypto ops.\n");
    }
  }

  q->m_n_cur_entries = 0;

  return ret;
}


static inline void
s_put_queue(ipsecvsw_cdevq_t q, rte_cop_t cop) {
  q->m_q_put_entries[q->m_n_cur_entries++] = cop;
  if (q->m_n_cur_entries == q->m_n_max_entries) {
    (void)s_flush_queue(q);
  }
}


static inline lagopus_result_t
s_flush_queue_per_thread(pthread_t tid,
                         ipsecvsw_queue_role_t role) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(tid != LAGOPUS_INVALID_THREAD &&
             role != ipsecvsw_queue_role_unknown)) {
    cdevq_per_thread_t l = s_get_cdevq_per_thread(tid, role);

    if (likely(l != NULL)) {
      size_t i;
      size_t n = 0;

      for (i = 0; i < l->m_n_qs; i++) {
        n += s_flush_queue(l->m_qs[i]);
      }
      ret = (lagopus_result_t)n;
    } else {
      /*
       * must not happen.
       */
      lagopus_exit_fatal("once could enqueue to queues but has "
                         "no queues at this moment.\n");
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}


static inline lagopus_result_t
s_put(pthread_t tid,
      ipsecvsw_queue_role_t role,
      ipsecvsw_xform_proc_t pre_xform_proc,
      rte_mbuf_t const pkts[],
      ipsecvsw_session_ctx_t sctxs[],
      size_t n_pkts) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(tid != LAGOPUS_INVALID_THREAD &&
             pre_xform_proc != NULL &&
             pkts != NULL && sctxs != NULL && n_pkts > 0)) {
    struct ipsec_mbuf_metadata *priv;
    ipsec_sa_t sa;
    ipsecvsw_session_ctx_t ctx = NULL;
    size_t i;
    size_t n = 0;
    int xform_ret;

    if (likely(n_pkts <= (size_t)USHRT_MAX)) {
      for (i = 0; i < n_pkts; i++) {
        if (likely(pkts[i] != NULL &&
                   (ctx = sctxs[i]) != NULL &&
                   ctx->m_q != NULL &&
                   ctx->m_q->m_put_tid == tid)) {
          /*
           * Not yet fully evaluated this could work but do it anyway:
           */
          rte_prefetch0(&(ctx->m_sa));
          rte_prefetch0(pkts[i]);

          priv = get_priv(pkts[i]);

          /*
           * Use SA data in a session context.
           */
          sa = &(ctx->m_sa);

          priv->session_ctx = ctx;
          priv->cop.type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
          priv->cop.status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;

          rte_prefetch0(&priv->sym_cop);

          rte_crypto_op_attach_sym_session(&(priv->cop),
                                           ctx->m_session);
          priv->cop.sym->m_src = NULL;
          if (likely((xform_ret = pre_xform_proc(pkts[i], sa, &(priv->cop)))
                     == 0)) {
            s_put_queue(ctx->m_q, &(priv->cop));
            ipsecvsw_session_ctx_incref(ctx);
            n++;
          } else {
            lagopus_msg_error("pre xform function '%s' returns %d.\n",
                              ipsecvsw_get_xform_funcname(pre_xform_proc),
                              xform_ret);
            rte_pktmbuf_free(pkts[i]);
            continue;
          }
        } else {
          if (ctx != NULL &&
              ctx->m_q != NULL &&
              ctx->m_q->m_put_tid != tid) {
            lagopus_msg_error("SA/cdevq is not acquired for this thread.\n");
          } else if (ctx != NULL &&
                     ctx->m_q == NULL) {
            lagopus_msg_error("cdevq is not acquired for this SA.\n");
          } else {
            lagopus_msg_error("pkts/sas[" PFSZ(u) "] is not properly setup.\n",
                              i);
          }
          rte_pktmbuf_free(pkts[i]);
          continue;
        }
      }

      if (likely(n > 0 &&
                 s_flush_queue_per_thread(tid, role) >= 0)) {
        ret = (lagopus_result_t)n;
      } else if (n == 0) {
        ret = (lagopus_result_t)0;
      }
    } else {
      ret = LAGOPUS_RESULT_TOO_LARGE;
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}





static inline lagopus_result_t
s_get(pthread_t tid,
      ipsecvsw_queue_role_t role,
      ipsecvsw_xform_proc_t post_xform_proc,
      rte_mbuf_t pkts[],
      size_t n_max_pkts) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(tid != LAGOPUS_INVALID_THREAD &&
             role != ipsecvsw_queue_role_unknown &&
             post_xform_proc != NULL)) {
    cdevq_per_thread_t l = s_get_cdevq_per_thread(tid, role);

    if (likely(l != NULL)) {
      size_t i;
      size_t j;
      size_t q_idx;
      ipsec_sa_t sa;
      ipsecvsw_session_ctx_t ctx;
      ipsecvsw_cdevq_t q;
      rte_mbuf_t pkt;
      rte_cop_t cop;
      struct ipsec_mbuf_metadata *priv;
      size_t n_pkts = 0;
      size_t vacant;
      uint16_t n_cops;
      uint16_t max_cops;
      int xform_ret;

      for (i = 0;
           ((i < l->m_n_qs) &&
            ((vacant = n_max_pkts - n_pkts) > 0));
           i++) {
        q_idx = (l->m_mru_q_idx + i) % l->m_n_qs;
        q = l->m_qs[q_idx];
        max_cops = (vacant < q->m_n_max_entries) ?
                   (uint16_t)vacant : (uint16_t)q->m_n_max_entries;

        n_cops = rte_cryptodev_dequeue_burst(q->m_dev_id,
                                             q->m_q_id,
                                             q->m_q_get_entries,
                                             max_cops);
        for (j = 0; j < n_cops; j++) {
          cop = q->m_q_get_entries[j];
          pkt = cop->sym->m_src;

          /*
           * Not yet fully evaluated this could work but do it anyway:
           */
          rte_prefetch0(pkt);

          priv = get_priv(pkt);
          ctx = priv->session_ctx;

          ipsecvsw_session_ctx_decref(ctx);

          sa = &(ctx->m_sa);

          if (likely(sa != NULL &&
                     (xform_ret = post_xform_proc(pkt, sa, cop)) == 0)) {
            pkts[n_pkts++] = pkt;
          } else {
            lagopus_msg_error("post xform function '%s' returns %d.\n",
                              ipsecvsw_get_xform_funcname(post_xform_proc),
                              xform_ret);
            rte_pktmbuf_free(pkt);
            continue;
          }
        }
      }

      ret = (lagopus_result_t)n_pkts;

    } else {
      ret = LAGOPUS_RESULT_NOT_FOUND;
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  return ret;
}





/*
 * External APIs:
 */


lagopus_result_t
ipsecvsw_setup_cdevq(void *optarg) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  uint16_t dbglvl = lagopus_log_get_debug_level();

  lagopus_log_set_debug_level(2);

  ret = s_setup(optarg);

  lagopus_log_set_debug_level(dbglvl);

  return ret;
}


lagopus_result_t
ipsecvsw_acquire_cdevq_for_get(pthread_t tid,
                               ipsecvsw_queue_role_t role,
                               ipsecvsw_cdevq_t *qptr) {
  return s_acquire_cdevq_for_get(tid, role, qptr);
}


lagopus_result_t
ipsecvsw_release_cdevq_for_get(pthread_t tid,
                               ipsecvsw_queue_role_t role,
                               ipsecvsw_cdevq_t q) {
  return s_release_cdevq_for_get(tid, role, q);
}


lagopus_result_t
ipsecvsw_release_cdevq_for_put(pthread_t tid,
                               ipsecvsw_queue_role_t role,
                               ipsecvsw_cdevq_t q) {
  return s_release_cdevq_for_put(tid, role, q);
}


lagopus_result_t
ipsecvsw_acquire_cdevqs_for_get(pthread_t tid,
                                ipsecvsw_queue_role_t role,
                                size_t n,
                                size_t *n_actual) {
  return s_acquire_cdevqs_for_get(tid, role, n, n_actual);
}


lagopus_result_t
ipsecvsw_release_cdevqs_for_get(pthread_t tid,
                                ipsecvsw_queue_role_t role) {
  return s_release_cdevqs_for_get(tid, role);
}


lagopus_result_t
ipsecvsw_get_cdevqs_no(ipsecvsw_queue_role_t role) {
  return s_get_cdevqs_no(role);
}


lagopus_result_t
ipsecvsw_create_session_ctx(pthread_t tid,
                            ipsecvsw_queue_role_t role,
                            ipsec_sa_t sa,
                            ipsecvsw_session_ctx_t *ctx_ptr) {
  return s_create_session(tid, role, sa, ctx_ptr);
}


lagopus_result_t
ipsecvsw_dispose_session_ctx(pthread_t tid,
                             ipsecvsw_queue_role_t role,
                             ipsecvsw_session_ctx_t sctx,
                             ipsecvsw_session_gc_ctx_t gctx) {
  return s_dispose_session(tid, role, sctx, gctx);
}


lagopus_result_t
ipsecvsw_cdevq_put(pthread_t tid,
                   ipsecvsw_queue_role_t role,
                   ipsecvsw_xform_proc_t pre_xform_proc,
                   rte_mbuf_t const pkts[],
                   ipsecvsw_session_ctx_t sctxs[],
                   size_t n_pkts) {
  return s_put(tid, role, pre_xform_proc, pkts, sctxs, n_pkts);
}


lagopus_result_t
ipsecvsw_cdevq_get(pthread_t tid,
                   ipsecvsw_queue_role_t role,
                   ipsecvsw_xform_proc_t post_xform_proc,
                   rte_mbuf_t pkts[],
                   size_t max_pkts) {
  return s_get(tid, role, post_xform_proc, pkts, max_pkts);
}


lagopus_result_t
ipsecvsw_cdevq_get_numanode(ipsecvsw_cdevq_t q) {
  if (likely(q != NULL)) {
    return (lagopus_result_t)q->m_numa_node;
  } else {
    return LAGOPUS_RESULT_INVALID_ARGS;
  }
}


lagopus_result_t
ipsecvsw_cdevq_get_dev_id(ipsecvsw_cdevq_t q) {
  if (likely(q != NULL)) {
    return (lagopus_result_t)q->m_dev_id;
  } else {
    return LAGOPUS_RESULT_INVALID_ARGS;
  }
}

lagopus_result_t
ipsecvsw_cdevq_get_queue_id(ipsecvsw_cdevq_t q) {
  if (likely(q != NULL)) {
    return (lagopus_result_t)q->m_q_id;
  } else {
    return LAGOPUS_RESULT_INVALID_ARGS;
  }
}

lagopus_result_t
ipsecvsw_cdevq_get_session_pool(ipsecvsw_cdevq_t q,
                                struct rte_mempool **session_pool) {
  if (likely(q != NULL)) {
    *session_pool = q->session_pool;
    return LAGOPUS_RESULT_OK;
  } else {
    return LAGOPUS_RESULT_INVALID_ARGS;
  }
}
