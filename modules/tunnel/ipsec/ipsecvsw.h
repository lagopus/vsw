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

#ifndef IPSECVSW_H
#define IPSECVSW_H





#include "dpdk_apis.h"

#include "sa.h"





#ifdef RTE_LOG
#undef RTE_LOG
#endif /* RTE_LOG */

#define RTE_LOG(lvl, id, ...) {                             \
    do {                                                    \
      if (RTE_LOG_ ## lvl == RTE_LOG_ERR) {                 \
        lagopus_msg_error(__VA_ARGS__);                     \
      } else if (RTE_LOG_ ## lvl == RTE_LOG_DEBUG) {        \
        lagopus_msg_debug(1, __VA_ARGS__);                  \
      } else if (RTE_LOG_ ## lvl == RTE_LOG_WARNING) {      \
        lagopus_msg_warning(__VA_ARGS__);                   \
      } else {                                              \
        lagopus_msg_info(__VA_ARGS__);                      \
      }                                                     \
    } while (0);                                            \
  }

#define is_ipsecvsw_supported_cipher(x)                 \
  (((x == RTE_CRYPTO_CIPHER_NULL ||                     \
     x == RTE_CRYPTO_CIPHER_AES_CBC ||                  \
     x == RTE_CRYPTO_CIPHER_AES_CTR)) ? true : false)

#define is_ipsecvsw_supported_auth(x)                   \
  (((x == RTE_CRYPTO_AUTH_NULL ||                       \
     x == RTE_CRYPTO_AUTH_SHA1_HMAC ||                  \
     x == RTE_CRYPTO_AUTH_SHA256_HMAC)) ? true : false)

#define is_ipsecvsw_supported_aead(x)                 \
  (((x == RTE_CRYPTO_AEAD_AES_GCM)) ? true : false)

#define CDEVQ_MAX_QUEUES_PER_DEV	32
#define CDEVQ_MAX_QLEN			1024

#define CDEVQ_MAX_QUEUES_PER_THD	2048

/*
 * Parameters copied from the ipsec-secgw.
 */
#define CDEV_MP_NB_OBJS		2048
#define CDEV_MP_CACHE_SZ	64





typedef struct ipsec_mbuf_metadata	*ipsecvsw_metadata_t;
typedef struct ipsec_sa	*ipsec_sa_t;

typedef struct rte_mbuf	*rte_mbuf_t;
typedef struct rte_crypto_op	*rte_cop_t;
typedef struct rte_crypto_sym_op	*rte_crypto_sym_op_t;

typedef enum rte_crypto_cipher_algorithm	rte_crypto_cipher_t;
typedef enum rte_crypto_auth_algorithm		rte_crypto_auth_t;
typedef enum rte_crypto_aead_algorithm		rte_crypto_aead_t;
typedef struct rte_cryptodev_sym_session	*rte_cryptodev_sym_session_t;
typedef struct rte_crypto_sym_xform	*rte_crypto_sym_xform_t;

typedef int (ipsecvsw_xform_proc_t)(rte_mbuf_t pkt,
                                    ipsec_sa_t sa,
                                    rte_cop_t cop);




typedef struct ipsecvsw_session_ctx_record {
  TAILQ_ENTRY(ipsecvsw_session_ctx_record) m_elem;
  size_t m_ref_cnt;
  pthread_t m_tid;
  uint8_t m_dev_id;
  struct ipsec_sa m_sa;
  struct rte_crypto_sym_xform a;
  struct rte_crypto_sym_xform b;
  ipsecvsw_queue_role_t m_role;
  struct ipsecvsw_q_record *m_q;
  struct rte_cryptodev_sym_session *m_session;
} ipsecvsw_session_ctx_record;


TAILQ_HEAD(ipsecvsw_session_ctx_list_record, ipsecvsw_session_ctx_record);
typedef struct ipsecvsw_session_ctx_list_record ipsecvsw_session_ctx_list_t;

typedef struct ipsecvsw_session_gc_ctx_record {
  pthread_t m_tid;
  rte_spinlock_t m_gc_lock;
  ipsecvsw_session_ctx_list_t m_gc_list;
} ipsecvsw_session_gc_ctx_record;
typedef ipsecvsw_session_gc_ctx_record *ipsecvsw_session_gc_ctx_t;





/**
 * Initialize DPDK crypto devices and queues.
 *
 *	@param[in]	optarg	An optional argument (NULL allowed.)
 *
 *	@retval	LAGOPUS_RESULT_OK	Succeeded.
 *	@retval LAGOPUS_RESULT_NO_MEMORY	Failed, no memoty.
 *	@retval LAGOPUS_RESULT_NOT_FOUND	Fialed, no DPDK crypto device found.
 *	@retval	LAGOPUS_RESULT_ANY_FAILURES	Failed.
 */
lagopus_result_t
ipsecvsw_setup_cdevq(void *optarg);





/**
 * Acquire a crypto device queue fot dequeue.
 *
 *	@param[in]	tid	A pthread id which the thread uses the queue.
 *	@param[in]	role	A role, inbound or outbound.
 *	@param[out]	qptr	An acquired queue returned.
 *
 *	@retval	LAGOPUS_RESULT_OK	Succeeded.
 *	@retval LAGOPUS_RESULT_INVALID_ARGS	Failed, invalid args.
 *	@retval LAGOPUS_RESULT_NOT_FOUND	Fialed, queue not available at the moment.
 *	@retval LAGOPUS_RESULT_ANY_FAILURES	Failed.
 */
lagopus_result_t
ipsecvsw_acquire_cdevq_for_get(pthread_t tid,
                               ipsecvsw_queue_role_t role,
                               ipsecvsw_cdevq_t *qptr);


/**
 * Release a crypto device queue for dequeue.
 *
 *	@param[in]	tid	A pthread id which the thread uses the queue.
 *	@param[in]	role	A role, inbound or outbound.
 *	@param[in]	q	A queue.
 *
 *	@retval	LAGOPUS_RESULT_OK	Succeeded.
 *	@retval LAGOPUS_RESULT_INVALID_ARGS	Failed, invalid args.
 *	@retval LAGOPUS_RESULT_NOT_OWNER	Failed, not an owner.
 *	@retval LAGOPUS_RESULT_ANY_FAILURES	Failed.
 */
lagopus_result_t
ipsecvsw_release_cdevq_for_get(pthread_t tid,
                               ipsecvsw_queue_role_t role,
                               ipsecvsw_cdevq_t q);


/**
 * Release a crypto device queue for enqueue.
 *
 *	@param[in]	tid	A pthread id which the thread uses the queue.
 *	@param[in]	role	A role, inbound or outbound.
 *	@param[in]	q	A queue.
 *
 *	@retval	LAGOPUS_RESULT_OK	Succeeded.
 *	@retval LAGOPUS_RESULT_INVALID_ARGS	Failed, invalid args.
 *	@retval LAGOPUS_RESULT_NOT_OWNER	Failed, not an owner.
 *	@retval LAGOPUS_RESULT_ANY_FAILURES	Failed.
 */
lagopus_result_t
ipsecvsw_release_cdevq_for_put(pthread_t tid,
                               ipsecvsw_queue_role_t role,
                               ipsecvsw_cdevq_t q);


/**
 * Acquire crypto device queues fot dequeue.
 *
 *	@param[in]	tid	A pthread id which the thread uses the queue.
 *	@param[in]	role	A role, inbound or outbound.
 *	@param[in]	n	# of queues to acquire.
 *	@param[out]	n_actual	# of queues actually acquired.
 *
 *	@retval	>0	Succeeded.
 *	@retval LAGOPUS_RESULT_INVALID_ARGS	Failed, invalid args.
 *	@retval LAGOPUS_RESULT_NOT_FOUND	Fialed, queue not available at the moment.
 *	@retval LAGOPUS_RESULT_ANY_FAILURES	Failed.
 */
lagopus_result_t
ipsecvsw_acquire_cdevqs_for_get(pthread_t tid,
                                ipsecvsw_queue_role_t role,
                                size_t n,
                                size_t *n_actual);


/**
 * Release crypto device queues for dequeue.
 *
 *	@param[in]	tid	A pthread id which the thread uses the queue.
 *	@param[in]	role	A role, inbound or outbound.
 *
 *	@retval	LAGOPUS_RESULT_OK	Succeeded.
 *	@retval LAGOPUS_RESULT_INVALID_ARGS	Failed, invalid args.
 *	@retval LAGOPUS_RESULT_NOT_OWNER	Failed, not an owner.
 *	@retval LAGOPUS_RESULT_ANY_FAILURES	Failed.
 */
lagopus_result_t
ipsecvsw_release_cdevqs_for_get(pthread_t tid,
                                ipsecvsw_queue_role_t role);


/**
 * Get a # of crypto device queues.
 *
 *	@param[in]	role	A role, inbound or outbound.
 *
 *	@retval >=0	A # of crypto device queues.
 *	@retval LAGOPUS_RESULT_INVALID_ARGS	Failed, invalid args.
 *	@retval LAGOPUS_RESULT_ANY_FAILURES	Failed.
 */
lagopus_result_t
ipsecvsw_get_cdevqs_no(ipsecvsw_queue_role_t role);


/**
 * Create a session context (crypto device queue and crypto session) for an SA.
 *
 *	@param[in]	tid	A pthread id which the thread uses the SA.
 *	@param[in]	role	A role, inbound or outbound.
 *	@param[in]	sa	An SA.
 *	@param[out]	ctx_ptr	A created session context.
 *
 *	@retval	LAGOPUS_RESULT_OK	Succeeded.
 *	@retval LAGOPUS_RESULT_INVALID_ARGS	Failed, invalid args.
 *	@retval LAGOPUS_RESULT_ANY_FAILURES	Failed.
 */
lagopus_result_t
ipsecvsw_create_session_ctx(pthread_t tid,
                            ipsecvsw_queue_role_t role,
                            ipsec_sa_t sa,
                            ipsecvsw_session_ctx_t *session_ctx_ptr);


/**
 * Dispose a session context of an SA.
 *
 *	@param[in]	tid	A pthread id which the thread uses the SA.
 *	@param[in]	role	A role, inbound or outbound.
 *	@param[in]	sctx	An session context.
 *	@param[in]	gctx	A session gc context.
 *
 *	@retval	LAGOPUS_RESULT_OK	Succeeded.
 *	@retval LAGOPUS_RESULT_INVALID_ARGS	Failed, invalid args.
 *	@retval LAGOPUS_RESULT_ANY_FAILURES	Failed.
 */
lagopus_result_t
ipsecvsw_dispose_session_ctx(pthread_t tid,
                             ipsecvsw_queue_role_t role,
                             ipsecvsw_session_ctx_t sctx,
                             ipsecvsw_session_gc_ctx_t gctx);


/**
 * Enqueue packets into a crypto device queues acquired for SAs.
 *
 *	@param[in]	tid	A pthread id which the thread uses the queue.
 *	@paran[in]	role	A role, inbound or outbound.
 *	@param[in]	pre_xform_proc	A per-packet, pre-packet-transform function.
 *	@param[in]	pkts	Packets.
 *	@param[in]	sctxs	Session contexts.
 *	@param[in]	n_pkts	A # of packets, SAs and session contexts.
 *
 *	@retval	>=0	A # of packets successfully enqueued.
 *	@retval LAGOPUS_RESULT_INVALID_ARGS	Failed, invalid args.
 *	@retval	LAGOPUS_RESULT_TOO_LARGE	Failed, too many packets.
 *	@retval LAGOPUS_RESULT_ANY_FAILURES	Failed.
 *
 *	@detail Each SA in the \b sas[] must be properly setup or
 *	packets in the \b pkts[] associated to the SA could be dropped.
 */
lagopus_result_t
ipsecvsw_cdevq_put(pthread_t tid,
                   ipsecvsw_queue_role_t role,
                   ipsecvsw_xform_proc_t pre_xform_proc,
                   rte_mbuf_t const pkts[],
                   ipsecvsw_session_ctx_t sctxs[],
                   size_t n_pkts);


/**
 * Dequeue packets from a crypto device queues acquired for a thread.
 *
 *	@param[in]	tid	A pthread id which the thread uses the queue.
 *	@paran[in]	role	A role, inbound or outbound.
 *	@param[in]	post_xform_proc	A per-packet, post-packet-transform function.
 *	@param[out]	pkts	Packets dequeued.
 *	@param[in]	max_pkts	A # of maximum packets the \b pkts can hold.
 *
 *	@retval	>=0	A # of packets successfully dequeued.
 *	@retval LAGOPUS_RESULT_INVALID_ARGS	Failed, invalid args.
 *	@retval	LAGOPUS_RESULT_NOT_FOUND	Failed, no queues for \b tid.
 *	@retval LAGOPUS_RESULT_ANY_FAILURES	Failed.
 */
lagopus_result_t
ipsecvsw_cdevq_get(pthread_t tid,
                   ipsecvsw_queue_role_t role,
                   ipsecvsw_xform_proc_t post_xform_proc,
                   rte_mbuf_t pkts[],
                   size_t max_pkts);





const char *
ipsecvsw_get_xform_funcname(ipsecvsw_xform_proc_t proc);


lagopus_result_t
ipsecvsw_cdevq_get_numanode(ipsecvsw_cdevq_t q);


lagopus_result_t
ipsecvsw_cdevq_get_dev_id(ipsecvsw_cdevq_t q);

lagopus_result_t
ipsecvsw_cdevq_get_queue_id(ipsecvsw_cdevq_t q);

lagopus_result_t
ipsecvsw_cdevq_get_session_pool(ipsecvsw_cdevq_t q,
                                struct rte_mempool **session_pool);

lagopus_result_t
ipsecvsw_create_session_ctx_body(pthread_t tid,
                                 ipsec_sa_t sa,
                                 ipsecvsw_queue_role_t role,
                                 ipsecvsw_cdevq_t q,
                                 ipsecvsw_session_ctx_t *ctx_ptr);


lagopus_result_t
ipsecvsw_dispose_session_ctx_body(ipsecvsw_session_ctx_t ctx,
                                  ipsecvsw_session_gc_ctx_t gctx);


void
ipsecvsw_session_gc_initialize(pthread_t tid,
                               ipsecvsw_session_gc_ctx_t gctx);


void
ipsecvsw_session_ctx_gc(pthread_t tid,
                        ipsecvsw_session_gc_ctx_t gctx);





static inline void
ipsecvsw_session_ctx_incref(ipsecvsw_session_ctx_t ctx) {
  (void)__sync_fetch_and_add(&(ctx->m_ref_cnt), 1);
}


static inline void
ipsecvsw_session_ctx_decref(ipsecvsw_session_ctx_t ctx) {
  (void)__sync_fetch_and_sub(&(ctx->m_ref_cnt), 1);
}





#endif /* !IPSECVSW_H */
