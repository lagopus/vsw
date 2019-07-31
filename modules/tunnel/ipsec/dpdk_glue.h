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

#ifndef DPDK_GLUE_H
#define DPDK_GLUE_H

/* DPDK version Compatibility */
#if RTE_VER_YEAR < 18
#define cryptodev_get_private_session_size(_cdev_id) \
  rte_cryptodev_get_private_session_size(_cdev_id)

void static inline
cryptodev_attach_sym_session(struct rte_cryptodev_info *cdev_info,
                             uint16_t q_id,
                             ipsecvsw_session_ctx_t *ctx_ptr) {
  int32_t r = 0;

  if (unlikely(cdev_info->sym.max_nb_sessions_per_qp > 0)) {
    r = rte_cryptodev_queue_pair_attach_sym_session(
        (*ctx_ptr)->m_dev_id, q_id, (*ctx_ptr)->m_session);
    if (unlikely(r < 0)) {
      lagopus_free_on_numanode((void *)(*ctx_ptr));
      *ctx_ptr = NULL;
    }
  }
}

void static inline
cryptodev_detach_sym_session(struct rte_cryptodev_info *cdev_info,
                             ipsecvsw_session_ctx_t ctx) {
  uint16_t q_id;

  if (unlikely(cdev_info->sym.max_nb_sessions_per_qp > 0)) {
    if (ctx->m_q != NULL) {
      if (unlikely((q_id = ipsecvsw_cdevq_get_queue_id(ctx->m_q)) >= 0)) {
        rte_cryptodev_queue_pair_detach_sym_session (
            ctx->m_dev_id, q_id, ctx->m_session);
      }
    }
  }
}

#else /* RTE_VER_YEAR >= 18 */
uint32_t static inline
cryptodev_get_private_session_size(uint8_t cdev_id) {
  void *sec_ctx;
  uint32_t sess_sz, max_sess_sz;

  /* Get crypto priv session size */
  max_sess_sz = rte_cryptodev_sym_get_private_session_size(cdev_id);

  /* Get security context of the crypto device */
  sec_ctx = rte_cryptodev_get_sec_ctx(cdev_id);
  if (sec_ctx != NULL) {
    /* Get size of security session */
    sess_sz = rte_security_session_get_size(sec_ctx);
    if (sess_sz > max_sess_sz) {
      max_sess_sz = sess_sz;
    }
  }

  return max_sess_sz;
}

#define cryptodev_attach_sym_session(_cdev_info, _q_id, _ctx_ptr)
#define cryptodev_detach_sym_session(_cdev_info, _ctx)
#endif /* RTE_VER_YEAR */

#endif /* DPDK_GLUE_H */
