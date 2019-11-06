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

#ifndef SA_H
#define SA_H

#include <stdint.h>
#include <rte_crypto.h>
#include <rte_atomic.h>

#include "lagopus_apis.h"
#include "ipsec.h"
#include "hash.h"

#define MAX_KEY_SIZE (32)

#define IV_OFFSET ((sizeof(struct rte_crypto_op) +      \
                    sizeof(struct rte_crypto_sym_op)))

#define AEAD_AES_GCM_IV_LENGTH (12)
#define CIPHER_AES_CTR_IV_LENGTH (16)

#define UNKNOWN_ALGORITHM (0)

#define SA_IS_NAT_T(sa) ((sa)->encap_proto != 0 ? true : false)

enum cipher_algo_type {
  CIPHER_ALGO_UNKNOWN = 0,
  CIPHER_ALGO_NULL,
  CIPHER_ALGO_AES_256_CBC,
  CIPHER_ALGO_AES_128_CBC,
  CIPHER_ALGO_AES_128_CTR,
  CIPHER_ALGO_3DES_CBC,

  CIPHER_ALGO_MAX
};

enum aead_algo_type {
  AEAD_ALGO_UNKNOWN = 0,
  AEAD_ALGO_AES_128_GCM,

  AEAD_ALGO_MAX
};

enum auth_algo_type {
  AUTH_ALGO_UNKNOWN = 0,
  AUTH_ALGO_NULL,
  AUTH_ALGO_SHA1_HMAC,
  AUTH_ALGO_SHA256_128_HMAC,

  AUTH_ALGO_MAX
};

struct ipsecvsw_session_gc_ctx_record;
typedef struct ipsecvsw_session_gc_ctx_record *ipsecvsw_session_gc_ctx_t;

/**
 * information of supported Cipher algorithm.
 */
struct supported_cipher_algo {
  const char *keyword;                   /*< name */
  enum rte_crypto_cipher_algorithm algo; /*< algo */
  enum cipher_algo_type atype;
  uint16_t iv_len;
  uint16_t block_size;
  uint16_t key_len;
};

/**
 * get informations of supported Cipher Algorithms
 *
 *  @param[out]     len             num of informations
 *
 *  @retval got informations
 */
const struct supported_cipher_algo *
get_supported_cipher_algos(size_t *len);

/**
 * information of supported Auth algorithm.
 */
struct supported_auth_algo {
  const char *keyword;                 /*< name */
  enum rte_crypto_auth_algorithm algo; /*< algo */
  enum auth_algo_type atype;
  uint16_t digest_len;
  uint16_t key_len;
  uint8_t key_not_req;
};


/**
 * get informations of supported Auth Algorithms
 *
 *  @param[out]     len             num of informations
 *
 *  @retval got informations
 */
const struct supported_auth_algo *
get_supported_auth_algos(size_t *len);


/**
 * information of supported AEAD algorithm.
 */
struct supported_aead_algo {
  const char *keyword;
  enum rte_crypto_aead_algorithm algo;
  enum aead_algo_type atype;
  uint16_t iv_len;
  uint16_t block_size;
  uint16_t digest_len;
  uint16_t key_len;
  uint8_t aad_len;
};

/**
 * get informations of supported AEAD Algorithms
 *
 *  @param[out]     len             num of informations
 *
 *  @retval got informations
 */
const struct supported_aead_algo *
get_supported_aead_algos(size_t *len);

/**
 * static data of SA.
 *
 *   (*) ... Dynamic data that is used only in SAs copied for session
 */
struct ipsec_sa {
  uint32_t spi;
  uint32_t cdev_id_qp;          /*< Queue(*) */
  uint64_t seq;                 /*< sequence(*) */
  uint64_t hash;
  uint32_t salt;
#ifdef NO_SESSION_CTX
  struct rte_cryptodev_sym_session *crypto_session;
#endif /* NO_SESSION_CTX */
  enum rte_crypto_cipher_algorithm cipher_algo;
  enum rte_crypto_auth_algorithm auth_algo;
  enum rte_crypto_aead_algorithm aead_algo;
  uint16_t digest_len;
  uint16_t iv_len;
  uint16_t block_size;
  uint16_t flags;
#define IP4_TUNNEL (1 << 0)
#define IP6_TUNNEL (1 << 1)
#define TRANSPORT  (1 << 2)
  // TBD: address mask
  struct ip_addr src;
  struct ip_addr dst;
  uint8_t encap_proto;    /*< For NAT-T */
  uint16_t encap_src_port; /*< For NAT-T */
  uint16_t encap_dst_port; /*< For NAT-T */
  uint8_t cipher_key[MAX_KEY_SIZE];
  uint16_t cipher_key_len;
  uint8_t auth_key[MAX_KEY_SIZE];
  uint16_t auth_key_len;
  uint16_t aad_len;
  struct rte_crypto_sym_xform *xforms; /*< =xf[x].a */
} __rte_cache_aligned;
typedef struct ipsec_sa *ipsec_sa_t;

/**
 * current lifetimes of SA.
 */
struct ipsec_sa_lifetime {
  lagopus_chrono_t time_current;      /*< current lifetime [not immutable] */
  uint64_t byte_current; /*< current lifetime(byte) [not immutable] */
};

/**
 * SADB_ACQUIRE info
 */
struct sadb_acquire {
  uint8_t ip_ver;
  uint32_t sp_entry_id;
  struct ip_addr src;
  struct ip_addr dst;
  // XXX: mask, port, etc
};

/**
 * SAD
 */
struct ipsec_sadb {
  struct ipsec_sa db[IPSEC_SA_MAX_ENTRIES];  /*< SAD for lookup */
  rte_atomic16_t refs;
};

/**
 * SAD context
 */
struct sa_ctx {
  uint64_t current;
  rte_atomic64_t seq;
  struct ipsec_sadb sadb[2]; /*< SAD for lookup */
  struct ipsec_sa_lifetime
    lifetime[IPSEC_SA_MAX_ENTRIES]; /*< current lifetimes */
  struct sadb_acquire acquire[IPSEC_SA_MAX_ENTRIES]; /*< for SADB_ACQUIRE */
  struct ipsecvsw_session_ctx_record *session_ctx[IPSEC_SA_MAX_ENTRIES];
  struct {
    struct rte_crypto_sym_xform a; /*< first xform (=sa[x].xforms) */
    struct rte_crypto_sym_xform b; /*< next xform */
  } xf[IPSEC_SA_MAX_ENTRIES];   /*< xforms */
};
typedef struct sa_ctx *sad_t;

#define SAD_GET_DB(sad_t, index) ((sad_t)->sadb[(index)])
#define SAD_CURRENT(sad_t) (SAD_GET_DB((sad_t), (sad_t)->current))
#define SAD_MODIFIED(sad_t) (SAD_GET_DB((sad_t), ((sad_t)->current + 1) % 2))

/**
 * copy all sadb_acquire records to buf.
 *
 * required: buf needs to be allocated with sufficient size.
 *
 *  @param[in]      sad             SAD pointer
 *  @param[out]     buf             buffer to copy
 *
 *  @retval LAGOPUS_RESULT_OK               Succeeded.
 *  @retval LAGOPUS_RESULT_INVALID_ARGS     Failed, invalid args.
 *  @retval LAGOPUS_RESULT_ANY_FAILURES     Failed.
 */
lagopus_result_t
sad_get_acquires(sad_t sad, struct sadb_acquire *buf);

/**
 * get SAs defined in config file.
 *
 * required: parse_cfg_file() is called before.
 *
 *  @param[out]     sas             SA array.
 *  @param[in]      role            SAD role (inbound/outbound)
 *
 *  @retval num of SAs
 */
size_t
get_parsed_config(ipsec_sa_t *sas, const ipsecvsw_queue_role_t role);

/**
 * check if SPI in mbuf matches SA which specified index.
 *
 *  @param[in]      sad             SAD pointer
 *  @param[in]      m               mbuf
 *  @param[in]      sa_idx          index of SA
 *
 *  @retval true                    matched
 *  @retval false                   not matched
 */
bool
inbound_sa_check(const sad_t sad,
                 const struct rte_mbuf *m,
                 const uint32_t sa_idx);

/**
 * lookup SAD for inbound. (and attach Session for SAs if neccessary)
 *
 *  @param[in]              tid             thread ID
 *  @param[in,out]          sad             SAD pointer
 *  @param[in]              pkts            lookup targets
 *  @param[in]              nb_pkts         num of sa_idx[] (= num of sa[])
 *  @param[in]              now             current time
 *  @param[out]             sctx            got sessions
 */
void
inbound_sa_lookup(const pthread_t tid,
                  sad_t sad,
                  const struct rte_mbuf *pkts[],
                  const size_t nb_pkts,
                  const lagopus_chrono_t now,
                  ipsecvsw_session_ctx_t sctx[]);

/**
 * lookup SAD for outbound. (and attach Session for SAs if neccessary)
 *
 *  @param[in]              tid             thread ID
 *  @param[in,out]          sad             SAD pointer
 *  @param[in]              sa_idx          indexes of lookup targets
 *                                          in SA table (it is array
 *                                          index, not SPI.)
 *  @param[in]              pkts            packets
 *  @param[in]              nb_pkts         num of sa_idx[] (= num of sa[])
 *  @param[in]              now             current time
 *  @param[out]             sctx            got sessions
 */
void
outbound_sa_lookup(const pthread_t tid,
                   sad_t sad,
                   const uint32_t sa_idx[],
                   const struct rte_mbuf *pkts[],
                   const size_t nb_pkts,
                   const lagopus_chrono_t now,
                   ipsecvsw_session_ctx_t sctx[]);

/**
 * create and initialize SAD.
 *
 *  @param[out]     sad             SAD pointer
 *  @param[in]      socket_id       socket ID
 *  @param[in]      role            SAD role (inbound/outbound)
 *
 *  @retval LAGOPUS_RESULT_OK               Succeeded.
 *  @retval LAGOPUS_RESULT_NO_MEMORY        Failed, allocation error.
 *  @retval LAGOPUS_RESULT_INVALID_ARGS     Failed, invalid args.
 *  @retval LAGOPUS_RESULT_ALREADY_EXISTS   Failed, confricts SPI
 *  @retval LAGOPUS_RESULT_ANY_FAILURES     Failed.
 */
lagopus_result_t
sad_init(sad_t *sad,
         const uint32_t socket_id,
         const ipsecvsw_queue_role_t role);

/**
 * finalize SAD.
 *
 *  @param[in,out]  sad             SAD pointer
 *  @param[in]      role            SAD role (inbound/outbound)
 *  @param[in]      tid             thread ID
 *  @param[in]      gctx            session gc context
 */
void
sad_finalize(sad_t ctx,
             const ipsecvsw_queue_role_t role,
             const pthread_t tid,
             ipsecvsw_session_gc_ctx_t gctx);

/**
 * pre process.
 *
 *  @param[in]      sad             SAD pointer
 *  @param[in]      role            SAD role (inbound/outbound)
 *  @param[in]      tid             thread ID
 *  @param[in]      gctx            session gc context
 *
 *  @retval LAGOPUS_RESULT_OK               Succeeded.
 *  @retval LAGOPUS_RESULT_INVALID_ARGS     Failed, invalid args.
 *  @retval LAGOPUS_RESULT_ANY_FAILURES     Failed.
 */
lagopus_result_t
sad_pre_process(sad_t sad,
                const ipsecvsw_queue_role_t role,
                const pthread_t tid,
                ipsecvsw_session_gc_ctx_t gctx);

/**
 * post process.
 *
 *  @param[in]      sad             SAD pointer
 *
 *  @retval LAGOPUS_RESULT_OK               Succeeded.
 *  @retval LAGOPUS_RESULT_INVALID_ARGS     Failed, invalid args.
 *  @retval LAGOPUS_RESULT_ANY_FAILURES     Failed.
 */
lagopus_result_t
sad_post_process(sad_t sad);

/**
 * add SA rules to SAD.
 *
 *  @param[in,out]  sad             SAD pointer
 *  @param[in]      entries         array of SA rules
 *  @param[in]      role            SAD role (inbound/outbound)
 *
 *  @retval LAGOPUS_RESULT_OK               Succeeded.
 *  @retval LAGOPUS_RESULT_INVALID_ARGS     Failed, invalid args.
 *  @retval LAGOPUS_RESULT_ALREADY_EXISTS   Failed, confricts SPI
 *  @retval LAGOPUS_RESULT_ANY_FAILURES     Failed.
 */
lagopus_result_t
sad_push(sad_t sad,
         const struct ipsec_sa entries[],
         const size_t nb_entries,
         const ipsecvsw_queue_role_t role);

#endif /* SA_H */
