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

#ifndef IPSEC_H
#define IPSEC_H

#include <stdint.h>

#include <rte_byteorder.h>
#include <rte_crypto.h>
#include <rte_mbuf.h>
#include "lagopus_apis.h"
#include "hash.h"
#include "packet.h"
#include "metadata.h"
#include "tunnel.h"

#define DEFAULT_MAX_CATEGORIES (1)

#define MODULE_NAME "ipsec"

#define VIF_MAX_ENTRY (VIF_MAX_INDEX + 1)

#define DEFAULT_SOCKET_ID (0UL)

/*
 * SP acl.userdata(uint32)
 * (1) DISCARD/BYPASS/RESERVED flags. : 4-bit
 * (2) SP Entry ID. : 12-bit
 * (3) SA Index. : 16-bit (IPSEC_SA_MAX_ENTRIES_BITS < 16)
 * +---+--------------+-----------------+
 * |(1)|      (2)     |       (3)       |
 * +---+--------------+-----------------+
 * 31  28             16                0
 */
#define IPSEC_SA_ENTRIES_BITS (16)
#define IPSEC_SA_MAX_ENTRIES_BITS (7) /* 0 < IPSEC_SA_MAX_ENTRIES_BITS < 16 (tiny). */
#define IPSEC_SA_MAX_ENTRIES (1 << IPSEC_SA_MAX_ENTRIES_BITS) /* must be power of 2, max 2 power 30 */
#define SPI2IDX(spi) (hash_fnv1a32_tiny(spi, IPSEC_SA_MAX_ENTRIES_BITS))
#define INVALID_SPI (0)
#define DISCARD (0x80000000)
#define BYPASS (0x40000000)
#define RESERVED (0x20000000)
#define PROTECT_MASK (0x0000ffff)
#define PROTECT(sa_idx) (SPI2IDX(sa_idx) & PROTECT_MASK) /* SA idx 16 bits */
#define SP_ENTRY_ID_BITS (12)
#define SP_ENTRY_ID_MASK \
  (((1 << SP_ENTRY_ID_BITS) -1) << IPSEC_SA_ENTRIES_BITS) /* 0x0fff0000 */
#define DATA2SP_ENTRY_ID(data) (((data) & SP_ENTRY_ID_MASK) >> IPSEC_SA_ENTRIES_BITS)
#define SP_ENTRY_ID(id) (((id) << IPSEC_SA_ENTRIES_BITS) & SP_ENTRY_ID_MASK)
#define GET_VRF_LAST_INDEX(index, last) (((index) > (last)) ? (index) : (last))

struct ipsec_xform;
struct rte_crypto_xform;
struct rte_cryptodev_session;
struct rte_mbuf;

struct ipsec_sa;
struct sa_ctx;

typedef int32_t (*ipsec_xform_fn)(struct rte_mbuf *m, struct ipsec_sa *sa,
                                  struct rte_crypto_op *cop);

/* port/source ethernet addr and destination ethernet addr */
struct ethaddr_info {
  uint64_t src, dst;
};

struct ipsecvsw_q_record;
typedef struct ipsecvsw_q_record	*ipsecvsw_cdevq_t;

struct ipsecvsw_session_ctx_reqcord;
typedef struct ipsecvsw_session_ctx_record	*ipsecvsw_session_ctx_t;

typedef enum {
  ipsecvsw_queue_dir_unknown = 0,
  ipsecvsw_queue_dir_put = 1,
  ipsecvsw_queue_dir_get = 2
} ipsecvsw_queue_dir_t;

typedef enum {
  ipsecvsw_queue_role_unknown = 0,
  ipsecvsw_queue_role_inbound = 1,
  ipsecvsw_queue_role_outbound = 2
} ipsecvsw_queue_role_t;

struct cnt_blk {
  uint32_t salt;
  uint64_t iv;
  uint32_t cnt;
} __attribute__((packed));

struct ipsec_params {
  ipsecvsw_queue_role_t role;
  bool is_core_bind;
  uint64_t inbound_core_mask;
  uint64_t outbound_core_mask;
};

static inline uint16_t
ipsec_metadata_size(void) {
  return sizeof(struct ipsec_mbuf_metadata);
}

/* get metadata of mbuf.
 *          +---+----------------------+---------------------+---
 * rte_mbuf |...| tunnel_mbuf_metadata | ipsec_mbuf_metadata |...
 *          +---+----------------------+---------------------+---
 *              ^
 *              |
 *              vsw_packet_metadata.udata
 */
static inline struct ipsec_mbuf_metadata *
get_priv(const struct rte_mbuf *m) {
  struct vsw_packet_metadata *lm = VSW_MBUF_METADATA(m);
  return (struct ipsec_mbuf_metadata *) ((void *) (lm->udata) +
         sizeof(struct tunnel_mbuf_metadata));
}

static inline void *
get_cnt_blk(const struct rte_mbuf *m) {
  struct ipsec_mbuf_metadata *priv = get_priv(m);

  return &priv->buf[0];
}

static inline void *
get_aad(struct rte_mbuf *m) {
  struct ipsec_mbuf_metadata *priv = get_priv(m);

  return &priv->buf[16];
}

static inline void *
get_sym_cop(struct rte_crypto_op *cop) {
  return (cop + 1);
}

uint32_t
spi2sa_index(uint32_t spi);

struct module;

struct spd4 *
ipsec_get_spd4(struct module *module, vrfindex_t vrf_index);

struct spd6 *
ipsec_get_spd6(struct module *module, vrfindex_t vrf_index);

struct sa_ctx **
ipsec_get_sad(struct module *module, vrfindex_t vrf_index);

struct ifaces *
ipsec_get_ifaces(struct module *module);

lagopus_result_t
ipsec_add_ethaddr(uint8_t port,
                  struct ethaddr_info *info);

lagopus_result_t
ipsec_mainloop(struct module *myself);

lagopus_result_t
ipsec_configure(struct module *myself, void *p);

void
ipsec_unconfigure(struct module *myself);

void
ipsec_stop(struct module *myself);

#endif /* IPSEC_H */
