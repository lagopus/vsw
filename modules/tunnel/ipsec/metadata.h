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

/**
 *      @file   metadata.h
 *      @brief  IPsec metadata.
 */

#ifndef IPSEC_METADATA_H
#define IPSEC_METADATA_H

#include <rte_crypto.h>
#include "tunnel.h"

/* metadata of mbuf.
 *          +---+----------------------+---------------------+---
 * rte_mbuf |...| tunnel_mbuf_metadata | ipsec_mbuf_metadata |...
 *          +---+----------------------+---------------------+---
 *              ^
 *              |
 *              vsw_packet_metadata.udata
 */

struct ipsec_mbuf_metadata {
  uint8_t ttl;
  int8_t tos;
  uint16_t nat_t_len;
  uint32_t sp_entry_id;
  struct rte_crypto_op cop;
  struct rte_crypto_sym_op sym_cop;
  uint8_t buf[32];
  struct ipsecvsw_session_ctx_record *session_ctx;
} __rte_cache_aligned;
TUNNEL_ASSERT(sizeof(struct tunnel_mbuf_metadata) +
              sizeof(struct ipsec_mbuf_metadata) <=
              PACKET_METADATA_SIZE);
typedef struct ipsec_mbuf_metadata ipsec_mbuf_metadata_t;


#define IPSEC_IS_NAT_T(meta) ((meta)->nat_t_len != 0 ? true : false)
#define IPSEC_SET_NAT_T_LEN(meta, len) ((meta)->nat_t_len = (len))
#define IPSEC_GET_NAT_T_LEN(meta) ((meta)->nat_t_len)

#endif /* IPSEC_METADATA_H */
