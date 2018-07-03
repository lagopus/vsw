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

/**
 *      @file   metadata.h
 *      @brief  IPsec metadata.
 */

#ifndef IPSEC_METADATA_H
#define IPSEC_METADATA_H

#include <rte_crypto.h>

struct ipsec_mbuf_metadata {
  uint8_t ttl;
  int8_t tos;
  uint32_t sp_entry_id;
  struct rte_crypto_op cop;
  struct rte_crypto_sym_op sym_cop;
  uint8_t buf[32];
  struct ipsecvsw_session_ctx_record *session_ctx;
} __rte_cache_aligned;
typedef struct ipsec_mbuf_metadata ipsec_mbuf_metadata_t;

#endif /* IPSEC_METADATA_H */
