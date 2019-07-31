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

#ifndef MBUF_H
#define MBUF_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

#include "lagopus_types.h"
#include "lagopus_error.h"
#include "logger.h"
#include "packet.h"
#include "tunnel.h"

#define MBUF_CACHE_SIZE (256)

static inline struct rte_mbuf *
mbuf_alloc_indirect(struct rte_mbuf *src, struct rte_mempool *pool) {
  struct rte_mbuf *mbuf;

  mbuf = rte_pktmbuf_alloc(pool);
  if (unlikely(mbuf == NULL)) {
    TUNNEL_ERROR("mbuf is NULL");
    return NULL;
  }

  *mbuf = *src;
  rte_mbuf_refcnt_set(mbuf, 1);
  mbuf->pool = pool;
  mbuf->ol_flags |= IND_ATTACHED_MBUF;

  return mbuf;
}

/* Public. */

/**
 * Create mempool.
 *
 * @param[in,out] pool        A pointer to a mempool.
 * @param[in] prefix          Prefix for name of mempool.
 * @param[in] n               The number of elements in the mbuf pool.
 * @param[in] data_room_size  Size of data buffer in each mbuf.
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_NO_MEMORY Failed.
 */
static inline lagopus_result_t
mbuf_create_mempool(struct rte_mempool **pool, const char *prefix,
                    unsigned n, uint16_t data_room_size) {
  char pool_name[RTE_MEMZONE_NAMESIZE];
  int socket_id = rte_socket_id();

  snprintf(pool_name, RTE_MEMZONE_NAMESIZE, "%s-%d", prefix, socket_id);
  *pool = rte_pktmbuf_pool_create(pool_name, n, MBUF_CACHE_SIZE,
                                  PACKET_METADATA_SIZE,
                                  data_room_size, socket_id);
  if (unlikely(*pool == NULL)) {
    TUNNEL_ERROR("rte_pktmbuf_pool_create failed");
    return LAGOPUS_RESULT_NO_MEMORY;
  }
  return LAGOPUS_RESULT_OK;
}

/**
 * Destroy mempool.
 *
 * @param[in] pool        A pointer to a mempool.
 */
static inline void
mbuf_destroy_mempool(struct rte_mempool *pool) {
  if (pool != NULL) {
    rte_mempool_free(pool);
  }
}

/**
 * Clone mbuf.
 *
 * @param[in,out] dst         A pointer to a mbuf(dst).
 * @param[in] src             A pointer to a mbuf(src).
 * @param[in] pool            A pointer to a mempool.
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_NO_MEMORY Failed.
 *
 * @detail Fig.
 *                  +-------------+------+--+---------------
 *  indirect mbuf   | mbuf header |      |  |
 *                  +-------------+------+--+---------------
 *                  ^   *(buf_addr + data_off) -------------------+
 *                  |                                             |
 *                  +----------+                                  |
 *                             |                                  |
 *                          *(next)                               |
 *                  +-------------+------+--+--------------+---   |
 *  dst mbuf        | mbuf header | mata |  | ether header |      |
 *                  +-------------+------+--+--------------+---   |
 *                                 ^         ^                    |
 *                                 |         |             +------+
 *                                 |         |             |
 *                                 |copy     |copy         V
 *                  +-------------+------+--+--------------+---
 *  src mbuf        | mbuf header | mata |  |(ether header)| IP header ...
 *                  +-------------+------+--+--------------+---
 *
 */
static inline lagopus_result_t
mbuf_clone(struct rte_mbuf **dst,
           struct rte_mbuf *src,
           struct rte_mempool *pool) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct ether_hdr *src_ether_hdr, *dst_ether_hdr;
  struct rte_mbuf *new_mbuf = NULL;
  struct rte_mbuf *indirect_mbuf = NULL;
  struct vsw_packet_metadata *src_metadata;
  struct vsw_packet_metadata *dst_metadata;

  src_ether_hdr = rte_pktmbuf_mtod(src, struct ether_hdr *);
  src_metadata = VSW_MBUF_METADATA(src);

  new_mbuf = rte_pktmbuf_alloc(pool);
  if (unlikely(new_mbuf == NULL)) {
    TUNNEL_ERROR("rte_pktmbuf_alloc failed");
    ret = LAGOPUS_RESULT_NO_MEMORY;
    goto done;
  }

  indirect_mbuf = mbuf_alloc_indirect(src, pool);
  if (unlikely(indirect_mbuf == NULL)) {
    TUNNEL_ERROR("mbuf_alloc_indirect failed");
    ret = LAGOPUS_RESULT_NO_MEMORY;
    goto done;
  }

  dst_ether_hdr = (struct ether_hdr *)rte_pktmbuf_prepend(new_mbuf,
                  sizeof(struct ether_hdr));
  if (unlikely(dst_ether_hdr == NULL)) {
    TUNNEL_ERROR("rte_pktmbuf_prepend failed");
    ret = LAGOPUS_RESULT_NO_MEMORY;
    goto done;
  }
  memcpy(dst_ether_hdr, src_ether_hdr, sizeof(struct ether_hdr));

  if (unlikely(rte_pktmbuf_adj(indirect_mbuf,
                               sizeof(struct ether_hdr)) == NULL)) {
    TUNNEL_ERROR("rte_pktmbuf_adj failed");
    ret = LAGOPUS_RESULT_NO_MEMORY;
    goto done;
  }

  new_mbuf->next = indirect_mbuf;

  new_mbuf->pkt_len = (uint16_t) (new_mbuf->data_len + indirect_mbuf->pkt_len);
  new_mbuf->nb_segs = (uint8_t) (indirect_mbuf->nb_segs + 1);
  new_mbuf->port = src->port;
  new_mbuf->vlan_tci = src->vlan_tci;
  new_mbuf->vlan_tci_outer = src->vlan_tci_outer;
  new_mbuf->tx_offload = src->tx_offload;
  new_mbuf->hash = src->hash;

  // copy metadata.
  dst_metadata = VSW_MBUF_METADATA(new_mbuf);
  *dst_metadata = *src_metadata;

  *dst = new_mbuf;

  ret = LAGOPUS_RESULT_OK;

done:
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    if (indirect_mbuf != NULL) {
      rte_pktmbuf_free(indirect_mbuf);
    }
    if (new_mbuf != NULL) {
      rte_pktmbuf_free(new_mbuf);
    }
  }

  return ret;
}

#endif // MBUF_H
