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

#ifndef __L2_H__
#define __L2_H__

#include <rte_ether.h>
#include <rte_mbuf.h>

#include "lagopus_types.h"
#include "lagopus_error.h"
#include "logger.h"
#include "tunnel.h"

/**
 * Encap VXLAN header.
 *
 * @param[in] m mbuf.
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 */
static inline lagopus_result_t
encap_vxlan(struct rte_mbuf *m)
{
  return LAGOPUS_RESULT_UNSUPPORTED;
}

/**
 * Decap VXLAN header.
 *
 * @param[in] m mbuf.
 * @param[in] offset header offset.(in bytes, zero allowed.)
 * @param[out] out A pointer to a Ethernet header returns.(NULL allowed.)
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 *
 * @details the *out is mbuf pointer, attention is required when operating.
 */
static inline lagopus_result_t
decap_vxlan(struct rte_mbuf *m)
{
  return LAGOPUS_RESULT_UNSUPPORTED;
}

/**
 * Encap Ethernet header.
 *
 * @param[in] m mbuf.
 * @param[in] ether_type EtherType
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 */
static inline lagopus_result_t
encap_ether(struct rte_mbuf *m, uint16_t ether_type)
{
  struct ether_hdr *out_ether;

  if (m == NULL) {
    lagopus_printf("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  out_ether = (struct ether_hdr *) rte_pktmbuf_prepend(m, ETHER_HDR_LEN);
  if (out_ether == NULL) {
    lagopus_printf("rte_pktmbuf_prepend failed");
    return LAGOPUS_RESULT_NO_MEMORY;
  }

  struct ether_addr addr = {0};
  out_ether->d_addr = addr;
  out_ether->s_addr = addr;
  out_ether->ether_type = rte_cpu_to_be_16(ether_type);

  return LAGOPUS_RESULT_OK;
}

/**
 * Decap Ethernet header.
 *
 * @param[in] m mbuf.
 * @param[in] offset header offset.(in bytes, zero allowed.)
 * @param[out] out A pointer to a Ethernet header returns.(NULL allowed.)
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 *
 * @details the *out is mbuf pointer, attention is required when operating.
 */
static inline lagopus_result_t
decap_ether(struct rte_mbuf *m, struct ether_hdr **out)
{
  char *next;
  struct ether_hdr *ether_hdr;

  if (m == NULL) {
    lagopus_printf("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  ether_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
  if (ether_hdr == NULL) {
    lagopus_printf("rte_pktmbuf_mtod failed");
    return LAGOPUS_RESULT_ANY_FAILURES;
  }

  next = rte_pktmbuf_adj(m, ETHER_HDR_LEN);
  if (next == NULL) {
    lagopus_printf("rte_pktmbuf_adj failed");
    return LAGOPUS_RESULT_ANY_FAILURES;
  }

  if (out != NULL) {
    *out = ether_hdr;
  }

  return LAGOPUS_RESULT_OK;
}

#endif /* __L2_H__ */
