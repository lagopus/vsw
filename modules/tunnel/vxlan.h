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

#ifndef VXLAN_H
#define VXLAN_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "lagopus_types.h"
#include "lagopus_error.h"
#include "tunnel.h"
#include "runtime.h"

#define VXLAN_MODULE_NAME "vxlan"

// NOTE: RFC 7348.
#define VXLAN_DEFAULT_UDP_DST_PORT (4789)
#define VXLAN_DEFAULT_IP_OFFSET (0) /* DF is 0. */
#define VXLAN_VALID_VNI (0x08000000)
#define VXLAN_VALID_VNI_MASK VXLAN_VALID_VNI
#define VXLAN_VNI_MASK (0xffffff00)
#define VXLAN_UDP_PORT_MIN (49152)
#define VXLAN_UDP_PORT_MAX (65535)

/*
 * VXLAN.
 */

/**
 * Encap VXLAN header.
 *
 * @param[in] m               mbuf.
 * @param[in] vni             VXLAN Network ID.
 * @param[out] out_vxlan_hdr  A pointer to a outer UDP header returns. (NULL allowed)
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_NO_MEMORY Failed.
 */
static inline lagopus_result_t
encap_vxlan(struct rte_mbuf *m, uint32_t vni,
            struct vxlan_hdr **out_vxlan_hdr) {
  struct vxlan_hdr *vxlan_hdr;

  if (unlikely(m == NULL)) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  vxlan_hdr = (struct vxlan_hdr *) rte_pktmbuf_prepend(m,
              sizeof(struct vxlan_hdr));
  if (unlikely(vxlan_hdr == NULL)) {
    TUNNEL_ERROR("rte_pktmbuf_prepend failed");
    return LAGOPUS_RESULT_NO_MEMORY;
  }

  vxlan_hdr->vx_flags = htonl(VXLAN_VALID_VNI);
  vxlan_hdr->vx_vni = htonl(vni << 8);

  if (out_vxlan_hdr != NULL) {
    *out_vxlan_hdr = vxlan_hdr;
  }

  return LAGOPUS_RESULT_OK;
}

/**
 * Decap VXLAN header.
 *
 * @param[in]  m              mbuf.
 * @param[in] vni             VXLAN Network ID.
 * @param[out] out_vxlan_hdr  A pointer to a outer UDP header returns. (NULL allowed)
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_INVALID_OBJECT Failed.
 * @retval LAGOPUS_RESULT_TOO_SHORT Failed.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 */
static inline lagopus_result_t
decap_vxlan(struct rte_mbuf *m, uint32_t vni,
            struct vxlan_hdr **out_vxlan_hdr) {
  struct vxlan_hdr *vxlan_hdr;
  uint32_t vx_vni, vx_flags_i;

  if (unlikely(m == NULL)) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  if (unlikely(m->pkt_len < sizeof(struct vxlan_hdr))) {
    TUNNEL_ERROR("Bad packet length");
    return LAGOPUS_RESULT_TOO_SHORT;
  }

  /* outer. */
  vxlan_hdr = rte_pktmbuf_mtod(m, struct vxlan_hdr *);

  /* Check flags(I). Ignore reserved fields. */
  vx_flags_i = ntohl(vxlan_hdr->vx_flags) & VXLAN_VALID_VNI_MASK;
  if (unlikely(vx_flags_i != VXLAN_VALID_VNI)) {
    TUNNEL_ERROR("Bad flags, %"PRIu32" != %"PRIu32,
                 vx_flags_i, VXLAN_VALID_VNI);
    return LAGOPUS_RESULT_INVALID_OBJECT;
  }

  /* Check VNI. Ignore reserved fields. */
  vx_vni = (ntohl(vxlan_hdr->vx_vni) & VXLAN_VNI_MASK) >> 8;
  if (unlikely(vx_vni != vni)) {
    TUNNEL_ERROR("Bad VNI, %"PRIu32" != %"PRIu32,
                 vx_vni, vni);
    return LAGOPUS_RESULT_INVALID_OBJECT;
  }

  /* inner. */
  if (unlikely(rte_pktmbuf_adj(m, sizeof(struct vxlan_hdr)) == NULL)) {
    TUNNEL_ERROR("rte_pktmbuf_adj failed");
    return LAGOPUS_RESULT_ANY_FAILURES;
  }

  if (out_vxlan_hdr != NULL) {
    *out_vxlan_hdr = vxlan_hdr;
  }

  return LAGOPUS_RESULT_OK;
}

extern struct vsw_runtime_ops vxlan_inbound_runtime_ops;
extern struct vsw_runtime_ops vxlan_outbound_runtime_ops;

#endif // VXLAN_H
