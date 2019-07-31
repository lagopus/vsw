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

#ifndef VLAN_H
#define VLAN_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

#include "lagopus_types.h"
#include "lagopus_error.h"
#include "tunnel.h"

#define VID_MASK (0x0fff)

/**
 * Set unstripped (unset PKT_RX_VLAN_STRIPPED) in mbuf metadata.
 * And set vlan_tci in VLAN header.
 *
 * @param[in]  m         mbuf.
 * @param[in]  vlan_hdr  A pointer to a VLAN header.
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 */
static inline lagopus_result_t
vlan_set_unstripped(struct rte_mbuf *m, struct vlan_hdr *vlan_hdr) {
  if (unlikely(m == NULL || vlan_hdr == NULL)) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  vlan_hdr->vlan_tci = htons(m->vlan_tci);
  m->ol_flags &= ~PKT_RX_VLAN_STRIPPED;
  return LAGOPUS_RESULT_OK;
}

/**
 * Set stripped (PKT_RX_VLAN_STRIPPED, PKT_RX_VLAN) in mbuf metadata.
 * And set vlan_tci in mbuf metadata.
 *
 * @param[in]  m         mbuf.
 * @param[in]  vlan_hdr  A pointer to a VLAN header.
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 */
static inline lagopus_result_t
vlan_set_stripped(struct rte_mbuf *m, uint16_t vlan_tci) {
  if (unlikely(m == NULL)) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  m->vlan_tci = vlan_tci;
  m->ol_flags |= PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED;
  return LAGOPUS_RESULT_OK;
}

/**
 * Pop VLAN.
 *
 * @param[in]  m       mbuf.
 * @param[out] vid     A pointer to a vid returns. (NULL allowed.)
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 */
static inline lagopus_result_t
vlan_pop(struct rte_mbuf *m, uint16_t *vid) {
  if (unlikely(m == NULL)) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  if (unlikely(rte_vlan_strip(m) != 0)) {
    TUNNEL_ERROR("Not VLAN packet");
    return LAGOPUS_RESULT_UNSUPPORTED;
  }

  if (vid != NULL) {
    *vid = m->vlan_tci & VID_MASK;
  }

  return LAGOPUS_RESULT_OK;
}

/**
 * Push VLAN.
 *
 * @param[in]  m       mbuf.
 *
 * @retval LAGOPUS_RESULT_OK Succeeded.
 * @retval LAGOPUS_RESULT_INVALID_ARGS Failed, invalid args.
 * @retval LAGOPUS_RESULT_NO_MEMORY Failed.
 * @retval LAGOPUS_RESULT_ANY_FAILURES Failed.
 */
static inline lagopus_result_t
vlan_push(struct rte_mbuf *m) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct vlan_hdr *vlan_hdr;
  struct ether_hdr *org_ether_hdr, *new_ether_hdr;

  if (unlikely(m == NULL)) {
    TUNNEL_ERROR("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  org_ether_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

  new_ether_hdr = (struct ether_hdr *)
                  rte_pktmbuf_prepend(m, sizeof(struct vlan_hdr));
  if (unlikely(new_ether_hdr == NULL)) {
    TUNNEL_ERROR("rte_pktmbuf_prepend failed");
    return LAGOPUS_RESULT_NO_MEMORY;
  }

  memmove(new_ether_hdr, org_ether_hdr, 2 * ETHER_ADDR_LEN);
  new_ether_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);

  vlan_hdr = (struct vlan_hdr *) (new_ether_hdr + 1);

  ret = vlan_set_unstripped(m, vlan_hdr);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    return ret;
  }

  return LAGOPUS_RESULT_OK;
}

#endif // VLAN_H
