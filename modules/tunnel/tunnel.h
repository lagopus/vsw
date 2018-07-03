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

#ifndef __TUNNEL_H__
#define __TUNNEL_H__

#include <stdint.h>
#include <rte_mbuf.h>

#include "lagopus_types.h"
#include "lagopus_error.h"
#include "logger.h"
#include "packet.h"

#define TUNNEL_MODULE_NAME "tunnel"

#define MAX_PKT_BURST (1024)

#define DEFAULT_TTL (0)
#define DEFAULT_TOS (-1)

#define AF_IPV4 (0)
#define AF_IPV6 (1)

#define IP6_VERSION (6)

#define IS_FLOODING(mbuf) ((rte_mbuf_refcnt_read((mbuf)) == 1) ? false : true)

#define uint32_t_to_char(ip, a, b, c, d) do {\
    *a = (uint8_t)(ip >> 24 & 0xff);\
    *b = (uint8_t)(ip >> 16 & 0xff);\
    *c = (uint8_t)(ip >> 8 & 0xff);\
    *d = (uint8_t)(ip & 0xff);\
  } while (0)

struct ip_addr {
  union {
    uint32_t ip4;
    union {
      uint64_t ip6[2];
      uint8_t ip6_b[16];
    } ip6;
  } ip;
};

static inline lagopus_result_t
set_meta_local(struct rte_mbuf *m)
{
  if (m == NULL) {
    lagopus_printf("invalid args");
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  struct lagopus_packet_metadata *metadata = LAGOPUS_MBUF_METADATA(m);
  metadata->md_vif.local = true;

  return LAGOPUS_RESULT_OK;
}

#endif /* __TUNNEL_H__ */
