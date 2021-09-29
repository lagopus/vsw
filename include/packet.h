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

#ifndef VSW_PACKET_H_
#define VSW_PACKET_H_

#include <stdbool.h>
#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint16_t vifindex_t;
typedef uint16_t vrfindex_t;

#define VIF_INVALID_INDEX	0
#define VIF_MAX_INDEX		4095	   // Valid VIF index is from 1 to VIF_MAX_INDEX
#define VIF_BROADCAST		0xfffffffc // OFPP_ALL

#define VRF_MAX_ENTRY		256	   // A maximum number of VRF entries

#define BRIDGE_INVALID_ID	0
#define BRIDGE_MAX_ID		1023	   // Valid Bridge ID is from 1 to BRIDGE_MAX_ID

#define MAX_PACKET_SZ 2048
#define PACKET_METADATA_SIZE (RTE_MBUF_PRIV_ALIGN << 6)	// Shall be a multiple of RTE_MBUF_PRIV_ALIGN

#define VSW_MBUF_METADATA(mbuf) (struct vsw_packet_metadata*)((void*)(mbuf) + sizeof(struct rte_mbuf))

typedef enum {
	// The packet should be processed by MAT. Used by bridge module only.
	VSW_MD_MAT			= (1 << 1),
} vsw_md_flag_t;

struct vsw_packet_metadata {
	struct vsw_common_metadata {
		vifindex_t in_vif;
		vifindex_t out_vif;

		vsw_md_flag_t flags;	// Or'd VSW_MD_*

		bool keep_ttl;		// Set to true to preserve the current TTL, i.e. do not decrement TTL.
		bool encap;		// Set to true for the packet encapsulated by tunnel module.
		bool to_tap;		// If True, send this packet to the TAP.
	} common;
	uint8_t udata[PACKET_METADATA_SIZE - sizeof(struct vsw_common_metadata)];
};

#ifdef __cplusplus
}
#endif

#endif // VSW_PACKET_H_
