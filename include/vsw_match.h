/*
 * Copyright 2017 Nippon Telegraph and Telephone Corporation.
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

#ifndef LAGOPUS_VSW_MATCH_
#define LAGOPUS_VSW_MATCH_

typedef enum {
  VSW_VRF_COLOR_VLAN,
} vsw_color_t;


typedef uint16_t vsw_color_vlan_t;
#define VSW_VLAN_NO_TAG 4096

typedef enum {
  VSW_MATCH_ANY,	// default destination
  VSW_MATCH_IN_VIF,	// VIF index
  VSW_MATCH_OUT_VIF,	// VIF index
  VSW_MATCH_BRIDGE_ID,	// Bridge ID
  VSW_MATCH_ETH_DST,
  VSW_MATCH_ETH_DST_SELF,
  VSW_MATCH_ETH_DST_MC,
  VSW_MATCH_ETH_SRC,
  VSW_MATCH_ETH_TYPE_IPV4,
  VSW_MATCH_ETH_TYPE_IPV6,
  VSW_MATCH_ETH_TYPE_ARP,
  VSW_MATCH_ETH_TYPE,
  VSW_MATCH_VLAN_ID,
  VSW_MATCH_IPV4_PROTO,
  VSW_MATCH_IPV4_SRC,
  VSW_MATCH_IPV4_SRC_NET,
  VSW_MATCH_IPV4_DST,
  VSW_MATCH_IPV4_DST_NET,
  VSW_MATCH_IPV4_DST_SELF,
  VSW_MATCH_TP_SRC,
  VSW_MATCH_TP_DST,
} vsw_match_t;


#endif // LAGOPUS_VSW_MATCH_
