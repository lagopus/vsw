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

#ifndef VSW_MODULE_ROUTER_ROUTER_CONFIG_H_
#define VSW_MODULE_ROUTER_ROUTER_CONFIG_H_

/* maximum number of router instances */
#define ROUTER_MAX_ROUTERS 256

/* size of input ring of router instance */
#define ROUTER_MAX_MBUFS 1024

/* maximum number of VIF per router instance */
#define ROUTER_MAX_VIFS 32

/* minimum number of table that holds packet forwarding rules */
#define ROUTER_RULE_BASE_SIZE 16

/* maximum number of packet forward rules per router instance */
/* ROUTER_MAX_RULES must be a multiple of ROUTER_RULE_BASE_SIZE */
#define ROUTER_MAX_RULES (ROUTER_RULE_BASE_SIZE * 64)

/* maximum number of IP addresses per VIF */
#define ROUTER_MAX_VIF_IPADDRS 64

/* maximum number of nexthops in PBR action */
#define ROUTER_MAX_PBR_NEXTHOPS 16

/* maximum number of neighbor cache entries per VIF */
#define ROUTER_MAX_NEIGHBOR_ENTRIES 1024

#endif /* !VSW_MODULE_ROUTER_ROUTER_CONFIG_H_ */

