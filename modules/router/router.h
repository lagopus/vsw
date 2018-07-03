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

#ifndef __LAGOPUS_MODULES_ROUTER_H__
#define __LAGOPUS_MODULES_ROUTER_H__

#include <stdbool.h>
#include <stdint.h>

#include "router_common.h"
#include "route.h"
#include "arp.h"
#include "interface.h"

#define MAX_ROUTER_REQUESTS	1024

// check packet header
#define VERSION_IPV4 0x04
#define VERSION_IPV6 0x06

struct router_context {
	char		*name;
	uint64_t	vrfidx;
	struct vrf	*vrf;
	struct router_ring rings;
	bool		active;

	struct route_table	*route;
	struct arp_table	*arp;
	struct interface_table	*vif;
};

// Router Runtime
struct router_mempools {
	struct rte_mempool *direct_pool;
	struct rte_mempool *indirect_pool;
};

// Router metadata
struct router_mbuf_metadata {
	struct rte_ring	*ring;
	bool		df;
} __rte_cache_aligned;

// netlink?
#define SCOPE_LINK 253  //RT_SCOPE_LINK



#endif /* __LAGOPUS_MODULES_ROUTER_H__ */
