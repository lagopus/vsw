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
#ifndef VSW_MODULE_ROUTER_NAPT_H_
#define VSW_MODULE_ROUTER_NAPT_H_

#include <rte_mbuf.h>

#include "packet.h"

struct napt;

/**
 * NAPT configuration
 */
struct napt_config {
	uint32_t wan_addr;     /**< external address */
	uint16_t port_min;     /**< minimum TU port */
	uint16_t port_max;     /**< maximum TU port */
	uint16_t max_entries;  /**< maximum # of entries */
	uint16_t aging_time;   /**< aging time */
	uint16_t frag_entries; /*<< maximum fragment entries */
	vifindex_t vif;	/**< VIF index */
};

/**
 * Create symmetric NAPT
 */
extern struct napt *napt_create(struct napt_config *config);

/**
 * Free NAPT
 */
extern void napt_free(struct napt *napt);

/**
 * Process outbound mbuf
 *
 * mbuf SHALL refer to valid IPv4 packet
 */
extern bool napt_outbound(struct napt *napt, struct rte_mbuf *mbuf);

/**
 * Process inbound mbuf
 *
 * mbuf SHALL refer to valid IPv4 packet
 */
extern bool napt_inbound(struct napt *napt, struct rte_mbuf *mbuf);

#endif /* !VSW_MODULE_ROUTER_NAPT_H_ */
