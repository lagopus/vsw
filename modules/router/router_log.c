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

/**
 *      @file   router_log.c
 *      @brief  Debug log utilities.
 */

#include <arpa/inet.h>
#include <netinet/in.h>

#include <rte_config.h>
#include <rte_ip.h>

#include "logger.h"
#include "router_log.h"

#define ETHADDR_STRLEN 18

// Have buffer for each core.
static char ipstr[RTE_MAX_LCORE][INET_ADDRSTRLEN];
static char macstr[RTE_MAX_LCORE][ETHADDR_STRLEN];

/**
 * Convert IP address(uint32_t) to string(char *).
 * This function use the inet_ntop(),
 * do not make multiple calls on the save line.
 */
char *
ip2str(uint32_t addr) {
	unsigned id = rte_lcore_id();
	uint32_t ip = htonl(addr);
	inet_ntop(AF_INET, &ip, ipstr[id], INET_ADDRSTRLEN);
	return ipstr[id];
}

/**
 * Convert MAC address(struct ether_addr) to string(char *).
 */
char *
mac2str(struct ether_addr mac) {
	unsigned id = rte_lcore_id();
	ether_format_addr(macstr[id], ETHADDR_STRLEN, &mac);
	return macstr[id];
}

