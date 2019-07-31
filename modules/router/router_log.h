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

#ifndef VSW_MODULES_ROUTER_LOG_H_
#define VSW_MODULES_ROUTER_LOG_H_

#include "logger.h"
#include <rte_ether.h>

extern uint32_t router_log_id;

#define ROUTER_DEBUG(fmt, x...) vsw_msg_debug(router_log_id, 0, fmt, ##x)
#define ROUTER_INFO(fmt, x...) vsw_msg_info(router_log_id, fmt, ##x)
#define ROUTER_WARNING(fmt, x...) vsw_msg_warning(router_log_id, fmt, ##x)
#define ROUTER_ERROR(fmt, x...) vsw_msg_error(router_log_id, fmt, ##x)
#define ROUTER_FATAL(fmt, x...) vsw_msg_fatal(router_log_id, fmt, ##x)

char *
ip2str(uint32_t addr);

char *
mac2str(struct ether_addr mac);

#endif /* VSW_MODULES_ROUTER_LOG_H_ */
