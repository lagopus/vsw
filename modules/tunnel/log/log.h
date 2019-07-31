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

#ifndef TUNNEL_LOG_H
#define TUNNEL_LOG_H

#include "lagopus_apis.h"

extern uint32_t tunnel_log_id;

#define TUNNEL_DEBUG_ENABLED           VSW_LOG_DEBUG_ENABLED(tunnel_log_id)
#define TUNNEL_DEBUG(fmt, x...)        vsw_msg_debug(tunnel_log_id, 0, "%s: "fmt, __func__, ## x)
#define TUNNEL_DEBUG_NOFUNC(fmt, x...) vsw_msg_debug(tunnel_log_id, 0, fmt, ## x)
#define TUNNEL_INFO(fmt, x...)         vsw_msg_info(tunnel_log_id, "%s: " fmt, __func__, ## x)
#define TUNNEL_WARNING(fmt, x...)      vsw_msg_warning(tunnel_log_id, "%s: " fmt, __func__, ## x)
#define TUNNEL_ERROR(fmt, x...)        vsw_msg_error(tunnel_log_id, "%s: " fmt, __func__, ## x)
#define TUNNEL_PERROR(err)             vsw_msg_error(tunnel_log_id, "%s: %s", \
    __func__, lagopus_error_get_string((err)))
#define TUNNEL_FATAL(fmt, x...) {                             \
    vsw_msg_fatal(tunnel_log_id, "%s: " fmt, __func__, ## x); \
    abort();                                                  \
}

void
tunnel_set_logid(int id);

#endif /* TUNNEL_LOG_H */
