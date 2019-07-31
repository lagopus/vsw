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

#ifndef VXLAN_INCLUDES_H
#define VXLAN_INCLUDES_H

#include "lagopus_apis.h"

#include "tunnel.h"
#include "l2tun.h"
#include "vxlan.h"

#define PREFETCH_OFFSET (3)
#define MAX_PKTS_WITH_FLOOD (MAX_PKT_BURST * 2)

struct eventq_entry;

lagopus_result_t
vxlan_get_events(struct eventq_entry *entries,
                 size_t *num);

#endif /* VXLAN_INCLUDES_H */
