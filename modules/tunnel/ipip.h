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

#ifndef _LAGOPUS_MODULES_IPIP_H
#define _LAGOPUS_MODULES_IPIP_H

#include "l3tun.h"

#define IPIP_MODULE_NAME "ipip"

extern struct vsw_runtime_ops ipip_inbound_runtime_ops;
extern struct vsw_runtime_ops ipip_outbound_runtime_ops;

#endif // _LAGOPUS_MODULES_IPIP_H
