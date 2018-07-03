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

#include <rte_random.h>
#include <rte_cycles.h>
#include <rte_atomic.h>

#include "ip_id.h"

static rte_atomic16_t ip_id;

static inline void
ip_reset_id() {
  rte_atomic16_set(&ip_id, (uint16_t) rte_rand());
}

void
ip_init_id(void) {
  rte_atomic16_init(&ip_id);
  rte_srand(rte_rdtsc());
  ip_reset_id();
}

uint16_t
ip_generate_id(void) {
  uint16_t id = rte_atomic16_add_return(&ip_id, 1);
  if (id == 0) {
    /* 0 is reserved. */
    return ip_generate_id();
  }
  return id;
}
