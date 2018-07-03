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

#ifndef SAD_GO_H
#define SAD_GO_H

#include "sa.h"

/**
 * get value of current SA fields atomically.
 *
 * @params [in]  module         target module
 * @params [in]  spi            target SA's SPI
 * @params [out] lifetime       got value of lifetime_current
 * @params [out] byte           got value of lifetime_byte_current
 *
 * @retval true   Succeeded.
 * @retval false  Failed.
 */
bool
load_sa_atomically(const sad_t sad, const uint32_t spi,
                   time_t *lifetime, uint64_t *byte);

/**
 * get list of SADB_ACQUIRE messages.
 *
 * @params [in]  module         target module
 *
 * @retval array of struct sadb_acquire (if NULL, got error.)
 */
struct sadb_acquire *
get_acquires(sad_t sad);

#endif /* SAD_GO_H */
