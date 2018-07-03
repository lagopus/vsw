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

#include "lagopus_apis.h"
#include "sad_go.h"

bool
load_sa_atomically(const sad_t sad, const uint32_t spi,
                   time_t *lifetime, uint64_t *byte) {
  bool ret = false;
  if (unlikely(lifetime == NULL || byte == NULL)) {
    lagopus_msg_error("NULL argument, lifetime:%p, byte:%p", lifetime, byte);
  } else if (unlikely(spi == INVALID_SPI)) {
    lagopus_msg_error("invalid spi\n");
  } else if (unlikely(sad == NULL)) {
    lagopus_msg_error("sad is NULL\n");
  } else {
    const size_t sa_idx = SPI2IDX(spi);
    *lifetime = sad->lifetime[sa_idx].time_current / 1000LL / 1000LL / 1000LL;
    *byte = sad->lifetime[sa_idx].byte_current;
    lagopus_msg_debug(200, "pull SA(%u) %ld %lu\n", spi, *lifetime, *byte);
    ret = true;
  }
  return ret;
}

struct sadb_acquire *
get_acquires(sad_t sad) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct sadb_acquire *acquire = NULL;

  if (likely(sad != NULL)) {
    // copy sad->acquired[] to 'acquire'. 'acquire' will freed at Go plane.
    acquire = (struct sadb_acquire *) malloc(IPSEC_SA_MAX_ENTRIES *
              sizeof(struct sadb_acquire));
    if (likely(acquire != NULL)) {
      if (likely((ret = sad_get_acquires(sad, acquire)) != LAGOPUS_RESULT_OK)) {
        lagopus_perror(ret);
        free(acquire);
        acquire = NULL;
      }
    } else {
      lagopus_msg_error("cannot allocate return value\n");
    }
  } else {
    lagopus_msg_error("sad is NULL\n");
  }

  return acquire;
}
