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

#include "lagopus_apis.h"
#include "sad_go.h"

bool
load_sa_atomically(const sad_t sad, const uint32_t spi,
                   time_t *lifetime, uint64_t *byte) {
  bool ret = false;
  if (unlikely(lifetime == NULL || byte == NULL)) {
    TUNNEL_ERROR("NULL argument, lifetime:%p, byte:%p", lifetime, byte);
  } else if (unlikely(spi == INVALID_SPI)) {
    TUNNEL_ERROR("invalid spi");
  } else if (unlikely(sad == NULL)) {
    TUNNEL_ERROR("sad is NULL");
  } else {
    const size_t sa_idx = SPI2IDX(spi);
    *lifetime = sad->lifetime[sa_idx].time_current / 1000LL / 1000LL / 1000LL;
    *byte = sad->lifetime[sa_idx].byte_current;

    /* For debug */
    /* TUNNEL_DEBUG("pull SA(%u) %ld %lu", spi, *lifetime, *byte); */
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
        TUNNEL_PERROR(ret);
        free(acquire);
        acquire = NULL;
      }
    } else {
      TUNNEL_ERROR("cannot allocate return value");
    }
  } else {
    TUNNEL_ERROR("sad is NULL");
  }

  return acquire;
}
