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

#ifndef EVENTQ_H
#define EVENTQ_H

#include "vxlan_includes.h"
#include "fdb.h"

#define EVENTQ_SIZE (MAX_PKT_BURST * 2)
#define MAX_BATCHES (MAX_PKT_BURST * 2)
#define LEAST_BATCHES (1LL)
#define PUT_TIMEOUT (0LL)
#define GET_TIMEOUT (1LL * 1000LL * 1000LL)

struct fdb_entry;

struct eventq_entry {
  l2tun_cmd_t cmd_type;
  uint32_t vni;
  struct fdb_entry fdb_entry;
};

/* entry of eventq. */

static inline void
eventq_entry_set(struct eventq_entry *entry,
                 l2tun_cmd_t cmd_type,
                 uint32_t vni,
                 struct fdb_entry *fdb_entry) {
  if (likely(entry != NULL)) {
    entry->cmd_type = cmd_type;
    entry->vni = vni;
    if (fdb_entry != NULL) {
      entry->fdb_entry = *fdb_entry;
    }
  }
}

/* eventq. */

static inline lagopus_result_t
event_queue_create(lagopus_bbq_t *eventq) {
  return lagopus_bbq_create(eventq, struct eventq_entry,
                            EVENTQ_SIZE, NULL);
}

static inline void
event_queue_shutdown(lagopus_bbq_t *eventq) {
  lagopus_bbq_shutdown(eventq, true);
}

static inline void
event_queue_destroy(lagopus_bbq_t *eventq) {
  lagopus_bbq_destroy(eventq, true);
}

static inline lagopus_result_t
event_queue_put(lagopus_bbq_t *eventq, struct eventq_entry *entry) {
  return lagopus_bbq_put(eventq, &entry,
                         struct eventq_entry,
                         PUT_TIMEOUT);
}

static inline lagopus_result_t
event_queue_puts(lagopus_bbq_t *eventq, struct eventq_entry *entries,
                 size_t num) {
  return lagopus_bbq_put_n(eventq, entries, num,
                           struct eventq_entry,
                           PUT_TIMEOUT, NULL);
}

static inline lagopus_result_t
event_queue_gets(lagopus_bbq_t *eventq, struct eventq_entry *entries,
                 size_t *num) {
  return lagopus_bbq_get_n(eventq, entries, MAX_BATCHES, LEAST_BATCHES,
                           struct eventq_entry, GET_TIMEOUT, num);
}

#endif /* EVENTQ_H */
