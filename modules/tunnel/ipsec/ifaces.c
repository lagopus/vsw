// +build ignore

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

#ifndef IFACES_C
#define IFACES_C

#include <rte_atomic.h>
#include "lagopus_apis.h"
#include "ipsec.h"
#include "ifaces.h"

struct ifaces_attr {
  struct iface all_ifaces[VIF_MAX_ENTRY]; /* per VIF index. */
  struct iface_list active_ifaces; /* List of active ifaces. */
  rte_atomic16_t refs;
};

struct ifaces {
  struct ifaces_attr attr[2];
  rte_atomic64_t seq;
  uint64_t current;
};

static struct iface default_iface = {
  .input = NULL,
  .output = NULL,
  .ttl = DEFAULT_TTL,
  .tos = DEFAULT_TOS,
};

static inline lagopus_result_t
ifaces_alloc(struct ifaces **ifaces) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  size_t i;

  if (ifaces != NULL) {
    *ifaces = (struct ifaces *) calloc(1, sizeof(struct ifaces));
    if (*ifaces == NULL) {
      ret = LAGOPUS_RESULT_NO_MEMORY;
      lagopus_perror(ret);
      goto done;
    }

    rte_atomic64_init(&(*ifaces)->seq);
    for (i = 0; i < VIF_MAX_ENTRY; i++) {
      IFACES_MODIFIED(*ifaces).all_ifaces[i] = default_iface;
      IFACES_CURRENT(*ifaces).all_ifaces[i] = default_iface;
    }
    TAILQ_INIT(&IFACES_MODIFIED(*ifaces).active_ifaces);
    TAILQ_INIT(&IFACES_CURRENT(*ifaces).active_ifaces);

    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    lagopus_perror(ret);
  }

done:
  return ret;
}

static inline void
ifaces_free(struct ifaces **ifaces) {
  free(*ifaces);
  *ifaces = NULL;
}

static inline lagopus_result_t
ifaces_pre_process(struct ifaces *ifaces, struct iface_list **active_ifaces) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(ifaces != NULL && active_ifaces != NULL)) {
    /* switch. */
    ifaces->current = (uint64_t) rte_atomic64_read(&ifaces->seq) % 2;
    /* set referenced. */
    rte_atomic16_inc(&IFACES_CURRENT(ifaces).refs);

    *active_ifaces = &IFACES_CURRENT(ifaces).active_ifaces;

    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    lagopus_perror(ret);
  }

  return ret;
}

static inline lagopus_result_t
ifaces_post_process(struct ifaces *ifaces) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(ifaces != NULL)) {
    /* unset referenced. */
    rte_atomic16_dec(&IFACES_CURRENT(ifaces).refs);
    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    lagopus_perror(ret);
  }

  return ret;
}

static inline void
ifaces_finalize(struct ifaces **ifaces) {
  ifaces_free(ifaces);
}

static inline void
ifaces_initialize(struct ifaces **ifaces) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  if ((ret = ifaces_alloc(ifaces)) != LAGOPUS_RESULT_OK) {
    lagopus_perror(ret);
    ifaces_finalize(ifaces);
    rte_exit(EXIT_FAILURE, "Can't initialize ifaces.\n");
  }
}

/* public. */

lagopus_result_t
ifaces_push_config(struct ifaces *ifaces,
                   struct iface *iface_array,
                   size_t num_iface_array) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  uint64_t next_modified;
  size_t i;
  struct iface *iface;
  struct ifaces_attr *attr;

  if (ifaces != NULL && num_iface_array <= VIF_MAX_ENTRY) {
    next_modified = (uint64_t) (rte_atomic64_read(&ifaces->seq) + 1) % 2;
    if (rte_atomic16_read(&IFACES_GET_ATTR(ifaces, next_modified).refs) == 0) {
      attr = &IFACES_GET_ATTR(ifaces, next_modified);

      /* copy array of iface. */
      memcpy(&attr->all_ifaces, iface_array, num_iface_array);

      /* clear list of iface. */
      while ((iface = TAILQ_FIRST(&attr->active_ifaces)) != NULL) {
        TAILQ_REMOVE(&attr->active_ifaces, iface, entry);
      }

      /* insert list of iface. */
      for (i = 0; i < num_iface_array; i++) {
        if (attr->all_ifaces[i].input != NULL &&
            attr->all_ifaces[i].output != NULL) {
          TAILQ_INSERT_TAIL(&attr->active_ifaces, &attr->all_ifaces[i], entry);
        }
      }

      rte_atomic64_inc(&ifaces->seq);

      ret = LAGOPUS_RESULT_OK;
    } else {
      ret = LAGOPUS_RESULT_OK;
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    lagopus_perror(ret);
  }

  return ret;

}

struct iface *
ifaces_alloc_array(size_t size) {
  struct iface *ifaces;
  size_t i;

  ifaces = (struct iface *) calloc(size, sizeof(struct iface));
  if (ifaces != NULL) {
    for (i = 0; i < size; i++) {
      ifaces[i] = default_iface;
    }
  }
  return ifaces;
}

void
ifaces_free_array(struct iface *iface_array) {
  free(iface_array);
}

/* iface. */

static inline uint8_t
iface_get_vrf_index(struct iface *iface) {
  if (likely(iface != NULL)) {
    return iface->vrf_index;
  }
  return 0;
}

static inline struct rte_ring *
iface_get_input(struct iface *iface) {
  if (likely(iface != NULL)) {
    return iface->input;
  }
  return NULL;
}

static inline struct rte_ring *
iface_get_output(struct iface *iface) {
  if (likely(iface != NULL)) {
    return iface->output;
  }
  return NULL;
}

static inline uint8_t
iface_get_ttl(struct iface *iface) {
  if (likely(iface != NULL)) {
    return iface->ttl;
  }
  return DEFAULT_TTL;
}

static inline int8_t
iface_get_tos(struct iface *iface) {
  if (likely(iface != NULL)) {
    return iface->tos;
  }
  return DEFAULT_TOS;
}

#endif /* IFACES_C */
