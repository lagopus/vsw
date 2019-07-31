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
#include "tunnel.h"
#include "module.h"

static lagopus_hashmap_t moduleconf_hashmap = NULL;

void
moduleconf_register(struct moduleconf *conf) {
  static bool inited = false;
  void *val;
  lagopus_result_t rv;

  if (inited == false) {
    rv = lagopus_hashmap_create(&moduleconf_hashmap,
                                LAGOPUS_HASHMAP_TYPE_STRING,
                                NULL);
    if (rv != LAGOPUS_RESULT_OK) {
      TUNNEL_PERROR(rv);
      return;
    }
    inited = true;
  }
  val = conf;
  if ((rv = lagopus_hashmap_add(&moduleconf_hashmap,
                                (void *)conf->name, &val, false)) !=
      LAGOPUS_RESULT_OK) {
    TUNNEL_PERROR(rv);
    return;
  }
  TUNNEL_DEBUG("module %s registered", conf->name);
}

void
moduleconf_destroy(void) {
  if (moduleconf_hashmap != NULL) {
    lagopus_hashmap_destroy(&moduleconf_hashmap, false);
    moduleconf_hashmap = NULL;
  }
}

struct moduleconf *
moduleconf_getconf(const char *name) {
  struct moduleconf *conf;
  lagopus_result_t rv;

  if ((rv = lagopus_hashmap_find(&moduleconf_hashmap,
                                 (void *) name, (void **)&conf)) !=
      LAGOPUS_RESULT_OK) {
    TUNNEL_PERROR(rv);
    return NULL;
  }
  return conf;
}
