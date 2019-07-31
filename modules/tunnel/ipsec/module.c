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

struct module *
module_create(char *name) {
  struct module *module;
  struct moduleconf *conf;

  conf = moduleconf_getconf(name);
  if (conf == NULL) {
    TUNNEL_ERROR("No such module %s", name);
    return NULL;
  }
  module = calloc(1, sizeof(struct module));
  if (module != NULL) {
    module->name = strdup(name);
    if (module->name == NULL) {
      TUNNEL_ERROR("allocation failure for module %s", name);
      free(module);
      return NULL;
    }

    module->context = calloc(1, conf->context_size);
    if (module->context == NULL) {
      TUNNEL_ERROR("%zu bytes allocation failure for module %s",
                   conf->context_size, name);
      free((void *) module->name);
      free(module);
      return NULL;
    }

    TUNNEL_DEBUG("create %s module.", name);
  } else {
    TUNNEL_ERROR("Can't create module.");
  }
  return module;
}

void
module_destroy(struct module *module) {
  if (module != NULL) {
    free((void *) module->name);
    free(module->context);
  }
  free(module);
}

void *
module_get_context(struct module *module) {
  return module->context;
}
