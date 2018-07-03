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

#ifndef MODULE_H
#define MODULE_H

#include "lagopus_config.h"
#include "lagopus_apis.h"

struct moduleconf {
  const char *name;
  size_t context_size;
};

struct module {
  const char *name;
  void *context;
  struct moduleconf *conf;
};

#define REGISTER_MODULECONF(name)                                       \
  void modinitfn_ ##name(void);                                         \
  void moduninitfn_ ##name(void);                                         \
  void __attribute__((constructor, used)) modinitfn_ ##name(void) {     \
    moduleconf_register(&name);                                         \
  }                                                                     \
  void __attribute__((destructor, used)) moduninitfn_ ##name(void) {    \
    moduleconf_destroy();                                               \
  }                                                                     \

void
moduleconf_register(struct moduleconf *);

void
moduleconf_destroy(void);

struct moduleconf *
moduleconf_getconf(const char *);

struct module *
module_create(char *name);

void *
module_get_context(struct module *module);

void
module_destroy(struct module *module);

#endif /* MODULE_H */
