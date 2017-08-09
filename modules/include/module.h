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

#ifndef LIBDPMODULE_MODULE_H_
#define LIBDPMODULE_MODULE_H_

/*
 * module definition
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_NEXT 1024

struct module;

struct ctrlconf {
  char *ctrlname;
  int (*ctrlfunc)(struct module *, const char *ctrlname, const char *param);
};

struct moduleconf {
  char *name;
  size_t context_size;
  size_t tls_size;
  struct ctrlconf *ctrlconf;
  void *(*class_init)(const char *name);
  void (*class_fini)(const char *name);
  struct module *(*create_hook)(const char *name, struct module *myself);
  void (*destroy_hook)(struct module *myself);
  int (*configure)(struct module *, const char *);
  int (*unconfigure)(struct module *);
  int (*main)(struct module *);
  int (*stats)();
  size_t (*input)(struct module *, void **, void **, size_t);
};

struct module {
  char *name;
  void *context;
  void **tls;
  //rte_rwlock_t rwlock;
  int id;
  bool stop;
  struct moduleconf *conf;
  struct module *(*create_hook)(char *name, struct module *myself);
  void (*destroy_hook)(struct module *);
  int (*configure)(struct module *, void *);
  int (*unconfigure)(struct module *);
  int (*tls_setup)();
  int (*main)(struct module *);
  int (*stats)();
  int (*notify)();
  void **input_rlink;
  size_t (*input)(struct module *, void **, void **, size_t);
  struct module *output[MAX_NEXT];
  size_t n_outputs;
};

#ifdef __cplusplus
}
#endif

#endif /* LIBDPMODULE_MODULE_H_ */
