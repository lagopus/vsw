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

#ifndef VSW_MODULE_ROUTER_RADIX_TREE_H_
#define VSW_MODULE_ROUTER_RADIX_TREE_H_

#include <stdbool.h>
#include <stdint.h>

typedef const char *(*stringer)(void *p);

struct set;
extern bool set_insert(struct set *set, void *value);
extern void *set_value_at(struct set *set, unsigned pos);
extern void *set_get_first(struct set *set);

struct rt;
extern struct rt *rt_new();
extern void rt_free(struct rt*);
extern struct set *rt_alloc_node(struct rt *rt, uint32_t key, uint32_t len);
extern bool rt_insert_key(struct rt *rt, uint32_t key, uint32_t len, void *value);
extern bool rt_delete_key(struct rt *rt, uint32_t key, uint32_t len, void *value);
extern int rt_search_key(struct rt *rt, uint32_t key, uint32_t len);
extern bool rt_iterate_results(struct rt *rt, void **value);
extern void rt_dump(struct rt *rt);
extern void rt_dump2(struct rt *rt, stringer s);

extern bool rt_insert_range(struct rt *rt, uint32_t min, uint32_t max, void *value);
extern bool rt_delete_range(struct rt *rt, uint32_t min, uint32_t max, void *value);

#endif /* !VSW_MODULE_ROUTER_RADIX_TREE_H_ */
