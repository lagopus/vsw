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

#ifndef HASH_H
#define HASH_H

#define TINY_MASK(size) (((uint32_t)1 << (size))-1)

// 0 < size < 16 ONLY.
uint32_t
hash_fnv1a32_tiny(uint32_t input, size_t hash_size);

uint64_t
hash_fnv1a64(uint64_t input);

#endif /* HASH_H */
