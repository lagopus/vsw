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
#include "hash.h"

/* FNV-1a Hash */
#define FNV_PRIME_32 (16777619)
#define FNV_OFFSET_BASIS_32 (2166136261)
#define FNV_PRIME_64 (1099511628211ULL)
#define FNV_OFFSET_BASIS_64 (14695981039346656037ULL)

static inline uint32_t
hash_fnv1a32_internal(void *buf, size_t buf_size) {
  uint32_t hash = FNV_OFFSET_BASIS_32;
  unsigned char *bufp = (unsigned char *) buf;
  unsigned char *end = buf + buf_size;

  while (bufp < end) {
    hash ^= (unsigned char) *bufp++;
    hash *= FNV_PRIME_32;
  }

  return hash;
}

static inline uint64_t
hash_fnv1a64_internal(void *buf, size_t buf_size) {
  uint64_t hash = FNV_OFFSET_BASIS_64;
  unsigned char *bufp = (unsigned char *) buf;
  unsigned char *end = buf + buf_size;

  while (bufp < end) {
    hash ^= (unsigned char) *bufp++;
    hash *= FNV_PRIME_64;
  }

  return hash;
}

uint32_t
hash_fnv1a32_tiny(uint32_t input, size_t hash_size) {
  uint32_t hash;
  assert(hash_size < 16);
  hash = hash_fnv1a32_internal(&input, sizeof(uint32_t));
  // NOTE: not ZERO(+ 1), userdata (rte_acl) > 0.
  hash = ((((hash >> hash_size) ^ hash)) & TINY_MASK(hash_size)) + 1;
  // carry over.
  hash += (hash >> hash_size);
  return hash & TINY_MASK(hash_size);
}

uint64_t
hash_fnv1a64(uint64_t input) {
  return hash_fnv1a64_internal(&input, sizeof(uint64_t));
}
