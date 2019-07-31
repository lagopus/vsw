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

#ifndef FDB_H
#define FDB_H

#include <rte_rwlock.h>

#include "vxlan_includes.h"

struct fdb {
  lagopus_hashmap_t db;
  rte_rwlock_t rwlock;
  uint8_t numa_node;
  uint64_t refs;
};

struct fdb_entry {
  struct ether_addr mac;
  uint8_t ver; /* IPv4(4)/IPv6(6). */
  uint8_t len;
  struct ip_addr remote_ip;
  bool referred; /* For aging. Whether referred to this entry or not. */
};

/* entry of FDB.  */

static inline lagopus_result_t
_fdb_entry_alloc(struct fdb_entry **entry, uint8_t numa_node) {
  *entry = lagopus_malloc_on_numanode(sizeof(struct fdb_entry),
                                      numa_node);
  if (unlikely(*entry == NULL)) {
    return LAGOPUS_RESULT_NO_MEMORY;
  }
  memset(*entry, 0, sizeof(struct fdb_entry));

  return LAGOPUS_RESULT_OK;
}

static inline void
_fdb_entry_free(void *entry) {
  if (entry != NULL) {
    lagopus_free_on_numanode(entry);
  }
}

static inline void
_fdb_entry_set(struct fdb_entry *entry,
               struct ether_addr *mac,
               struct ip *ip) {
  struct ip6_hdr *ip6;
  void *src_ip;

  // no lock.
  entry->referred = false;
  entry->ver = ip->ip_v;
  entry->mac = *mac;
  if (ip->ip_v == IPVERSION) {
    entry->len = IP4_ADDR_LEN;
    src_ip = (void *) &ip->ip_src;
  } else {
    entry->len = IP6_ADDR_LEN;
    ip6 = (struct ip6_hdr *) ip;
    src_ip = (void *) &ip6->ip6_src;
  }
  memcpy(&entry->remote_ip, src_ip, entry->len);
}

static inline int
_fdb_entry_ip_cmp(struct fdb_entry *entry,
                  struct ip *ip) {
  struct ip6_hdr *ip6;

  // IPv4.
  if (ip->ip_v == IPVERSION) {
    return memcmp(&entry->remote_ip, &ip->ip_src, entry->len);
  }

  // IPv6.
  ip6 = (struct ip6_hdr *) ip;
  return memcmp(&entry->remote_ip, &ip6->ip6_src, entry->len);
}

/* Public. */

static inline void
fdb_entry_set_ip(struct fdb_entry *entry,
                 uint16_t address_type,
                 struct ip_addr *ip) {
  // no lock.
  if (address_type == ADDRESS_TYPE_IPV4) {
    entry->ver = IPVERSION;
    entry->len = IP4_ADDR_LEN;
  } else {
    entry->ver = IP6_VERSION;
    entry->len = IP6_ADDR_LEN;
  }
  entry->remote_ip = *ip;
}

static inline bool
fdb_entry_is_referred(struct fdb_entry *entry) {
  return entry->referred;
}

/* FDB. */

static inline void
_find_read_rlock(struct fdb *fdb) {
  rte_rwlock_read_lock(&fdb->rwlock);
}

static inline void
_find_read_unlock(struct fdb *fdb) {
  rte_rwlock_read_unlock(&fdb->rwlock);
}

static inline void
_find_write_lock(struct fdb *fdb) {
  rte_rwlock_write_lock(&fdb->rwlock);
}

static inline void
_find_write_unlock(struct fdb *fdb) {
  rte_rwlock_write_unlock(&fdb->rwlock);
}

static inline void
_fdb_update_entry(struct fdb *fdb,
                  struct fdb_entry *entry,
                  struct ether_addr *mac,
                  struct ip *ip) {
  _find_write_lock(fdb);
  _fdb_entry_set(entry, mac, ip);
  _find_write_unlock(fdb);
}

static inline void
_fdb_set_entry_referred(struct fdb *fdb,
                        struct fdb_entry *entry,
                        bool b) {
  _find_write_lock(fdb);
  entry->referred = b;
  _find_write_unlock(fdb);
}

static inline lagopus_result_t
_fdb_find_nolock(struct fdb *fdb,
                 struct ether_addr *mac,
                 struct fdb_entry **entry) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  uint64_t mac_key;

  if (unlikely(fdb == NULL || fdb->db == NULL ||
               mac == NULL || entry == NULL)) {
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  mac_key = ETHADDR_TO_UINT64(*mac);
  ret = lagopus_hashmap_find_no_lock(&fdb->db,
                                     (void *) mac_key,
                                     (void **) entry);
  if (unlikely(ret != LAGOPUS_RESULT_OK &&
               ret != LAGOPUS_RESULT_NOT_FOUND)) {
    lagopus_perror(ret);
  }

  return ret;
}

/* Public. */

static inline lagopus_result_t
fdb_alloc(struct fdb **fdb, uint8_t numa_node) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (unlikely(fdb == NULL)) {
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  *fdb = lagopus_malloc_on_numanode(sizeof(struct fdb),
                                    numa_node);
  if (unlikely(*fdb == NULL)) {
    return LAGOPUS_RESULT_NO_MEMORY;
  }

  if ((ret = lagopus_hashmap_create(&(*fdb)->db, LAGOPUS_HASHMAP_TYPE_ONE_WORD,
                                    _fdb_entry_free)) != LAGOPUS_RESULT_OK) {
    TUNNEL_PERROR(ret);
    return ret;
  }
  rte_rwlock_init(&(*fdb)->rwlock);
  (*fdb)->numa_node = numa_node;
  (*fdb)->refs = 1;

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
fdb_free(struct fdb **fdb) {
  if (unlikely(fdb == NULL || *fdb == NULL)) {
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  _find_write_lock(*fdb);
  (*fdb)->refs--;
  if ((*fdb)->refs == 0) {
    if ((*fdb)->db != NULL) {
      lagopus_hashmap_shutdown(&(*fdb)->db, true);
      lagopus_hashmap_destroy(&(*fdb)->db, true);
    }
  }
  _find_write_unlock(*fdb);

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
fdb_inc_refs(struct fdb *fdb) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (unlikely(fdb == NULL)) {
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  _find_write_lock(fdb);
  fdb->refs++;
  _find_write_unlock(fdb);

  return ret;
}

static inline lagopus_result_t
fdb_find(struct fdb *fdb,
         struct ether_addr *mac,
         struct fdb_entry **entry) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (unlikely(fdb == NULL || fdb->db == NULL ||
               mac == NULL || entry == NULL)) {
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  if (unlikely(!is_unicast_ether_addr(mac))) {
    /* broadcast/multicast. */
    return LAGOPUS_RESULT_NOT_FOUND;
  }

  /* unicast. */
  _find_read_rlock(fdb);
  ret = _fdb_find_nolock(fdb, mac, entry);
  _find_read_unlock(fdb);

  return ret;
}

static inline lagopus_result_t
fdb_find_copy(struct fdb *fdb,
              struct ether_addr *mac,
              struct fdb_entry *entry) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct fdb_entry *e;

  if (unlikely(fdb == NULL || fdb->db == NULL ||
               mac == NULL || entry == NULL)) {
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  if (unlikely(!is_unicast_ether_addr(mac))) {
    /* broadcast/multicast. */
    return LAGOPUS_RESULT_NOT_FOUND;
  }

  /* unicast. */
  _find_read_rlock(fdb);
  ret = _fdb_find_nolock(fdb, mac, &e);
  if (likely(ret == LAGOPUS_RESULT_OK)) {
    /* copy.  */
    *entry = *e;
  }

  _find_read_unlock(fdb);

  return ret;
}

static inline lagopus_result_t
fdb_add(struct fdb *fdb,
        struct ether_addr *mac,
        struct fdb_entry **entry) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct fdb_entry *new_entry;
  uint64_t mac_key;

  if (unlikely(fdb == NULL || fdb->db == NULL ||
               mac == NULL || entry == NULL)) {
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  mac_key = ETHADDR_TO_UINT64(*mac);
  new_entry = *entry;

  _find_write_lock(fdb);
  ret = lagopus_hashmap_add_no_lock(&fdb->db,
                                    (void *) mac_key,
                                    (void **) &new_entry,
                                    false);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
  }
  _find_write_unlock(fdb);

  return ret;
}

static inline lagopus_result_t
fdb_delete(struct fdb *fdb,
           struct ether_addr *mac) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  uint64_t mac_key;

  if (unlikely(fdb == NULL || fdb->db == NULL ||
               mac == NULL)) {
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  mac_key = ETHADDR_TO_UINT64(*mac);

  _find_write_lock(fdb);
  ret = lagopus_hashmap_delete_no_lock(&fdb->db,
                                       (void *) mac_key,
                                       NULL,
                                       true);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
  }
  _find_write_unlock(fdb);

  return ret;
}

static inline lagopus_result_t
fdb_clear(struct fdb *fdb) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (unlikely(fdb == NULL || fdb->db == NULL)) {
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  _find_write_lock(fdb);
  ret = lagopus_hashmap_clear_no_lock(&fdb->db,
                                      true);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
  }
  _find_write_unlock(fdb);

  return ret;
}

static inline lagopus_result_t
fdb_learn(struct fdb *fdb,
          struct ether_addr *mac,
          struct ip *ip,
          struct fdb_entry **e) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct fdb_entry *entry = NULL;

  if (unlikely(fdb == NULL || fdb->db == NULL ||
               mac == NULL || ip == NULL)) {
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  if (unlikely(!is_unicast_ether_addr(mac))) {
    /* NOTE: not learn broadcast/multicast (does not occur). */
    *e = NULL;
    return LAGOPUS_RESULT_OK;
  }

  /* find. */
  ret = fdb_find(fdb, mac, &entry);
  if (likely(ret == LAGOPUS_RESULT_OK)) {
    /* found. */
    if (likely(entry->ver == ip->ip_v &&
               _fdb_entry_ip_cmp(entry, ip) == 0)) {
      _fdb_set_entry_referred(fdb, entry, true);
      TUNNEL_DEBUG("FDB: set referred.");
    } else {
      /* not same IP addr. */
      _fdb_update_entry(fdb, entry, mac, ip);
      TUNNEL_DEBUG("FDB: update remote IP addr.");
    }
  } else if (likely(ret == LAGOPUS_RESULT_NOT_FOUND)) {
    /* not found. */
    /* alloc/set entry. */
    ret = _fdb_entry_alloc(&entry, fdb->numa_node);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      goto done;
    }
    _fdb_entry_set(entry, mac, ip);

    /* add entry. */
    ret = fdb_add(fdb, mac, &entry);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      _fdb_entry_free(entry);
      TUNNEL_PERROR(ret);
      goto done;
    }
  } else {
    TUNNEL_PERROR(ret);
  }

done:
  if (likely(ret == LAGOPUS_RESULT_OK &&
             e != NULL)) {
    *e = entry;
  }

  return ret;
}

static inline lagopus_result_t
fdb_gc(struct fdb *fdb,
       struct ether_addr *mac,
       struct fdb_entry **entry) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (unlikely(fdb == NULL || fdb->db == NULL ||
               mac == NULL || entry == NULL)) {
    return LAGOPUS_RESULT_INVALID_ARGS;
  }

  /* find. */
  ret = fdb_find(fdb, mac, entry);
  if (likely(ret == LAGOPUS_RESULT_OK)) {
    /* found. */
    if ((*entry)->referred) {
      (*entry)->referred = false;
    } else {
      /* age out. */
      ret = fdb_delete(fdb, mac);
      if (unlikely(ret != LAGOPUS_RESULT_OK)) {
        TUNNEL_PERROR(ret);
      }
      *entry = NULL;
    }
  } else if (likely(ret == LAGOPUS_RESULT_NOT_FOUND)) {
    /* not found. */
    /* age out. */
    *entry = NULL;
    ret = LAGOPUS_RESULT_OK;
  } else {
    TUNNEL_PERROR(ret);
  }

  return ret;
}

#endif /* FDB_H */
