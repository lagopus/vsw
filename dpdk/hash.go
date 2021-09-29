//
// Copyright 2017 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package dpdk

/*
#include <stdlib.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_hash_crc.h>
#include "dpdk.h"

uint32_t
dpdk_jhash(const void *key, uint32_t key_len, uint32_t init_val) {
	return rte_jhash(key, key_len, init_val);
}

uint32_t
dpdk_jhash_32b(const void *key, uint32_t key_len, uint32_t init_val) {
	return rte_jhash_32b((const uint32_t *)key, key_len, init_val);
}

uint32_t
dpdk_crc_hash(const void *key, uint32_t key_len, uint32_t init_val) {
	return rte_hash_crc(key, key_len, init_val);
}

uint32_t
dpdk_crc_hash_8byte(const void *key, uint32_t key_len, uint32_t init_val) {
	return rte_hash_crc_8byte(*(uint64_t *)key, init_val);
}

uint32_t
dpdk_crc_hash_4byte(const void *key, uint32_t key_len, uint32_t init_val) {
	return rte_hash_crc_4byte(*(uint32_t *)key, init_val);
}

uint32_t
dpdk_crc_hash_2byte(const void *key, uint32_t key_len, uint32_t init_val) {
	return rte_hash_crc_2byte(*(uint16_t *)key, init_val);
}

uint32_t
dpdk_crc_hash_1byte(const void *key, uint32_t key_len, uint32_t init_val) {
	return rte_hash_crc_1byte(*(uint8_t *)key, init_val);
}

*/
import "C"

import "unsafe"

type Hash C.struct_rte_hash
type HashSig C.hash_sig_t
type HashFunc C.rte_hash_function
type HashExtraFlag uint8

const (
	HashEntriesMax = C.RTE_HASH_ENTRIES_MAX
	HashNameSize   = C.RTE_HASH_NAMESIZE
)

const (
	HashExtraFlagsTransMemSupport = HashExtraFlag(C.RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT)
	HashExtraFlagsMultiWriterAdd  = HashExtraFlag(C.RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD)
	HashExtraFlagsRWConcurrency   = HashExtraFlag(C.RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY)
	HashExtraFlagsExtTable        = HashExtraFlag(C.RTE_HASH_EXTRA_FLAGS_EXT_TABLE)
	HashExtraFlagsNoFreeOnDel     = HashExtraFlag(C.RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL)
	HashExtraFlagsRWConcurrencyLF = HashExtraFlag(C.RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF)
)

// DPDK Predefined Hash Functions
var JHash = HashFunc(C.dpdk_jhash)
var JHash32b = HashFunc(C.dpdk_jhash_32b)
var CRCHash = HashFunc(C.dpdk_crc_hash)
var CRCHash8Byte = HashFunc(C.dpdk_crc_hash_8byte)
var CRCHash4Byte = HashFunc(C.dpdk_crc_hash_4byte)
var CRCHash2Byte = HashFunc(C.dpdk_crc_hash_2byte)
var CRCHash1Byte = HashFunc(C.dpdk_crc_hash_1byte)

type HashParams struct {
	Name      string
	Entries   uint32
	KeyLen    uint32
	Func      HashFunc
	InitVal   uint32
	SocketId  int
	ExtraFlag HashExtraFlag
}

func HashCreate(hp *HashParams) (*Hash, error) {
	p := (*C.struct_rte_hash_parameters)(C.calloc(1, C.sizeof_struct_rte_hash_parameters))
	defer C.free(unsafe.Pointer(p))

	p.name = C.CString(hp.Name)
	defer C.free(unsafe.Pointer(p.name))

	p.entries = C.uint32_t(hp.Entries)
	p.key_len = C.uint32_t(hp.KeyLen)
	p.hash_func = C.rte_hash_function(hp.Func)
	p.hash_func_init_val = C.uint32_t(hp.InitVal)
	p.socket_id = C.int(hp.SocketId)
	p.extra_flag = C.uint8_t(hp.ExtraFlag)

	var err error
	hash := (*Hash)(C.rte_hash_create(p))
	if hash == nil {
		err = Errno(C.get_rte_errno())
	}

	return hash, err
}

func (h *Hash) Free() {
	C.rte_hash_free((*C.struct_rte_hash)(h))
}

func (h *Hash) Reset() {
	C.rte_hash_reset((*C.struct_rte_hash)(h))
}

func (h *Hash) Count() (int, error) {
	count := int(C.rte_hash_count((*C.struct_rte_hash)(h)))
	if count < 0 {
		return 0, Errno(-count)
	}
	return count, nil
}

func (h *Hash) AddKeyData(key, data unsafe.Pointer) error {
	rc := int(C.rte_hash_add_key_data((*C.struct_rte_hash)(h), key, data))
	if rc < 0 {
		return Errno(-rc)
	}
	return nil
}

func (h *Hash) DelKey(key unsafe.Pointer) (int, error) {
	rc := int(C.rte_hash_del_key((*C.struct_rte_hash)(h), key))
	if rc < 0 {
		return -1, Errno(-rc)
	}
	return rc, nil
}

func (h *Hash) LookupData(key unsafe.Pointer) (unsafe.Pointer, int, error) {
	var data unsafe.Pointer
	rc := int(C.rte_hash_lookup_data((*C.struct_rte_hash)(h), key, &data))
	if rc < 0 {
		return nil, -1, Errno(-rc)
	}
	return data, rc, nil
}

func (h *Hash) HashHash(key unsafe.Pointer) HashSig {
	return (HashSig)(C.rte_hash_hash((*C.struct_rte_hash)(h), key))
}
