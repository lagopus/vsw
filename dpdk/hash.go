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
*/
import "C"

import "unsafe"

type Hash C.struct_rte_hash
type HashSig C.hash_sig_t

type HashParams struct {
	Name            string
	Entries         uint32
	KeyLen          uint32
	HashFunc        unsafe.Pointer
	HashFuncInitVal uint32
	SocketId        uint
}

func HashCreate(hp *HashParams) *Hash {
	p := (*C.struct_rte_hash_parameters)(C.malloc(C.sizeof_struct_rte_hash_parameters))
	defer C.free(unsafe.Pointer(p))

	p.name = C.CString(hp.Name)
	defer C.free(unsafe.Pointer(p.name))

	p.entries = C.uint32_t(hp.Entries)
	p.key_len = C.uint32_t(hp.KeyLen)
	p.hash_func = C.rte_hash_function(hp.HashFunc)
	p.hash_func_init_val = C.uint32_t(hp.HashFuncInitVal)
	p.socket_id = C.int(hp.SocketId)

	return (*Hash)(C.rte_hash_create(p))
}

func (h *Hash) HashHash(key unsafe.Pointer) HashSig {
	return (HashSig)(C.rte_hash_hash((*C.struct_rte_hash)(h), key))
}

func (h *Hash) Free() {
	C.rte_hash_free((*C.struct_rte_hash)(h))
}
