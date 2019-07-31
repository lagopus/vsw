//
// Copyright 2017-2019 Nippon Telegraph and Telephone Corporation.
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
#include <stdio.h>
#include <stdlib.h>
#include <rte_config.h>
#include <rte_ring.h>

static char *ring_list_dump() {
	char *ptr;
	size_t size;

	FILE *out = open_memstream(&ptr, &size);
	if (out == NULL)
		return NULL;

	rte_ring_list_dump(out);

	fclose(out);

	return ptr;
};

*/
import "C"

import (
	"fmt"
	"unsafe"
)

const (
	SOCKET_ID_ANY = int(C.SOCKET_ID_ANY)
)

type Ring C.struct_rte_ring
type RingFlags uint

const (
	RING_F_SP_ENQ = RingFlags(C.RING_F_SP_ENQ)
	RING_F_SC_DEQ = RingFlags(C.RING_F_SC_DEQ)
)

func RingCreate(name string, count uint, socket_id int, flags RingFlags) *Ring {
	cname := C.CString(name)
	defer C.free((unsafe.Pointer)(cname))
	return (*Ring)(C.rte_ring_create(cname, C.unsigned(count), C.int(socket_id), C.unsigned(flags)))
}

func (r *Ring) Free() {
	C.rte_ring_free((*C.struct_rte_ring)(r))
}

func (r *Ring) Enqueue(obj unsafe.Pointer) int {
	return int(C.rte_ring_enqueue((*C.struct_rte_ring)(r), obj))
}

func (r *Ring) Dequeue(objp *unsafe.Pointer) int {
	return int(C.rte_ring_dequeue((*C.struct_rte_ring)(r), objp))
}

func (r *Ring) EnqueueMbuf(mbuf *Mbuf) int {
	return r.Enqueue(unsafe.Pointer(mbuf))
}

func (r *Ring) DequeueMbuf(mbuf **Mbuf) int {
	return r.Dequeue((*unsafe.Pointer)(unsafe.Pointer(mbuf)))
}

func (r *Ring) EnqueueBurst(obj_tbl *unsafe.Pointer, n uint) uint {
	return uint(C.rte_ring_enqueue_burst((*C.struct_rte_ring)(r), obj_tbl, C.unsigned(n), nil))
}

func (r *Ring) EnqueueBulk(obj_tbl *unsafe.Pointer, n uint) bool {
	cn := C.unsigned(n)
	return C.rte_ring_enqueue_bulk((*C.struct_rte_ring)(r), obj_tbl, cn, nil) == cn
}

func (r *Ring) EnqueueBurstMbufs(mbufs []*Mbuf) uint {
	return r.EnqueueBurst((*unsafe.Pointer)(unsafe.Pointer(&mbufs[0])), uint(len(mbufs)))
}

func (r *Ring) DequeueBurst(obj_tbl *unsafe.Pointer, n uint) uint {
	return uint(C.rte_ring_dequeue_burst((*C.struct_rte_ring)(r), obj_tbl, C.unsigned(n), nil))
}

func (r *Ring) DequeueBulk(obj_tbl *unsafe.Pointer, n uint) bool {
	cn := C.unsigned(n)
	return C.rte_ring_dequeue_bulk((*C.struct_rte_ring)(r), obj_tbl, cn, nil) == cn
}

func (r *Ring) DequeueBurstMbufs(mbufs *[]*Mbuf) uint {
	mb := *mbufs
	return r.DequeueBurst((*unsafe.Pointer)(unsafe.Pointer(&mb[0])), uint(len(mb)))
}

func RingListDump() (string, error) {
	cstr, err := C.ring_list_dump()

	if err != nil {
		return "", fmt.Errorf("Can't dump ring list: %v", err)
	}

	defer C.free(unsafe.Pointer(cstr))
	return C.GoString(cstr), nil
}
