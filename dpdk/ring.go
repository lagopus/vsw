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
#include <rte_config.h>
#include <rte_ring.h>
*/
import "C"

import (
	"unsafe"
)

const (
	SOCKET_ID_ANY = int(C.SOCKET_ID_ANY)
	RING_F_SP_ENQ = uint(C.RING_F_SP_ENQ)
	RING_F_SC_DEQ = uint(C.RING_F_SC_DEQ)
)

type Ring C.struct_rte_ring

func RingCreate(name string, count uint, socket_id int, flags uint) *Ring {
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
	return uint(C.rte_ring_enqueue_burst((*C.struct_rte_ring)(r), obj_tbl, C.unsigned(n)))
}

func (r *Ring) EnqueueBurstMbufs(mbufs []*Mbuf) uint {
	return r.EnqueueBurst((*unsafe.Pointer)(unsafe.Pointer(&mbufs[0])), uint(len(mbufs)))
}

func (r *Ring) DequeueBurst(obj_tbl *unsafe.Pointer, n uint) uint {
	return uint(C.rte_ring_dequeue_burst((*C.struct_rte_ring)(r), obj_tbl, C.unsigned(n)))
}

func (r *Ring) DequeueBurstMbufs(mbufs *[]*Mbuf) uint {
	mb := *mbufs
	return r.DequeueBurst((*unsafe.Pointer)(unsafe.Pointer(&mb[0])), uint(len(mb)))
}
