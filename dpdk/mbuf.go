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
#include <rte_mbuf.h>
#include <rte_ether.h>
#include "dpdk.h"
*/
import "C"

import (
	"unsafe"
)

const (
	RTE_MBUF_PRIV_ALIGN        = uint(C.RTE_MBUF_PRIV_ALIGN)
	RTE_MBUF_DEFAULT_BUF_SIZE  = uint(C.RTE_MBUF_DEFAULT_BUF_SIZE)
	RTE_PKTMBUF_HEADROOM       = uint(C.RTE_PKTMBUF_HEADROOM)
	RTE_MEMPOOL_CACHE_MAX_SIZE = uint(C.RTE_MEMPOOL_CACHE_MAX_SIZE)
)

type Mbuf C.struct_rte_mbuf
type MemPool C.struct_rte_mempool

func PktMbufPoolCreate(name string, n, cache_size, priv_size, data_room_size uint, socket_id int) (*MemPool, error) {
	cname := C.CString(name)
	defer C.free((unsafe.Pointer)(cname))
	pool := (*MemPool)(C.rte_pktmbuf_pool_create(cname, C.unsigned(n), C.unsigned(cache_size),
		C.uint16_t(priv_size), C.uint16_t(data_room_size), C.int(socket_id)))
	if pool == nil {
		return nil, Errno(C.get_rte_errno())
	}
	return pool, nil
}

func (mp *MemPool) Free() {
	C.rte_mempool_free((*C.struct_rte_mempool)(mp))
}

func (mp *MemPool) AllocMbuf() *Mbuf {
	return (*Mbuf)(C.rte_pktmbuf_alloc((*C.struct_rte_mempool)(mp)))
}

func (mp *MemPool) AllocBulkMbufs(count uint) []*Mbuf {
	mbufs := make([]*Mbuf, count)

	if int(C.rte_pktmbuf_alloc_bulk((*C.struct_rte_mempool)(mp),
		(**C.struct_rte_mbuf)(unsafe.Pointer(&mbufs[0])), C.unsigned(count))) == 0 {
		return mbufs
	}

	return nil
}

// Check if Mbuf has at least size of ether header
func (mb *Mbuf) checkAndUpdateMbufLen() {
	if mb.data_len < C.sizeof_struct_ether_hdr {
		mb.data_len = C.sizeof_struct_ether_hdr
		mb.pkt_len = C.sizeof_struct_ether_hdr
	}
}

func (mb *Mbuf) EtherHdr() EtherHdr {
	len := C.sizeof_struct_ether_hdr
	mb.checkAndUpdateMbufLen()
	return (EtherHdr)((*[1 << 30]byte)(unsafe.Pointer(uintptr(mb.buf_addr) + uintptr(mb.data_off)))[:len:len])
}

func (mb *Mbuf) SetEtherHdr(eh EtherHdr) {
	copy(mb.EtherHdr(), eh)
	mb.checkAndUpdateMbufLen()
}

// PktLen returns sum of all segments.
func (mb *Mbuf) PktLen() int {
	return int(mb.pkt_len)
}

// DataCap returns maximum available data storage in the mbuf.
func (mb *Mbuf) DataCap() int {
	return int(mb.buf_len) - int(RTE_PKTMBUF_HEADROOM)
}

// DataLen returns current length of the data in the mbuf.
func (mb *Mbuf) DataLen() int {
	return int(mb.data_len)
}

// Data returns the data in mbuf wrapped as []byte.
// Any modification to the []byte modifies the data.
func (mb *Mbuf) Data() []byte {
	len := mb.data_len
	return ([]byte)((*[1 << 30]byte)(unsafe.Pointer(uintptr(mb.buf_addr) + uintptr(mb.data_off)))[:len:len])
}

// AllData returns the entire data in mbuf wrapped as []byte.
// The length of the returned []byte is the same as DataCap().
// Any modification to the []byte modifies the data.
func (mb *Mbuf) AllData() []byte {
	len := mb.DataCap()
	return ([]byte)((*[1 << 30]byte)(unsafe.Pointer(uintptr(mb.buf_addr) + uintptr(mb.data_off)))[:len:len])
}

// SetData copies data to the data of mbuf.
// Returns number of bytes copied.
func (mb *Mbuf) SetData(data []byte) int {
	len := len(data)
	if len > mb.DataCap() {
		len = mb.DataCap()
	}
	copy(mb.AllData(), data)
	mb.data_len = C.uint16_t(len)
	mb.pkt_len = C.uint32_t(len)
	return len
}

// VlanTCI returns the current VLAN TCI value.
func (mb *Mbuf) VlanTCI() uint16 {
	return uint16(mb.vlan_tci)
}

// SetVlanTCI sets VLAN TCI value.
func (mb *Mbuf) SetVlanTCI(vt uint16) {
	mb.vlan_tci = C.uint16_t(vt)
}

func (mb *Mbuf) Metadata() unsafe.Pointer {
	return (unsafe.Pointer)(uintptr(unsafe.Pointer(mb)) + C.sizeof_struct_rte_mbuf)
}

func (mb *Mbuf) RefcntUpdate(v int16) {
	C.rte_pktmbuf_refcnt_update((*C.struct_rte_mbuf)(mb), C.int16_t(v))
}

func (mb *Mbuf) Refcnt() int {
	return int(C.rte_mbuf_refcnt_read((*C.struct_rte_mbuf)(mb)))
}

func (mb *Mbuf) Free() {
	C.rte_pktmbuf_free((*C.struct_rte_mbuf)(mb))
}

// Next returns a next segment of scattered packet.
func (mb *Mbuf) Next() *Mbuf {
	return (*Mbuf)(mb.next)
}
