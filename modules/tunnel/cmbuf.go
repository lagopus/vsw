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

// 'go test' is unsupported CGO. Unuse *_test.go.
// +build test

// For test.

package tunnel

// #include "packet.h"
// #include "mbuf.h"
import "C"

import (
	"unsafe"

	"github.com/lagopus/vsw/dpdk"
)

// Mbuf struct ret_mbuf.
type Mbuf struct {
	dpdk.Mbuf
}

// Free Free mbuf.
func (m *Mbuf) Free() {
	C.free(unsafe.Pointer(m))
}

// OLFlags Get ol_flags.
func (m *Mbuf) OLFlags() uint64 {
	mbuf := (*C.struct_rte_mbuf)(unsafe.Pointer(m))
	return uint64(mbuf.ol_flags)
}

// Alloc Mbuf.
func allocMbuf() *Mbuf {
	priSize := C.uint16_t(C.RTE_MBUF_PRIV_ALIGN +
		C.PACKET_METADATA_SIZE)
	bufSize := C.uint16_t(C.RTE_PKTMBUF_HEADROOM +
		C.MAX_PACKET_SZ)
	mbufSize := C.uint16_t(C.sizeof_struct_rte_mbuf +
		priSize)
	size := C.uint16_t(mbufSize +
		bufSize)

	mbuf := (*C.struct_rte_mbuf)(unsafe.Pointer(
		C.calloc(1, C.size_t(size))))
	if mbuf != nil {
		mbuf.priv_size = size
		mbuf.buf_addr = (unsafe.Pointer)(uintptr(unsafe.Pointer(mbuf)) +
			uintptr(mbufSize))
		mbuf.buf_len = bufSize
		C.rte_pktmbuf_reset(mbuf)
		C.rte_mbuf_refcnt_set(mbuf, 1)
	}
	return (*Mbuf)(unsafe.Pointer(mbuf))
}
