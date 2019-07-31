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
// #include "lagopus_types.h"
// #include "lagopus_error.h"
// #include "mbuf.h"
// #include "udp.h"
import "C"

import (
	"fmt"
	"unsafe"
)

// CUDP struct udp_hdr.
type CUDP C.struct_udp_hdr

func (u *CUDP) srcPort() uint16 {
	return uint16(u.src_port)
}

func (u *CUDP) dstPort() uint16 {
	return uint16(u.dst_port)
}

func (u *CUDP) dgramLen() uint16 {
	return uint16(u.dgram_len)
}

func (u *CUDP) dgramCksum() uint16 {
	return uint16(u.dgram_cksum)
}

func (u *CUDP) free() {
	fmt.Printf("go2 %p\n", u)
	C.free(unsafe.Pointer(u))
}

func genSRCPort(ether *byte, min uint16, max uint16) uint16 {
	// generate port.
	return uint16(C.udp_gen_src_port((*C.struct_ether_hdr)(unsafe.Pointer(ether)),
		C.uint16_t(min), C.uint16_t(max)))
}

func insertChecksum(udp *byte, l3 *byte, etherType uint16) error {
	// insert checksum.
	if ret := C.udp_insert_checksum((*C.struct_udp_hdr)(unsafe.Pointer(udp)),
		unsafe.Pointer(l3), C.uint16_t(etherType)); ret != C.LAGOPUS_RESULT_OK {
		return fmt.Errorf("Fail udpInsertChecksum(): %v\n", ret)
	}

	return nil
}

func encapUDP(m *Mbuf, srcPort uint16, dstPort uint16) (*CUDP, error) {
	var udp *C.struct_udp_hdr

	// encap.
	if ret := C.encap_udp((*C.struct_rte_mbuf)(unsafe.Pointer(m)),
		C.uint16_t(srcPort), C.uint16_t(dstPort),
		(**C.struct_udp_hdr)(unsafe.Pointer(&udp))); ret != C.LAGOPUS_RESULT_OK {
		return nil, fmt.Errorf("Fail encap_udp(): %v\n", ret)
	}

	return (*CUDP)(udp), nil
}

func decapUDP(m *Mbuf, l3 *byte, etherType uint16, calCksum bool) (*CUDP, error) {
	var udp *C.struct_udp_hdr

	// decap.
	if ret := C.decap_udp((*C.struct_rte_mbuf)(unsafe.Pointer(m)),
		unsafe.Pointer(l3), C.uint16_t(etherType), C.bool(calCksum),
		(**C.struct_udp_hdr)(unsafe.Pointer(&udp))); ret != C.LAGOPUS_RESULT_OK {
		return nil, fmt.Errorf("Fail decap_udp(): %v\n", ret)
	}

	return (*CUDP)(udp), nil
}
