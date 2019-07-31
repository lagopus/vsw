//
// Copyright 2019 Nippon Telegraph and Telephone Corporation.
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

package vxlan

// #include "lagopus_apis.h"
// #include "vxlan_includes.h"
// #include "fdb.h"
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"
)

func bytes2Uint(d []byte) uint32 {
	var num uint32
	buf := bytes.NewBuffer(d)
	binary.Read(buf, binary.LittleEndian, &num)
	return num
}

func uint2IP(i uint32) *net.IP {
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, i)
	ip := net.IP(bytes)
	return &ip
}

func (e *CFDBEntry) remoteIP2Uint() uint32 {
	return binary.LittleEndian.Uint32(e.remote_ip.ip[:])
}

func (e *CFDBEntry) refed() bool {
	return bool(e.referred)
}

// CEtherAddr struct ether_addr.
type CEtherAddr C.struct_ether_addr

func newCEtherAddr(mac *MacAddress) *CEtherAddr {
	var cmac CEtherAddr

	for i, v := range mac {
		cmac.addr_bytes[i] = C.uint8_t(v)
	}

	return &cmac
}

// CIP struct ip.
type CIP C.struct_ip

func newCIP(l3 []byte) *CIP {
	var cip CIP

	C.memcpy(unsafe.Pointer(&cip), unsafe.Pointer(&l3[0]),
		C.sizeof_struct_ip)

	return &cip
}

// CFDB struct fdb.
type CFDB C.struct_fdb

func allocFDB() (*CFDB, error) {
	var f *CFDB

	// initialize.
	if ret := C.fdb_alloc(
		(**C.struct_fdb)(unsafe.Pointer(&f)),
		C.uint8_t(0)); ret != C.LAGOPUS_RESULT_OK {
		return nil, fmt.Errorf("Fail fdb_initialize(): %v", ret)
	}

	return f, nil
}

func (f *CFDB) free() error {
	if ret := C.fdb_free(
		(**C.struct_fdb)(unsafe.Pointer(&f))); ret != C.LAGOPUS_RESULT_OK {
		return fmt.Errorf("Fail fdb_finalize(): %v", ret)
	}

	return nil
}

func (f *CFDB) learn(mac *CEtherAddr, ip *CIP) error {
	if ret := C.fdb_learn(
		(*C.struct_fdb)(unsafe.Pointer(f)),
		(*C.struct_ether_addr)(unsafe.Pointer(mac)),
		(*C.struct_ip)(unsafe.Pointer(ip)),
		nil); ret != C.LAGOPUS_RESULT_OK {
		return fmt.Errorf("Fail fdb_learn(): %v", ret)
	}

	return nil
}

func (f *CFDB) del(mac *CEtherAddr) error {
	if ret := C.fdb_delete(
		(*C.struct_fdb)(unsafe.Pointer(f)),
		(*C.struct_ether_addr)(unsafe.Pointer(mac))); ret != C.LAGOPUS_RESULT_OK {
		return fmt.Errorf("Fail fdb_delete(): %v", ret)
	}

	return nil
}

func (f *CFDB) clear() error {
	if ret := C.fdb_clear(
		(*C.struct_fdb)(unsafe.Pointer(f))); ret != C.LAGOPUS_RESULT_OK {
		return fmt.Errorf("Fail fdb_clear(): %v", ret)
	}

	return nil
}

func (f *CFDB) find(mac *CEtherAddr) (*CFDBEntry, error) {
	var entry CFDBEntry

	ret := C.fdb_find_copy(
		(*C.struct_fdb)(unsafe.Pointer(f)),
		(*C.struct_ether_addr)(unsafe.Pointer(mac)),
		(*C.struct_fdb_entry)(unsafe.Pointer(&entry)))
	if ret != C.LAGOPUS_RESULT_OK {
		if ret != C.LAGOPUS_RESULT_NOT_FOUND {
			return nil, fmt.Errorf("Fail fdb_find_copy(): %v", ret)
		}
		return nil, nil
	}

	return &entry, nil
}

func (f *CFDB) gc(mac *CEtherAddr) (*CFDBEntry, error) {
	var entry *CFDBEntry

	if ret := C.fdb_gc(
		(*C.struct_fdb)(unsafe.Pointer(f)),
		(*C.struct_ether_addr)(unsafe.Pointer(mac)),
		(**C.struct_fdb_entry)(unsafe.Pointer(&entry))); ret != C.LAGOPUS_RESULT_OK {
		return nil, fmt.Errorf("Fail fdb_aging(): %v", ret)
	}

	return entry, nil
}
