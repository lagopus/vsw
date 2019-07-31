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

package vxlan

// #include "lagopus_apis.h"
// #include "vxlan_includes.h"
// #include "fdb.h"
// #include "metadata.h"
import "C"
import (
	"net"
	"unsafe"
)

// Entry2CFDBEntry Entry => CFDBEntry.
func Entry2CFDBEntry(e *Entry) *CFDBEntry {
	mac := (*C.struct_ether_addr)(unsafe.Pointer(&e.MacAddr[0]))

	ce := &CFDBEntry{
		mac: *mac,
	}

	if ip := e.RemoteIP.To4(); ip != nil {
		ce.ver = C.IPVERSION
		ce.len = C.IP4_ADDR_LEN
		copy(ce.remote_ip.ip[:], ip[:])
	} else {
		ce.ver = C.IP6_VERSION
		ce.len = C.IP6_ADDR_LEN
		copy(ce.remote_ip.ip[:], e.RemoteIP[:])
	}

	return ce
}

// CFDBEntry struct fdb_entry.
type CFDBEntry C.struct_fdb_entry

// RemoteIP Get remote_ip.
func (e *CFDBEntry) RemoteIP() *net.IP {
	len := e.RemoteIPLen()
	ip := net.IP((*[1 << 30]byte)(unsafe.Pointer(&e.remote_ip.ip))[:len:len])
	return &ip
}

// RemoteIPLen Get len.
func (e *CFDBEntry) RemoteIPLen() uint8 {
	return uint8(e.len)
}

// MacAddr Get mac.
func (e *CFDBEntry) MacAddr() *MacAddress {
	mac := (*MacAddress)(unsafe.Pointer(&e.mac.addr_bytes))
	return mac
}

// NewControlParam Create ControlParam.
func (e *CFDBEntry) NewControlParam(cmd L2tunCmd) *ControlParam {
	param := &ControlParam{
		cmd: C.l2tun_cmd_t(cmd),
	}
	vxlanParam := C.struct_vxlan_ctrl_param_metadata{
		entry: C.struct_fdb_entry(*e),
	}

	C.memcpy(unsafe.Pointer(&param.metadata),
		unsafe.Pointer(&vxlanParam),
		C.sizeof_struct_vxlan_ctrl_param_metadata)

	return param
}
