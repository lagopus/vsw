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
// #include "vlan.h"
import "C"

import (
	"fmt"
	"unsafe"
)

const (
	// PktRxVLANStripped PKT_RX_VLAN_STRIPPED.
	PktRxVLANStripped uint64 = C.PKT_RX_VLAN_STRIPPED
	// PktRxVLAN PKT_RX_VLAN.
	PktRxVLAN uint64 = C.PKT_RX_VLAN
)

// VLAN struct vlan_hdr.
type CVLAN C.struct_vlan_hdr

func (v *CVLAN) vlanTCI() uint16 {
	return uint16(v.vlan_tci)
}

func (v *CVLAN) ethProto() uint16 {
	return uint16(v.eth_proto)
}

func vlanPop(m *Mbuf, vid *uint16) error {
	// pop.
	if ret := C.vlan_pop((*C.struct_rte_mbuf)(unsafe.Pointer(m)),
		(*C.uint16_t)(unsafe.Pointer(vid))); ret != C.LAGOPUS_RESULT_OK {
		return fmt.Errorf("Fail vlan_pop(): %v\n", ret)
	}

	return nil
}

func vlanPush(m *Mbuf) error {
	// psuh
	if ret := C.vlan_push((*C.struct_rte_mbuf)(unsafe.Pointer(m))); ret !=
		C.LAGOPUS_RESULT_OK {
		return fmt.Errorf("Fail vlan_push(): %v\n", ret)
	}

	return nil
}
