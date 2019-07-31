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
// #include "vxlan.h"
import "C"

import (
	"fmt"
	"unsafe"
)

const (
	// ValidVNIMask Mask for I flag.
	ValidVNIMask = C.VXLAN_VALID_VNI_MASK
	// VNIMask Mask for VNI.
	VNIMask = C.VXLAN_VNI_MASK
)

// CVXLAN struct vxlan_hdr.
type CVXLAN C.struct_vxlan_hdr

func (v *CVXLAN) flags() uint32 {
	return uint32(v.vx_flags)
}

func (v *CVXLAN) vni() uint32 {
	return uint32(v.vx_vni)
}

func encapVXLAN(m *Mbuf, vni uint32) (*CVXLAN, error) {
	var vxlan *C.struct_vxlan_hdr

	// encap.
	if ret := C.encap_vxlan((*C.struct_rte_mbuf)(unsafe.Pointer(m)),
		C.uint32_t(vni), (**C.struct_vxlan_hdr)(unsafe.Pointer(&vxlan))); ret !=
		C.LAGOPUS_RESULT_OK {
		return nil, fmt.Errorf("Fail encap_vxlan(): %v\n", ret)
	}

	return (*CVXLAN)(vxlan), nil
}

func decapVXLAN(m *Mbuf, vni uint32) (*CVXLAN, error) {
	var vxlan *C.struct_vxlan_hdr

	// decap.
	if ret := C.decap_vxlan((*C.struct_rte_mbuf)(unsafe.Pointer(m)),
		C.uint32_t(vni), (**C.struct_vxlan_hdr)(unsafe.Pointer(&vxlan))); ret !=
		C.LAGOPUS_RESULT_OK {
		return nil, fmt.Errorf("Fail decap_vxlan(): %v\n", ret)
	}

	return (*CVXLAN)(vxlan), nil
}
