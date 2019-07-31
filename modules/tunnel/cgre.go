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
// #include "gre.h"
import "C"

import (
	"fmt"
	"unsafe"
)

// CGRE struct gre_hdr.
type CGRE C.struct_gre_hdr

func (c *CGRE) version() uint16 {
	return uint16(c.flags)
}

func (c *CGRE) protocol() uint16 {
	return uint16(c.proto)
}

func encapGRE(m *Mbuf, proto uint16) (*CGRE, error) {
	var gre *C.struct_gre_hdr

	// encap.
	if ret := C.encap_gre((*C.struct_rte_mbuf)(unsafe.Pointer(m)),
		C.uint16_t(proto)); ret != C.LAGOPUS_RESULT_OK {
		return nil, fmt.Errorf("Fail encap_gre(): %v\n", ret)
	}

	return (*CGRE)(gre), nil
}

func decapGRE(m *Mbuf) (*CGRE, error) {
	var gre *C.struct_gre_hdr

	// decap.
	if ret := C.decap_gre((*C.struct_rte_mbuf)(unsafe.Pointer(m)),
		(**C.struct_gre_hdr)(unsafe.Pointer(&gre))); ret !=
		C.LAGOPUS_RESULT_OK {
		return nil, fmt.Errorf("Fail decap_gre(): %v\n", ret)
	}

	return (*CGRE)(gre), nil
}
