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

package vswitch

/*
#include "packet.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Metadata is a Lagopus2 internal data associated with each packet.
// Use dpdk.Mbuf's Metadata() to get a pointer to the metadata in the packet.
type Metadata C.struct_vsw_packet_metadata

// VIFIndex represents VIF index.
type VIFIndex C.vifindex_t
type VRFIndex C.vrfindex_t

// Get Input VIF.
func (m *Metadata) InVIF() VIFIndex {
	return VIFIndex((*C.struct_vsw_packet_metadata)(m).common.in_vif)
}

// Set Input VIF.
func (m *Metadata) SetInVIF(vif VIFIndex) {
	(*C.struct_vsw_packet_metadata)(m).common.in_vif = C.vifindex_t(vif)
}

// Get Output VIF.
func (m *Metadata) OutVIF() VIFIndex {
	return VIFIndex((*C.struct_vsw_packet_metadata)(m).common.out_vif)
}

// Set Output VIF.
func (m *Metadata) SetOutVIF(vif VIFIndex) {
	(*C.struct_vsw_packet_metadata)(m).common.out_vif = C.vifindex_t(vif)
}

// Get Local Flag.
func (m *Metadata) Local() bool {
	return bool((*C.struct_vsw_packet_metadata)(m).common.local)
}

// Set Local Flag.
func (m *Metadata) SetLocal(l bool) {
	(*C.struct_vsw_packet_metadata)(m).common.local = C.bool(l)
}

// Reset clears the metadata
func (m *Metadata) Reset() {
	C.memset(unsafe.Pointer(m), 0, C.sizeof_struct_vsw_common_metadata)
}

func (m *Metadata) String() string {
	return fmt.Sprintf("InVIF=%d OutVIF=%d", m.InVIF(), m.OutVIF())
}
