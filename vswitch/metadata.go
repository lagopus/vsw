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

package vswitch

/*
#include "packet.h"
*/
import "C"

import "fmt"

const (
	VifInvalidIndex   = C.VIF_INVALID_INDEX // Invalid VIF Index
	VifMaxIndex       = C.VIF_MAX_INDEX     // The maximum VIF Index number
	VifBroadcastIndex = C.VIF_BROADCAST     //VIF Index for broadcast
	BridgeMaxID       = C.BRIDGE_MAX_ID     // Max Bridge ID number
)

// Metadata is a Lagopus2 internal data associated with each packet.
// Use dpdk.Mbuf's Metadata() to get a pointer to the metadata in the packet.
type Metadata C.struct_lagopus_packet_metadata

// VifIndex represents VIF index.
type VifIndex C.vifindex_t

// Get VRF.
func (m *Metadata) Vrf() uint64 {
	return uint64((*C.struct_lagopus_packet_metadata)(m).md_vif.vrf)
}

// Set VRF.
func (m *Metadata) SetVrf(vrf uint64) {
	(*C.struct_lagopus_packet_metadata)(m).md_vif.vrf = C.uint64_t(vrf)
}

// Get Tunnel ID.
func (m *Metadata) TunnelId() uint64 {
	return uint64((*C.struct_lagopus_packet_metadata)(m).md_vif.tunnel_id)
}

// Set Tunnel ID.
func (m *Metadata) SetTunnelId(tid uint64) {
	(*C.struct_lagopus_packet_metadata)(m).md_vif.tunnel_id = C.uint64_t(tid)
}

// Get Input VIF.
func (m *Metadata) InVIF() VifIndex {
	return VifIndex((*C.struct_lagopus_packet_metadata)(m).md_vif.in_vif)
}

// Set Input VIF.
func (m *Metadata) SetInVIF(vif VifIndex) {
	(*C.struct_lagopus_packet_metadata)(m).md_vif.in_vif = C.vifindex_t(vif)
}

// Get Output VIF.
func (m *Metadata) OutVIF() VifIndex {
	return VifIndex((*C.struct_lagopus_packet_metadata)(m).md_vif.out_vif)
}

// Set Output VIF.
func (m *Metadata) SetOutVIF(vif VifIndex) {
	(*C.struct_lagopus_packet_metadata)(m).md_vif.out_vif = C.vifindex_t(vif)
}

// Check if the packet is sent to the router itself.
func (m *Metadata) Self() bool {
	return (*C.struct_lagopus_packet_metadata)(m).md_vif.flags&C.LAGOPUS_MD_SELF != 0
}

// Set whether the packet is sent to the router itself.
func (m *Metadata) SetSelf(self bool) {
	if self {
		(*C.struct_lagopus_packet_metadata)(m).md_vif.flags |= C.LAGOPUS_MD_SELF
	} else {
		(*C.struct_lagopus_packet_metadata)(m).md_vif.flags &^= C.LAGOPUS_MD_SELF
	}
}

// Get incoming bridge domain ID.
func (m *Metadata) BridgeID() uint32 {
	return uint32((*C.struct_lagopus_packet_metadata)(m).md_vif.bridge_id)
}

// Set incoming bridge domain ID.
func (m *Metadata) SetBridgeID(bid uint32) {
	(*C.struct_lagopus_packet_metadata)(m).md_vif.bridge_id = C.uint32_t(bid)
}

func (m *Metadata) String() string {
	return fmt.Sprintf("VRF=%d TunnelID=%d InVIF=%d OutVIF=%d Self=%v",
		m.Vrf(), m.TunnelId(), m.InVIF(), m.OutVIF(), m.Self())
}
