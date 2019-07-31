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
package vswitch

import (
	"fmt"
	"net"
)

// VxLAN represetns VxLAN connection
type VxLAN struct {
	Src     net.IP // Source IP address.
	Dst     net.IP // Destination IP address.
	DstPort uint16 // UDP Destination Port (default: 4789)
	VNI     uint32 // VNI
}

const DefaultVxLANPort = 4789

func (v *VxLAN) String() string {
	return fmt.Sprintf("Src: %v, Dst: %v:%d, VNI: %x", v.Src, v.Dst, v.DstPort, v.VNI)
}
