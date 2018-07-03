//
// Copyright 2018 Nippon Telegraph and Telephone Corporation.
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

package main

import (
	"fmt"
	"github.com/lagopus/vsw/vswitch"
	"net"
)

func l3_sample1() {
	//
	// 1. interfaces part
	//

	// Create interface if0
	if0, _ := vswitch.NewInterface("dpdk", "if0", dev["if0"])
	if0.SetMTU(1500)

	// Create subinterface if0-0
	if0_0 := if0.NewVIF("0")
	if0_0.AddIPAddr(IPAddr{net.IPv4(172, 16, 110, 1), net.CIDRMask(24, 32)})
	if0_0.Enable()

	// Create interface if1
	if1, _ := vswitch.NewInterface("dpdk", "if1", dev["if1"])
	if1.SetMTU(1500)

	// Create subinterface if1-0
	if1_0 := if1.NewVIF("0")
	if1_0.AddIPAddr(IPAddr{net.IPv4(10, 10, 0, 1), net.CIDRMask(24, 32)})
	if1_0.Enable()

	//
	// 2. network-instances part
	//

	// Create VRF1
	vrf1 := vswitch.NewVRF("VRF1")
	vrf1.SetMTU(1500)
	vrf1.AddVIF(if0_0)
	vrf1.AddVIF(if1_0)
	vrf1.Enable() // Starts VRF1 instance
}
