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

func l3_sample3(quit chan bool, done chan bool) {
	//
	// 1. interfaces part
	//

	//
	// Create interface if0
	if0, _ := vswitch.NewInterface("dpdk", "if0", dev["if0"])
	if0.SetMTU(1500)
	if0.AddVID(100)
	if0.SetInterfaceMode(vswitch.AccessMode)

	// Create subinterface if0-0
	if0_0 := if0.NewVIF("0")
	if0_0.Enable()
	if0_0.SetVID(100)

	//
	// Create interface if1
	if1, _ := vswitch.NewInterface("dpdk", "if1", dev["if1"])
	if1.SetMTU(1500)
	if1.SetInterfaceMode(vswitch.TrunkMode)
	if1.AddVID(200)
	if1.AddVID(201)

	// Create subinterface if1-200
	if1_200 := if1.NewVIF("200")
	if1_200.Enable()
	if1_200.AddIPAddr(IPAddr{net.IPv4(10, 0, 0, 1), net.CIDRMask(24, 32)})
	if1_200.SetVID(200)

	// Create subinterface if1-201
	if1_201 := if1.NewVIF("201")
	if1_201.Enable()
	if1_201.AddIPAddr(IPAddr{net.IPv4(10, 0, 0, 1), net.CIDRMask(24, 32)})
	if1_201.SetVID(201)

	//
	// Create interface rif0
	rif0, _ := vswitch.NewInterface("local", "rif0", nil)
	rif0.SetMTU(1500)
	rif0.AddVID(100)
	rif0.SetInterfaceMode(vswitch.AccessMode)

	// Create subinterface rif0-0
	rif0_0 := rif0.NewVIF("0")
	rif0_0.AddIPAddr(IPAddr{net.IPv4(192, 168, 0, 1), net.CIDRMask(24, 32)})
	rif0_0.Enable()
	rif0_0.SetVID(100)

	//
	// Create interface rif1
	rif1, _ := vswitch.NewInterface("local", "rif1", nil)
	rif1.SetMTU(1500)
	rif1.AddVID(100)
	rif1.SetInterfaceMode(vswitch.AccessMode)

	// Create subinterface rif1-0
	rif1_0 := rif1.NewVIF("0")
	rif1_0.AddIPAddr(IPAddr{net.IPv4(192, 168, 0, 2), net.CIDRMask(24, 32)})
	rif1_0.Enable()
	rif1_0.SetVID(100)

	//
	// 2. network-instances part
	//

	// Create VRF1
	vrf1 := vswitch.NewVRF("VRF1")
	vrf1.AddVIF(if1_200)
	vrf1.AddVIF(rif0_0)
	vrf1.Enable() // Starts VRF1 instance
	vrf1.SetMTU(1500)

	// Create VRF2
	vrf2 := vswitch.NewVRF("VRF2")
	vrf2.AddVIF(if1_201)
	vrf2.AddVIF(rif1_0)
	vrf2.Enable() // Starts VRF2 instance
	vrf2.SetMTU(1500)

	// Create VSI1
	vsi1 := vswitch.NewVSI("VSI1")
	vsi1.AddVID(100)
	vsi1.SetVIDEnable(100, true)
	vsi1.AddVIF(if0_0)  // VID:100
	vsi1.AddVIF(rif0_0) // VID:100
	vsi1.AddVIF(rif1_1) // VID:100
	vsi1.Enable()       // Starts VSI1 instance
	vsi1.SetMTU(1500)
	vsi1.SetMACAgingTime(300)
	vsi1.SetMACLearning(true)
	vsi1.SetMaximumEntries(3000)

	<-quit
}
