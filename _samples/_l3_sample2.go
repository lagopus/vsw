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

func l3_sample2() {
	//
	// 1. interfaces part
	//

	//
	// Create interface if0
	if0, _ := vswitch.NewInterface("dpdk", "if0", dev["if0"])
	if0.SetMTU(1518)
	if0.AddVID(100)
	if0.SetInterfaceMode(vswitch.AccessMode)

	// Create subinterface if0-0
	if0_0 := if0.NewVIF("0")
	if0_0.Enable()
	if0_0.SetVID(100)

	//
	// Create interface if1
	if1, _ := vswitch.NewInterface("dpdk", "if1", dev["if1"])
	if1.SetMTU(1518)
	if1.AddVID(200)
	if1.SetInterfaceMode(vswitch.AccessMode)

	// Create subinterface if1-0
	if1_0 := if1.NewVIF("0")
	if1_0.Enable()
	if1_0.SetVID(200)

	//
	// Create interface if2
	if2, _ := vswitch.NewInterface("dpdk", "if2", dev["if2"])
	if2.SetMTU(1518)
	if2.SetInterfaceMode(vswitch.TrunkMode)
	if2.AddVID(100)
	if2.AddVID(200)

	// Create subinterface if2-100
	if2_100 := if1.NewVIF("100")
	if2_100.Enable()
	if2_100.SetVID(100)

	// Create subinterface if2-200
	if2_200 := if1.NewVIF("200")
	if2_200.Enable()
	if2_200.SetVID(200)

	//
	// Create interface rif0
	rif0, _ := vswitch.NewInterface("local", "rif0", nil)
	rif0.SetMTU(1518)
	rif0.AddVID(100)
	rif0.SetInterfaceMode(vswitch.AccessMode)

	// Create subinterface rif0-100
	rif0_100 := rif0.NewVIF("100")
	rif0_100.AddIPAddr(IPAddr{net.IPv4(10, 10, 0, 1), net.CIDRMask(24, 32)})
	rif0_100.Enable()
	rif0_100.SetVID(100)

	//
	// Create interface rif1
	rif1, _ := vswitch.NewInterface("local", "rif1", nil)
	rif1.SetMTU(1518)
	rif1.AddVID(200)
	rif1.SetInterfaceMode(vswitch.AccessMode)

	// Create subinterface rif1-200
	rif1_200 := rif1.NewVIF("200")
	rif1_200.AddIPAddr(IPAddr{net.IPv4(10, 1, 0, 1), net.CIDRMask(24, 32)})
	rif1_200.Enable()
	rif1_200.SetVID(200)

	//
	// 2. network-instances part
	//

	// Create VRF1
	vrf1 := vswitch.NewVRF("VRF1")
	vrf1.SetMTU(1500)
	vrf1.AddVIF(rif0_100)
	vrf1.AddVIF(rif1_200)
	vrf1.Enable() // Starts VRF1 instance

	// Create VSI1
	vsi1 := vswitch.NewVSI("VSI1")
	vsi1.AddVID(100)
	vsi1.SetVIDEnable(100, true)
	vsi1.AddVID(200)
	vsi1.SetVIDEnable(200, true)
	vsi1.AddVIF(if0_0)    // VID:100
	vsi1.AddVIF(if1_0)    // VID:200
	vsi1.AddVIF(if2_100)  // VID:100
	vsi1.AddVIF(if2_200)  // VID:200
	vsi1.AddVIF(rif0_100) // VID:100
	vsi1.AddVIF(rif1_200) // VID:200
	vsi1.Enable()         // Starts VSI1 instance
	vsi1.SetMTU(1500)

	<-quit
}
