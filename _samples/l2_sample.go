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
	"github.com/lagopus/vsw/vswitch"
)

func l2_sample() error {
	var if0, if1, if2 *vswitch.Interface
	var if0_0, if1_0, if2_100, if2_200 *vswitch.VIF
	var vsi1 *vswitch.VSI
	var err error
	//
	// 1. interfaces part
	//

	//
	// Create interface if0
	if0, err = vswitch.NewInterface("dpdk", "if0", dev["if0"])
	if err != nil {
		return err
	}
	if err := if0.SetMTU(1518); err != nil {
		return err
	}
	if err := if0.AddVID(100); err != nil {
		return err
	}
	if err := if0.SetInterfaceMode(vswitch.AccessMode); err != nil {
		return err
	}
	if err := if0.Enable(); err != nil {
		return err
	}

	// Create subinterface if0-0
	if0_0, err = if0.NewVIF(0)
	if err != nil {
		return err
	}
	if err := if0_0.SetVID(100); err != nil {
		return err
	}
	if err := if0_0.Enable(); err != nil {
		return err
	}

	//
	// Create interface if1
	if1, err = vswitch.NewInterface("dpdk", "if1", dev["if1"])
	if err != nil {
		return err
	}
	if err := if1.SetMTU(1518); err != nil {
		return err
	}
	if1.AddVID(200)
	if1.SetInterfaceMode(vswitch.AccessMode)
	if1.Enable()

	// Create subinterface if1-0
	if1_0, err = if1.NewVIF(0)
	if err != nil {
		return err
	}
	if1_0.SetVID(200)
	if1_0.Enable()

	//
	// Create interface if2
	if2, err = vswitch.NewInterface("dpdk", "if2", dev["if2"])
	if err != nil {
		return err
	}
	if2.SetMTU(1518)
	if2.SetInterfaceMode(vswitch.TrunkMode)
	if2.AddVID(100)
	if2.AddVID(200)
	if2.Enable()

	// Create subinterface if2-100
	if2_100, err = if2.NewVIF(100)
	if err != nil {
		return err
	}
	if2_100.SetVID(100)
	if2_100.Enable()

	// Create subinterface if2-200
	if2_200, err = if2.NewVIF(200)
	if err != nil {
		return err
	}
	if2_200.SetVID(200)
	if2_200.Enable()

	//
	// 2. network-instances part
	//

	// Create VSI1
	vsi1, err = vswitch.NewVSI("VSI1")
	if err != nil {
		return err
	}
	if err := vsi1.AddVID(100); err != nil {
		return err
	}
	if err := vsi1.AddVID(200); err != nil {
		return err
	}
	if err := vsi1.EnableVID(100); err != nil {
		return err
	}
	if err := vsi1.EnableVID(200); err != nil {
		return err
	}
	if err := vsi1.AddVIF(if0_0); err != nil { // VID:100
		return err
	}
	if err := vsi1.AddVIF(if2_100); err != nil { // VID:100
		return err
	}
	if err := vsi1.AddVIF(if1_0); err != nil { // VID:200
		return err
	}
	if err := vsi1.AddVIF(if2_200); err != nil { // VID:200
		return err
	}
	if err := vsi1.SetMACAgingTime(300); err != nil {
		return err
	}
	vsi1.EnableMACLearning()
	if err := vsi1.SetMaximumEntries(3000); err != nil {
		return err
	}
	if err := vsi1.Enable(); err != nil { // Starts VSI1 instance
		return err
	}

	return nil
}
