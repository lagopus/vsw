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

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
	"sort"
	"testing"
)

const (
	IF0_0 = uint32(0)
	IF0_1 = uint32(1)
	IF0_2 = uint32(2)
)

func freevif(v *VIF, p *testInterfaceParam) error {
	v.Free()
	if _, err := p.checkOp(OpVIFFree); err != nil {
		return fmt.Errorf("Free() failed: %v", err)
	}
	return nil
}

func listIP(t *testing.T, addrs []IPAddr, expect int) {
	count := 0
	for _, addr := range addrs {
		t.Logf("\t%s", addr)
		count++
	}
	if count != expect {
		t.Errorf("VIF: # of IP address != 2 (%d)", count)
	}
}

func checkVIF(t *testing.T, p *testInterfaceParam, v *VIF, mac net.HardwareAddr) {
	vmac := v.MACAddress()
	if _, err := p.checkOp(OpMACAddress); err == nil {
		t.Fatalf("MACAddress() failed. Instance shouldn't be called")
	}

	if bytes.Compare(vmac, mac) != 0 {
		t.Errorf("VIF: %s != %s", mac, vmac)
	}
	t.Logf("VIF MAC: %s", vmac)

	t.Logf("Setting IP Addresses")

	ipv4 := IPAddr{IP: net.ParseIP("192.168.1.1"), Mask: net.CIDRMask(24, 32)}
	ipv6 := IPAddr{IP: net.ParseIP("2001:db8::68"), Mask: net.CIDRMask(64, 128)}

	if err := v.AddIPAddr(ipv4); err != nil {
		t.Errorf("VIF: Can't set IPv4: %s: %v", ipv4, err)
	}

	if err := v.AddIPAddr(ipv6); err != nil {
		t.Errorf("VIF: Can't set IPv6: %s: %v", ipv6, err)
	}

	// List all IP
	t.Logf("VIF: List All IP Address:\n")
	listIP(t, v.ListIPAddrs(), 2)

	// Change Prefix
	t.Logf("VIF: Modify IPv4 Address Prefix:")
	ipv4.Mask = net.CIDRMask(32, 32)
	if err := v.AddIPAddr(ipv4); err != nil {
		t.Errorf("VIF: Can't change prefix of IPv4: %s: %v", ipv4, err)
	}

	// List all IP
	t.Logf("VIF: List All IP Address:")
	listIP(t, v.ListIPAddrs(), 2)
}

func checkVIFIndex(t *testing.T, name string, idx VIFIndex) {
	vif := GetVIFByName(name)
	if vif.Index() == idx {
		t.Logf("VIFIndex for %s matched (idx=%d).", name, idx)
	} else {
		t.Errorf("VIFIndex for %s doesn't match. (Expected %d, Got %d)", name, idx, vif.Index())
	}
}

func TestVIFBasic(t *testing.T) {
	if err := RegisterModule(IFMODULE, newTestInterface, nil, TypeInterface); err != nil {
		t.Logf("Module already registered: %v", err)
	}

	t.Logf("TestInterface module registered.")
	p := &testInterfaceParam{
		mac: IF0_MAC,
		ch:  make(chan opcode, 4),
	}

	if0, err := p.newInterface(IFMODULE, IF0)
	if err != nil {
		t.Fatalf("NewInterface for %s failed: %v", IF0, err)
	}
	t.Logf("NewInterface succeeded.")

	// NewVIF
	vif0, err := p.newvif(if0, IF0_0)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("NewVIF() ok.")

	// test VIF
	checkVIF(t, p, vif0, IF0_MAC)
	checkVIFIndex(t, "if0-0", vif0.Index())

	// Free VIF
	if err := freevif(vif0, p); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("VIF.Free() ok.")

	// Free
	if err := p.free(if0); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("Free() ok.")
}

func TestVIFAccessMode(t *testing.T) {
	p := &testInterfaceParam{
		mac: IF0_MAC,
		ch:  make(chan opcode, 2),
	}

	if0, err := p.newInterface(IFMODULE, IF0)
	if err != nil {
		t.Fatalf("NewInterface for %s failed: %v", IF0, err)
	}
	t.Logf("NewInterface succeeded.")

	// Set to Access Mode then add VID 100
	if err := p.ifmode(if0, AccessMode, true); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("SetInterfaceMode(%v) ok.", AccessMode)

	if err := p.addvid(if0, 100, true); err != nil {
		t.Fatalf("%v", err)
	}
	if !reflect.DeepEqual(if0.VID(), []VID{100}) {
		t.Fatalf("VID not as expected: %v", if0.VID())
	}
	t.Logf("AddVIF(100) ok: %v", if0.VID())

	// NewVIF
	vif0, err := p.newvif(if0, IF0_0)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("NewVIF() ok.")

	// Try set to invalid VID
	if err := vif0.SetVID(200); err == nil {
		t.Fatalf("SetVID(200) succeeded. Should have failed.")
	} else {
		t.Logf("VIF.SetVID(200) failed ok: %v", err)
	}

	// Now set to valid VID
	if err := vif0.SetVID(100); err != nil {
		t.Fatalf("SetVID(100) failed: %v", err)
	}
	t.Logf("VIF.SetVID(100) ok")

	/*
		XXX: This test success if the VIF is connected to other instance.

			if err := vif0.Enable(); err != nil {
				t.Errorf("VIF.Enable() failed: %v", err)
			}
			if _, err := p.checkOp(OpVIFEnable); err != nil {
				t.Fatalf("VIF.Enable() failed: %v", err)
			}
			t.Logf("VIF.Enable() ok.")
	*/

	/// Free
	if err := p.free(if0); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("Free() ok.")
}

func TestVIFTrunkMode(t *testing.T) {
	p := &testInterfaceParam{
		mac: IF0_MAC,
		ch:  make(chan opcode, 10),
	}

	if0, err := p.newInterface(IFMODULE, IF0)
	if err != nil {
		t.Fatalf("NewInterface for %s failed: %v", IF0, err)
	}
	t.Logf("NewInterface succeeded.")

	// Set to Trunk Mode then add VID 100, 200, and 300
	if err := p.ifmode(if0, TrunkMode, true); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("SetInterfaceMode(%v) ok.", TrunkMode)

	vids := []VID{100, 200, 300}
	for _, vid := range vids {
		if err := p.addvid(if0, vid, true); err != nil {
			t.Fatalf("%v", err)
		}
	}
	ivids := if0.VID()
	sort.Sort(VIDS(ivids))
	if !reflect.DeepEqual(ivids, vids) {
		t.Fatalf("VID not as expected: %v", if0.VID())
	}
	t.Logf("AddVIF() ok: %v", if0.VID())

	// NewVIF
	vif0, err := p.newvif(if0, IF0_0)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("NewVIF() ok: vif0")

	vif1, err := p.newvif(if0, IF0_1)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("NewVIF() ok: vif1")

	vif2, err := p.newvif(if0, IF0_2)
	if err != nil {
		t.Fatalf("%v", err)
	}

	t.Logf("NewVIF() ok: vif1")

	// vif0 to 100
	if err := vif0.SetVID(100); err != nil {
		t.Fatalf("SetVID(100) failed: %v", err)
	}
	t.Logf("vif0.SetVID(100) ok")

	// vif1 to 200
	if err := vif1.SetVID(200); err != nil {
		t.Fatalf("SetVID(200) failed: %v", err)
	}
	t.Logf("vif1.SetVID(200) ok")

	// vif2 to 200 (should fail)
	if err := vif2.SetVID(200); err == nil {
		t.Fatalf("vif2.SetVID(200) succeeded")
	}
	t.Logf("vif2.SetVID(200) failed. ok")

	// vif1 to 300
	if err := vif1.SetVID(300); err != nil {
		t.Fatalf("SetVID(300) failed: %v", err)
	}
	t.Logf("vif1.SetVID(300) ok")

	// vif2 to 200
	if err := vif2.SetVID(200); err != nil {
		t.Fatalf("SetVID(200) failed: %v", err)
	}
	t.Logf("vif2.SetVID(200) ok")

	/// Free
	if err := p.free(if0); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("Free() ok.")
}

func TestVIFSetVRF(t *testing.T) {
	p := &testInterfaceParam{
		mac: IF0_MAC,
		ch:  make(chan opcode, 10),
	}

	if0, err := p.newInterface(IFMODULE, IF0)
	if err != nil {
		t.Fatalf("NewInterface for %s failed: %v", IF0, err)
	}
	t.Logf("NewInterface succeeded.")

	// NewVRF
	vrf, err := NewVRF("vrf0")
	if err != nil {
		t.Fatalf("NewVRF() failed: %v", err)
	}

	// NewVIF
	vif0, err := p.newvif(if0, IF0_0)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("NewVIF() ok")

	// SetVRF
	if err := p.vifSetVRF(vif0, vrf); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("SetVRF(%v) ok", vrf)

	// SetVRF
	if err := p.vifSetVRF(vif0, nil); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("SetVRF(nil) ok")

	// Free
	if err := p.free(if0); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("Free() ok.")

	vrf.Free()
}
