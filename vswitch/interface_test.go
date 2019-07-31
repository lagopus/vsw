//
// Copyright 2018-2019 Nippon Telegraph and Telephone Corporation.
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
	IFMODULE = "TestInterface"
	IF0      = "if0"
	MTU_GOOD = 1486
	MTU_BAD1 = 10
	MTU_BAD2 = 20000
)

var IF0_MAC = net.HardwareAddr{0x10, 0x02, 0x03, 0x04, 0x05, 0x06}
var IF1_MAC = net.HardwareAddr{0x10, 0x02, 0x03, 0x04, 0x05, 0x07}

type VIDS []VID

func (v VIDS) Len() int           { return len(v) }
func (v VIDS) Swap(i, j int)      { v[i], v[j] = v[j], v[i] }
func (v VIDS) Less(i, j int) bool { return v[i] < v[j] }

type testInterface struct {
	base      *BaseInstance
	mtu       MTU
	mac       net.HardwareAddr
	mode      VLANMode
	vid       map[VID]struct{}
	nativeVID VID
	ch        chan opcode
}

type testInterfaceParam struct {
	mac net.HardwareAddr
	ch  chan opcode
}

type testVIF struct {
	vif   *VIF
	iface *testInterface
	vrf   *VRF
}

func newTestInterface(base *BaseInstance, priv interface{}) (Instance, error) {
	p, ok := priv.(*testInterfaceParam)
	if !ok {
		return nil, fmt.Errorf("%s is testInterfaceParam", priv)
	}

	iface := &testInterface{
		base: base,
		mtu:  MTU(DefaultMTU),
		mac:  p.mac,
		mode: AccessMode,
		vid:  make(map[VID]struct{}),
		ch:   p.ch,
	}

	return iface, nil
}

func (t *testInterface) Enable() error {
	t.ch <- OpEnable
	return nil
}

func (t *testInterface) Disable() {
	t.ch <- OpDisable
}

func (t *testInterface) Free() {
	t.ch <- OpFree
}

func (t *testInterface) NewVIF(vif *VIF) (VIFInstance, error) {
	t.ch <- OpNewVIF
	return &testVIF{vif, t, nil}, nil
}

func (t *testInterface) MACAddress() net.HardwareAddr {
	t.ch <- OpMACAddress
	return t.mac
}

func (t *testInterface) SetMACAddress(mac net.HardwareAddr) error {
	t.ch <- OpSetMACAddress
	t.mac = mac
	return nil
}

func (t *testInterface) MTU() MTU {
	t.ch <- OpMTU
	return t.mtu
}

func (t *testInterface) SetMTU(mtu MTU) error {
	t.ch <- OpSetMTU
	if mtu < 68 || mtu > 9000 {
		return fmt.Errorf("MTU out of range: %d", mtu)
	}
	t.mtu = mtu
	return nil
}

func (t *testInterface) InterfaceMode() VLANMode {
	t.ch <- OpInterfaceMode
	return t.mode
}

func (t *testInterface) SetInterfaceMode(mode VLANMode) error {
	t.ch <- OpSetInterfaceMode
	t.mode = mode
	return nil
}

func (t *testInterface) AddVID(vid VID) error {
	t.ch <- OpAddVID
	if _, exists := t.vid[vid]; exists {
		return fmt.Errorf("VID already exists: %d", vid)
	}
	t.vid[vid] = struct{}{}
	return nil
}

func (t *testInterface) DeleteVID(vid VID) error {
	t.ch <- OpDeleteVID
	if _, exists := t.vid[vid]; !exists {
		return fmt.Errorf("No such VID: %d", vid)
	}
	delete(t.vid, vid)
	return nil
}

func (t *testInterface) SetNativeVID(vid VID) error {
	t.ch <- OpSetNativeVID
	t.nativeVID = vid
	return nil
}

func (t *testVIF) Free() {
	t.iface.ch <- OpVIFFree
}

func (t *testVIF) Enable() error {
	t.iface.ch <- OpVIFEnable
	return nil
}

func (t *testVIF) Disable() {
	t.iface.ch <- OpVIFDisable
}

func (t *testVIF) SetVRF(vrf *VRF) {
	t.vrf = vrf
	t.iface.ch <- OpVIFSetVRF
}

func (t *testInterfaceParam) checkOp(ops ...opcode) (opcode, error) {
	for {
		select {
		case rc := <-t.ch:
			for _, op := range ops {
				if rc == op {
					return op, nil
				}
			}
			return OpInvalid, fmt.Errorf("Expected %v. Got %v", ops, rc)
		default:
			return OpInvalid, fmt.Errorf("Instance not called.")
		}
	}
}

func (t *testInterfaceParam) newInterface(ifmodule, name string) (*Interface, error) {
	if0, err := NewInterface(ifmodule, name, t)
	if err != nil {
		return nil, err
	}

	// We should exepct to see MACAddress
	if _, err := t.checkOp(OpMACAddress); err != nil {
		return nil, err
	}

	return if0, nil
}

func (t *testInterfaceParam) enable(i *Interface) error {
	if err := i.Enable(); err != nil {
		return fmt.Errorf("Enable() failed: %v", err)
	}
	if _, err := t.checkOp(OpEnable); err != nil {
		return fmt.Errorf("Enable() failed: %v", err)
	}
	if !i.IsEnabled() {
		return fmt.Errorf("Interface not enabled.")
	}
	return nil
}

func (t *testInterfaceParam) disable(i *Interface) error {
	i.Disable()
	if _, err := t.checkOp(OpDisable); err != nil {
		return fmt.Errorf("Disable() failed: %v", err)
	}
	if i.IsEnabled() {
		return fmt.Errorf("Interface not disabled.")
	}
	return nil
}

func (t *testInterfaceParam) macAddress(i *Interface, mac net.HardwareAddr) error {
	m := i.MACAddress()
	if m.String() != mac.String() {
		return fmt.Errorf("MAC Address doesn't match: %v != %v", m, mac)
	}
	if _, err := t.checkOp(OpMACAddress); err == nil {
		return fmt.Errorf("MACAddress() shouldn't be called")
	}
	return nil
}

func (t *testInterfaceParam) mtu(i *Interface, mtu MTU, good bool) error {
	oldmtu := i.MTU()
	if _, err := t.checkOp(OpMTU); err != nil {
		return fmt.Errorf("MTU() failed: %v", err)
	}
	if _, err := t.checkOp(OpInterfaceMode); err != nil {
		return fmt.Errorf("MTU() failed: %v", err)
	}

	err := i.SetMTU(mtu)
	if good && err != nil {
		return fmt.Errorf("SetMTU() to %d failed: %v", mtu, err)
	} else if !good && err == nil {
		return fmt.Errorf("SetMTU() to %d succeeded. Should fail: %v", mtu, err)
	}

	if _, err := t.checkOp(OpSetMTU); err != nil {
		return fmt.Errorf("SetMTU() to %d failed: %v", mtu, err)
	}

	newmtu := i.MTU()
	if _, err := t.checkOp(OpMTU); err != nil {
		return fmt.Errorf("MTU() failed: %v", err)
	}
	if _, err := t.checkOp(OpInterfaceMode); err != nil {
		return fmt.Errorf("MTU() failed: %v", err)
	}
	if good && newmtu != mtu || !good && newmtu == mtu && newmtu != oldmtu {
		return fmt.Errorf("SetMTU() failed. Set %d. Got %d.", mtu, newmtu)
	}

	return nil
}

func (t *testInterfaceParam) ifmode(i *Interface, mode VLANMode, good bool) error {
	// check if the mode may change
	currentMode := i.InterfaceMode()
	if _, err := t.checkOp(OpInterfaceMode); err != nil {
		return fmt.Errorf("InterfaceMode() failed: %v", err)
	}

	willCallSet := (currentMode != mode)

	err := i.SetInterfaceMode(mode)

	if _, err := t.checkOp(OpInterfaceMode); err != nil {
		return fmt.Errorf("SetInterfaceMode() to %v failed: %v", mode, err)
	}

	if willCallSet {
		op, err := t.checkOp(OpDeleteVID, OpSetInterfaceMode)
		if err != nil {
			return fmt.Errorf("SetInterfaceMode() to %v failed: %v", mode, err)
		}

		for op == OpDeleteVID {
			op, err = t.checkOp(OpDeleteVID, OpSetInterfaceMode)
			if err != nil {
				return fmt.Errorf("SetInterfaceMode() to %v failed: %v", mode, err)
			}
		}

		if op != OpSetInterfaceMode {
			return fmt.Errorf("SetInterfaceMode() to %v failed: %v", mode, err)
		}
	}

	if good && err != nil {
		return fmt.Errorf("SetInterfaceMode() to %v failed: %v", mode, err)
	} else if !good && err == nil {
		return fmt.Errorf("SetInterfaceMode() to %v succeeded. Should fail.", mode)
	}

	newmode := i.InterfaceMode()
	if _, err := t.checkOp(OpInterfaceMode); err != nil {
		return fmt.Errorf("InterfaceMode() failed: %v", err)
	}
	if good && newmode != mode || !good && newmode == mode {
		return fmt.Errorf("SetInterfaceMode() failed. Set %v. Got %v.", mode, newmode)
	}

	return nil
}

func (t *testInterfaceParam) addvid(i *Interface, vid VID, good bool) error {
	err := i.AddVID(vid)

	if _, err := t.checkOp(OpInterfaceMode); err != nil {
		return fmt.Errorf("AddVID(%d) failed: %v", vid, err)
	}

	if good {
		if err != nil {
			return fmt.Errorf("AddVID(%d) failed: %v", vid, err)
		}

		if _, err := t.checkOp(OpAddVID); err != nil {
			return fmt.Errorf("AddVID(%d) failed: %v", vid, err)
		}
	} else {
		if err == nil {
			return fmt.Errorf("AddVID(%d) succeeded. Should have failed.", vid)
		}
	}

	return nil
}

func (t *testInterfaceParam) delvid(i *Interface, vid VID, good bool) error {
	err := i.DeleteVID(vid)

	if good {
		if err != nil {
			return fmt.Errorf("DeleteVID(%d) failed: %v", vid, err)
		}

		if _, err := t.checkOp(OpDeleteVID); err != nil {
			return fmt.Errorf("DeleteVID(%d) failed: %v", vid, err)
		}
	} else {
		if err == nil {
			return fmt.Errorf("DeleteVID(%d) succeeded. Should have failed.", vid)
		}
	}

	return nil
}

func (t *testInterfaceParam) free(i *Interface) error {
	n := len(i.VIF())
	i.Free()
	for j := 0; j < n; j++ {
		if _, err := t.checkOp(OpVIFFree); err != nil {
			return fmt.Errorf("Free() failed: %v", err)
		}
	}
	if _, err := t.checkOp(OpFree); err != nil {
		return fmt.Errorf("Free() failed: %v", err)
	}
	return nil
}

func (t *testInterfaceParam) newvif(i *Interface, index uint32) (*VIF, error) {
	vif, err := i.NewVIF(index)
	if err != nil {
		return nil, fmt.Errorf("NewVIF() failed: %v", err)
	}
	if _, err := t.checkOp(OpNewVIF); err != nil {
		return nil, fmt.Errorf("NewVIF() failed: %v", err)
	}
	return vif, nil
}

func (t *testInterfaceParam) vifSetVRF(vif *VIF, vrf *VRF) error {
	if err := vif.setVRF(vrf); err != nil {
		return fmt.Errorf("setVRF(%v) failed: %v", vrf, err)
	}

	if _, err := t.checkOp(OpVIFSetVRF); err != nil {
		return fmt.Errorf("setVRF() failed: %v", err)
	}

	if vif.vrf != vrf {
		return fmt.Errorf("VRF doesn't match: %v != %v", vif.vrf, vrf)
	}

	return nil
}

func TestInterfaceBasic(t *testing.T) {
	p := &testInterfaceParam{
		mac: IF0_MAC,
		ch:  make(chan opcode, 10),
	}

	if0, err := p.newInterface(IFMODULE, IF0)
	if err != nil {
		t.Fatalf("NewInterface for %s failed: %v", IF0, err)
	}
	t.Logf("NewInterface succeeded.")

	// Enable
	if err := p.enable(if0); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("Enable() ok.")

	// Disable
	if err := p.disable(if0); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("Disable() ok.")

	// MACAddress
	if err := p.macAddress(if0, IF0_MAC); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("MACAddress() ok.")

	// SetMTU GOOD
	if err := p.mtu(if0, MTU_GOOD, true); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("SetMTU(%d) ok.", MTU_GOOD)

	// SetMTU BAD1
	if err := p.mtu(if0, MTU_BAD1, false); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("SetMTU(%d) ok failed.", MTU_BAD1)

	// SetMTU BAD2
	if err := p.mtu(if0, MTU_BAD2, false); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("SetMTU(%d) ok failed.", MTU_BAD2)

	// VID Test (ACCESS Mode)
	t.Logf("Starting VID Test - ACCESS Mode")
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

	if err := p.addvid(if0, 200, false); err != nil {
		t.Fatalf("%v", err)
	}
	if !reflect.DeepEqual(if0.VID(), []VID{100}) {
		t.Fatalf("VID not as expected: %v", if0.VID())
	}
	t.Logf("AddVIF(200) failed. ok: %v", if0.VID())

	if err := p.delvid(if0, 100, true); err != nil {
		t.Fatalf("%v", err)
	}
	if !reflect.DeepEqual(if0.VID(), []VID{}) {
		t.Fatalf("VID not as expected: %v", if0.VID())
	}
	t.Logf("DeleteVIF(100) ok: %v", if0.VID())

	if err := p.addvid(if0, 200, true); err != nil {
		t.Fatalf("%v", err)
	}
	if !reflect.DeepEqual(if0.VID(), []VID{200}) {
		t.Fatalf("VID not as expected: %v", if0.VID())
	}
	t.Logf("AddVIF(200) ok: %v", if0.VID())

	if err := p.delvid(if0, 200, true); err != nil {
		t.Fatalf("%v", err)
	}
	if !reflect.DeepEqual(if0.VID(), []VID{}) {
		t.Fatalf("VID not as expected: %v", if0.VID())
	}
	t.Logf("DeleteVIF(200) ok: %v", if0.VID())

	// VID Test (TRUNK Mode)
	t.Logf("Starting VID Test - TRUNK Mode")
	if err := p.ifmode(if0, TrunkMode, true); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("SetInterfaceMode(%v) ok.", TrunkMode)

	vids := []VID{100, 200, 300, 400}
	newvids := []VID{}
	for _, vid := range vids {
		if err := p.addvid(if0, vid, true); err != nil {
			t.Fatalf("%v", err)
		}
		newvids = append(newvids, vid)
		ivids := if0.VID()
		sort.Sort(VIDS(ivids))
		if !reflect.DeepEqual(ivids, newvids) {
			t.Fatalf("VID not as expected: %v", if0.VID())
		}
		t.Logf("AddVIF(%d) ok: %v", vid, if0.VID())
	}

	t.Logf("Try chainging to ACCESS Mode")
	if err := p.ifmode(if0, AccessMode, true); err != nil {
		p.free(if0)
		t.Fatalf("SetInterfaceMode(%v) should succeed: %v", AccessMode, err)
	}
	ivids := if0.VID()
	if len(ivids) != 0 {
		p.free(if0)
		t.Fatalf("VID should have been cleared after changing to ACCESS mode: %v", ivids)
	}
	t.Logf("SetInterfaceMode(%v) ok.", AccessMode)

	/// Free
	if err := p.free(if0); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("Free() ok.")
}

func TestInterfaceAutoMAC(t *testing.T) {
	if err := RegisterModule(IFMODULE, newTestInterface, nil, TypeInterface); err != nil {
		t.Logf("Module already registered: %v", err)
	}

	t.Logf("TestInterface module registered.")
	p := &testInterfaceParam{
		mac: nil,
		ch:  make(chan opcode, 4),
	}

	if1, err := p.newInterface(IFMODULE, "if1")
	if err != nil {
		t.Fatalf("NewInterface for if1 failed: %v", err)
	}
	t.Logf("NewInterface succeeded.")

	// check if SetMACAddress has been called
	if _, err := p.checkOp(OpSetMACAddress); err != nil {
		t.Fatalf("SetMACAddress wasn't get called: %v", err)
	}

	// check the generated VIF
	t.Logf("Got MAC %v", if1.MACAddress())
	if !bytes.HasPrefix(if1.MACAddress(), macMgr.prefix) {
		t.Logf("Generated MAC Address doesn't match: Expected prefix=%#v", macMgr.prefix)
	}
	t.Logf("Generated MAC Address looks good.")

	if err := p.free(if1); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("Free() ok.")
}

func init() {
	if err := RegisterModule(IFMODULE, newTestInterface, nil, TypeInterface); err != nil {
		panic(err)
	}
}
