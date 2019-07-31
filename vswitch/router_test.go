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

import (
	"testing"
)

type dummyRouter struct {
	base *BaseInstance
	ch   chan opcode
	vif  map[string]*VIF
}

func (d *dummyRouter) AddVIF(vif *VIF) error {
	d.vif[vif.Name()] = vif
	d.ch <- OpAddVIF
	return nil
}

func (d *dummyRouter) DeleteVIF(vif *VIF) error {
	delete(d.vif, vif.Name())
	d.ch <- OpDeleteVIF
	return nil
}

func (d *dummyRouter) Enable() error {
	d.ch <- OpEnable
	return nil
}

func (d *dummyRouter) Disable() {
	d.ch <- OpDisable
}

func (d *dummyRouter) AddOutputDevice(dev OutputDevice) error {
	return nil
}

func (d *dummyRouter) DeleteOutputDevice(dev OutputDevice) error {
	return nil
}

func (d *dummyRouter) EnableNAPT(vif *VIF) error {
	return nil
}

func (d *dummyRouter) DisableNAPT(vif *VIF) error {
	return nil
}

func (d *dummyRouter) Free() {
	d.ch <- OpFree
}

func (d *dummyRouter) channel() chan opcode {
	return d.ch
}

func (d *dummyRouter) vifs() []*VIF {
	vifs := make([]*VIF, len(d.vif))
	n := 0
	for _, vif := range d.vif {
		vifs[n] = vif
		n++
	}
	return vifs
}

func newDummyRouter(base *BaseInstance, priv interface{}) (Instance, error) {
	return &dummyRouter{
		base: base,
		ch:   make(chan opcode, 10),
		vif:  make(map[string]*VIF),
	}, nil
}

const (
	DUMMYROUTER = "dummyRouter"
	ROUTER0     = "router-0"
	VIF0        = 0
)

func TestRouter(t *testing.T) {
	if routerModuleName != DUMMYROUTER {
		t.Fatalf("routerModuleName != %v. %v is set.", DUMMYROUTER, routerModuleName)
	}

	r0, err := newRouter(nil, ROUTER0)
	if err != nil {
		t.Fatalf("newRouter failed: %v", err)
	}

	dr, ok := r0.instance.(*dummyRouter)
	if !ok {
		t.Fatalf("not dummyRouter")
	}
	ch := dr.channel()

	r0.enable()
	if err := OpEnable.Expect(ch); err != nil {
		t.Fatalf("enable failed: %v", err)
	}
	t.Logf("Enabling router - ok")

	r0.disable()
	if err := OpDisable.Expect(ch); err != nil {
		t.Fatalf("disable failed: %v", err)
	}
	t.Logf("Disabling router - ok")

	// Create dummy VIF
	p := &testInterfaceParam{ch: make(chan opcode, 10)}
	if0, err := p.newInterface(IFMODULE, IF0)
	if err != nil {
		t.Fatalf("newInterface failed: %v", err)
	}
	vif, err := if0.NewVIF(VIF0)
	if err != nil {
		t.Fatalf("NewVIF failed: %v", err)
	}

	if err := r0.addVIF(vif); err != nil {
		t.Fatalf("addVIF failed: %v", err)
	}
	if err := OpAddVIF.Expect(ch); err != nil {
		t.Fatalf("addVIF failed; %v", err)
	}
	found := false
	vifs := dr.vifs()
	for _, v := range vifs {
		if v.Name() == vif.Name() {
			found = true
		}
	}
	if found {
		t.Logf("Found added VIF - ok: %v", vifs)
	} else {
		t.Fatalf("VIF not added: %v", vifs)
	}

	r0.deleteVIF(vif)
	if err := OpDeleteVIF.Expect(ch); err != nil {
		t.Fatalf("deleteVIF failed; %v", err)
	}
	found = false
	vifs = dr.vifs()
	for _, v := range vifs {
		if v.Name() == vif.Name() {
			found = true
		}
	}
	if !found {
		t.Logf("Delete VIF - ok: %v", vifs)
	} else {
		t.Fatalf("VIF not deleted: %v", vifs)
	}

	if0.Free()
}

func init() {
	if err := RegisterModule(DUMMYROUTER, newDummyRouter, nil, TypeRouter); err != nil {
		panic(err)
	}
}
