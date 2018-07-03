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
	"errors"
	"fmt"

	"github.com/lagopus/vsw/dpdk"
)

type BridgeInstance interface {
	AddVIF(*VIF, MTU) error
	DeleteVIF(*VIF, MTU) error
	SetMACAgingTime(int)
	SetMaxEntries(int)
	EnableMACLearning()
	DisableMACLearning()
	SetMAT(*dpdk.Ring) error
}

type bridge struct {
	vid      VID
	vifs     map[*VIF]struct{}
	instance BridgeInstance
	base     *BaseInstance
	mtu      MTU
}

func newBridge(name string, vid VID, mat *BaseInstance) (*bridge, error) {
	if bridgeModuleName == "" {
		return nil, errors.New("Can't find bridge module")
	}

	base, err := newInstance(bridgeModuleName, name, nil)
	if err != nil {
		return nil, err
	}

	instance, ok := base.instance.(BridgeInstance)
	if !ok {
		return nil, fmt.Errorf("Not bridge module: %s", bridgeModuleName)
	}

	b := &bridge{
		vid:      vid,
		vifs:     make(map[*VIF]struct{}),
		instance: instance,
		base:     base,
		mtu:      InvalidMTU,
	}

	if mat != nil {
		// XXX: We need to consider using MATCH_ANY
		if err := instance.SetMAT(mat.input); err != nil {
			return nil, err
		}

		if err := mat.connect(b.base.input, MATCH_VLAN_ID, vid); err != nil {
			return nil, err
		}
	}

	return b, nil
}

func (b *bridge) baseInstance() *BaseInstance {
	return b.base
}

func (b *bridge) free() {
	b.base.free()
}

func (b *bridge) addVIF(vif *VIF) error {
	if b.vid != vif.vid {
		return fmt.Errorf("VID doesn't match (bridge VID=%v, VIF VID=%v)", b.vid, vif.vid)
	}

	// We've already registered the VIF
	if _, exists := b.vifs[vif]; exists {
		return nil
	}

	// Check if MTU needs to be updated
	mtu := vif.MTU()
	if b.mtu < mtu {
		mtu = b.mtu
	}

	if err := b.instance.AddVIF(vif, mtu); err != nil {
		return err
	}

	b.mtu = mtu
	b.vifs[vif] = struct{}{}

	// Connect VIF to bridge
	// XXX: We should use BaseInstance.connect()
	vif.setOutput(b.base.input)

	return nil
}

func (b *bridge) deleteVIF(vif *VIF) error {
	if _, exists := b.vifs[vif]; !exists {
		return fmt.Errorf("No such VIF: %v", vif.Name())
	}

	// Check if MTU may need to be updated
	mtu := InvalidMTU
	for v := range b.vifs {
		if v == vif {
			continue
		}
		if m := vif.MTU(); mtu > m {
			mtu = m
		}
	}

	if err := b.instance.DeleteVIF(vif, mtu); err != nil {
		return err
	}

	b.mtu = mtu
	delete(b.vifs, vif)

	// Disconnect VIF first
	// XXX: We should use BaseInstance.disconnect()
	vif.setOutput(nil)

	return nil
}

func (b *bridge) vif() []*VIF {
	vifs := make([]*VIF, len(b.vifs))
	n := 0
	for vif, _ := range b.vifs {
		vifs[n] = vif
		n++
	}
	return vifs
}

func (b *bridge) enable() error {
	return b.base.enable()
}

func (b *bridge) disable() {
	b.base.disable()
}

func (b *bridge) setMACAgingTime(time int) {
	b.instance.SetMACAgingTime(time)
}

func (b *bridge) setMaxEntries(max int) {
	b.instance.SetMaxEntries(max)
}

func (b *bridge) enableMACLearning() {
	b.instance.EnableMACLearning()
}

func (b *bridge) disableMACLearning() {
	b.instance.DisableMACLearning()
}
