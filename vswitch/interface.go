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

package vswitch

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/notifier"
)

type InterfaceInstance interface {
	// NewVIF creates and returns the new VIF
	NewVIF(*VIF) (VIFInstance, error)

	// MACAddress returns the MAC address of the interface
	// If the interface doesn't have MAC address, the method
	// shall simple return nil. This will let the core to
	// generate a unique MAC address.
	MACAddress() net.HardwareAddr

	// SetMACAddress sets the MAC address of the interface.
	SetMACAddress(net.HardwareAddr) error

	// MTU returns the current MTU.
	MTU() MTU

	// SetMTU sets the MTU.
	SetMTU(mtu MTU) error

	// InterfaceMode returns the current interface mode.
	InterfaceMode() VLANMode

	// SetIntefaceMode changes the current interface mode.
	// All VIFs are deleted before the mode changes by the core.
	SetInterfaceMode(VLANMode) error

	// AddVID adds a VID.
	// In ACCESS mode, only one VID can be registered.
	AddVID(vid VID) error

	// DeleteVID deletes a VID.
	DeleteVID(vid VID) error

	// SetNormalVID sets a VID for Native VLAN.
	// To disble Native VLAN pass 0 as the VID.
	// Returns error when the interface is set to ACCESS mode.
	SetNativeVID(vid VID) error
}

type Interface struct {
	name     string
	vids     map[VID]*VIF
	vifs     []*VIF
	base     *BaseInstance
	mac      macAddress
	instance InterfaceInstance
}

type VLANMode int

const (
	AccessMode VLANMode = iota
	TrunkMode
)

func (v VLANMode) String() string {
	if v == AccessMode {
		return "ACCESS"
	}
	return "TRUNK"
}

var interfaceMutex sync.Mutex
var interfaces = make(map[string]*Interface)

func NewInterface(driver, name string, priv interface{}) (*Interface, error) {
	interfaceMutex.Lock()
	defer interfaceMutex.Unlock()

	if _, exists := interfaces[name]; exists {
		return nil, fmt.Errorf("Interface %v already exists", name)
	}

	base, err := newInstance(driver, name, priv)
	if err != nil {
		return nil, err
	}

	// Double check
	instance, ok := base.instance.(InterfaceInstance)
	if !ok {
		return nil, fmt.Errorf("%s doesn't conform to Interface type.", driver)
	}

	iface := &Interface{
		name:     name,
		vids:     make(map[VID]*VIF),
		base:     base,
		mac:      macAddress(instance.MACAddress()),
		instance: instance,
	}

	if iface.mac == nil {
		if mac, err := newMACAddress(); err == nil {
			iface.mac = mac
			if err := instance.SetMACAddress(net.HardwareAddr(mac)); err != nil {
				base.free()
				mac.free()
				return nil, fmt.Errorf("Can't set MAC: %v", err)
			}
		} else {
			base.free()
			return nil, fmt.Errorf("Can't generate MAC: %v", err)
		}
	}

	interfaces[name] = iface

	return iface, nil
}

// Instance returns the instance of the module behind this Interface.
// If the instance supports any private methods, you may be able to accesss
// them via the obtained instance.
func (i *Interface) Instance() interface{} {
	return i.base.instance
}

func (i *Interface) freeAllVIF() {
	v := make([]*VIF, len(i.vifs))
	copy(v, i.vifs)
	for _, vif := range v {
		vif.Free()
	}
}

func (i *Interface) Free() {
	interfaceMutex.Lock()
	defer interfaceMutex.Unlock()

	i.freeAllVIF()
	i.base.free()
	i.mac.free()
	delete(interfaces, i.name)
}

func (i *Interface) IsEnabled() bool {
	return i.base.isEnabled()
}

func (i *Interface) Enable() error {
	return i.base.enable()
}

func (i *Interface) Disable() {
	i.base.disable()
}

func (i *Interface) input() *dpdk.Ring {
	return i.base.input
}

func (i *Interface) initVIF(vif *VIF) error {
	vi, err := i.instance.NewVIF(vif)
	if err != nil {
		return err
	}

	if err = vif.setVIFInstance(vi); err != nil {
		return err
	}

	i.vifs = append(i.vifs, vif)

	return nil
}

// NewVIF creates VIF with the given index.
// Actual name of the VIF becomes "interface name" + "-" + index.
// For instance, if the interface name is "if0" and the index is 1, the
// name of the VIF becomes "if0-1".
// If the generated name already exists, the call fails.
// Returns VIF instance, or error otherwise.
func (i *Interface) NewVIF(index uint32) (*VIF, error) {
	vif, err := newVIF(i, fmt.Sprintf("%s-%d", i.name, index))
	if err != nil {
		return nil, err
	}

	if err := i.initVIF(vif); err != nil {
		vif.Free()
		return nil, err
	}

	return vif, nil
}

// NewTunnel creates VIF for IP Tunnel wight the given index.
// Tunnel shall not be nil.
func (i *Interface) NewTunnel(index uint32, tunnel *Tunnel) (*VIF, error) {
	if tunnel == nil {
		return nil, errors.New("Tunnel details is not given")
	}

	vif, err := newVIF(i, fmt.Sprintf("%s-%d", i.name, index))
	if err != nil {
		return nil, err
	}

	vif.setTunnel(tunnel)
	if err := i.initVIF(vif); err != nil {
		vif.Free()
		return nil, err
	}

	return vif, nil
}

func (i *Interface) deleteVIF(vif *VIF) {
	for n, v := range i.vifs {
		if v == vif {
			l := len(i.vifs) - 1
			i.vifs[n] = i.vifs[l]
			i.vifs[l] = nil
			i.vifs = i.vifs[:l]
			return
		}
	}
}
func (i *Interface) VIF() []*VIF {
	v := make([]*VIF, len(i.vifs))
	copy(v, i.vifs)
	return v
}

func (i *Interface) SetMACAddress(mac net.HardwareAddr) error {
	if mac == nil {
		return errors.New("Mac address not specified.")
	}

	if err := i.instance.SetMACAddress(mac); err != nil {
		return err
	}
	i.mac.free()
	i.mac = macAddress(mac)
	for _, v := range i.vifs {
		noti.Notify(notifier.Update, v, mac)
	}
	return nil
}

func (i *Interface) MACAddress() net.HardwareAddr {
	return net.HardwareAddr(i.mac)
}

func (i *Interface) MTU() MTU {
	mtu := i.instance.MTU()
	if i.instance.InterfaceMode() == TrunkMode {
		mtu -= 4
	}
	return mtu
}

func (i *Interface) SetMTU(mtu MTU) error {
	if err := i.instance.SetMTU(mtu); err != nil {
		return err
	}
	for _, v := range i.vifs {
		noti.Notify(notifier.Update, v, mtu)
	}
	return nil
}

func (i *Interface) InterfaceMode() VLANMode {
	return i.instance.InterfaceMode()
}

// SetInterfaceMode sets an interface mode to either AccessMode
// or TrunkMode. When the interface mode changes from other mode
// all VIFs are removed automatically, thus VIF shall be created
// once again after the mode is changed.
// This will also clears all VIDs assigned to the interface.
// Returns error if anything fails.
func (i *Interface) SetInterfaceMode(mode VLANMode) error {
	if mode == i.instance.InterfaceMode() {
		return nil
	}
	i.freeAllVIF()
	for vid := range i.vids {
		if err := i.instance.DeleteVID(vid); err != nil {
			return err
		}
		delete(i.vids, vid)
	}
	return i.instance.SetInterfaceMode(mode)
}

func (i *Interface) VID() []VID {
	v := make([]VID, len(i.vids))
	n := 0
	for vid := range i.vids {
		v[n] = vid
		n++
	}
	return v
}

func (i *Interface) AddVID(vid VID) error {
	if i.instance.InterfaceMode() == AccessMode && len(i.vids) > 0 {
		return errors.New("Can't add more than one VID on Access Mode.")
	}
	if err := i.instance.AddVID(vid); err != nil {
		return err
	}
	i.vids[vid] = nil
	return nil
}

func (i *Interface) DeleteVID(vid VID) error {
	if vif, exists := i.vids[vid]; !exists {
		return fmt.Errorf("No such VID: %d", vid)
	} else if vif != nil {
		return fmt.Errorf("Can't delete VID associated with VIF.")
	}
	if err := i.instance.DeleteVID(vid); err != nil {
		return err
	}
	delete(i.vids, vid)
	return nil

}

func (i *Interface) SetNativeVID(vid VID) error {
	if i.instance.InterfaceMode() != TrunkMode {
		return errors.New("Interface mode is not TRUNK")
	}
	return i.instance.SetNativeVID(vid)
}

func (i *Interface) reserveVID(vid VID, vif *VIF) bool {
	if v, ok := i.vids[vid]; !ok || v != nil {
		return false
	}

	i.vids[vid] = vif
	return true
}

func (i *Interface) freeVID(vid VID, vif *VIF) bool {
	if v, ok := i.vids[vid]; !ok || v != vif {
		return false
	}

	i.vids[vid] = nil
	return true
}
