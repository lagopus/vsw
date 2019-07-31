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
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

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

type CounterUpdater interface {
	// UpdateCounter updates Counter value.
	UpdateCounter()
}

type LinkStatuser interface {
	// LinkStatus returns the status of link.
	// Returns true on UP, and false on DOWN.
	LinkStatus() bool
}

type Interface struct {
	name       string
	driver     string
	private    interface{}
	vids       map[VID]*VIF
	vifs       []*VIF
	base       *BaseInstance
	mac        macAddress
	instance   InterfaceInstance
	tunnel     *L2Tunnel
	lastChange time.Time
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

func (v VLANMode) MarshalJSON() ([]byte, error) {
	if v == AccessMode {
		return []byte(`"access"`), nil
	}
	return []byte(`"trunk"`), nil
}

type ifManager struct {
	mutex sync.Mutex
	ifs   map[string]*Interface
}

var ifMgr = &ifManager{ifs: make(map[string]*Interface)}

func NewInterface(driver, name string, priv interface{}) (*Interface, error) {
	ifMgr.mutex.Lock()
	defer ifMgr.mutex.Unlock()

	if _, exists := ifMgr.ifs[name]; exists {
		return nil, fmt.Errorf("Interface %v already exists", name)
	}

	// Check tunnel config first
	tunnel, ok := priv.(*L2Tunnel)
	if ok && tunnel.VRF() == nil {
		return nil, fmt.Errorf("L2 tunnel %v is not associated with VRF", name)
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
		name:       name,
		driver:     driver,
		private:    priv,
		vids:       make(map[VID]*VIF),
		base:       base,
		mac:        macAddress(instance.MACAddress()),
		instance:   instance,
		lastChange: time.Now(),
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

	ifMgr.ifs[name] = iface

	// Checks for L2 Tunnel
	if tunnel != nil {
		iface.tunnel = tunnel

		if tn, ok := base.instance.(L2TunnelNotify); ok {
			tunnel.setNotify(tn)
		} else {
			logger.Warning("%s should be L2 Tunnel. But doesn't support L2TunnelNotify.", name)
		}

		if err := tunnel.VRF().addL2Tunnel(iface); err != nil {
			iface.mac.free()
			base.free()
			return nil, fmt.Errorf("Can't connect L2 tunnel to VRF: %v", err)
		}
	}

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
	ifMgr.mutex.Lock()
	defer ifMgr.mutex.Unlock()

	i.freeAllVIF()
	i.base.free()
	i.mac.free()
	delete(ifMgr.ifs, i.name)
}

func (i *Interface) Driver() string {
	return i.driver
}

func (i *Interface) Private() interface{} {
	return i.private
}

func (i *Interface) LastChange() time.Time {
	return i.lastChange
}

func (i *Interface) IsEnabled() bool {
	return i.base.isEnabled()
}

func (i *Interface) Enable() error {
	i.lastChange = time.Now()
	return i.base.enable()
}

func (i *Interface) Disable() {
	i.lastChange = time.Now()
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

// NewTunnel creates VIF for L3 Tunnel wight the given index.
// L3Tunnel shall not be nil.
func (i *Interface) NewTunnel(index uint32, tunnel *L3Tunnel) (*VIF, error) {
	// L2 Tunnel and L3 Tunnel doesn't coexist
	if i.tunnel != nil {
		return nil, errors.New("Interface is set up for L2 Tunnel")
	}

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
	return append([]*VIF(nil), i.vifs...)
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
	i.lastChange = time.Now()
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
		if v.vsi != nil {
			if err := v.vsi.UpdateMTU(v); err != nil {
				logger.Err("Failed to update MTU.(vif: %v, mtu: %v)", v, mtu)
			}
		}
		noti.Notify(notifier.Update, v, mtu)
	}
	i.lastChange = time.Now()
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
			// FIXME: We can't do anything here
			return err
		}
		delete(i.vids, vid)
	}

	i.lastChange = time.Now()
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
	i.lastChange = time.Now()
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
	i.lastChange = time.Now()
	return nil

}

func (i *Interface) SetNativeVID(vid VID) error {
	if i.instance.InterfaceMode() != TrunkMode {
		return errors.New("Interface mode is not TRUNK")
	}
	i.lastChange = time.Now()
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

func (i *Interface) Tunnel() *L2Tunnel {
	return i.tunnel
}

// Inbound returns an input ring for inbounds packets, i.e. external to Lagopus.
// If the underlying interface supports secondary input, then secondary input ring is returned.
// Otherwise, the ring same as Outbound is returned.
func (i *Interface) Inbound() *dpdk.Ring {
	return i.base.Inbound()
}

func (i *Interface) connect(dst *dpdk.Ring, match VswMatch, param interface{}) error {
	return i.base.connect(dst, match, param)
}

func (i *Interface) disconnect(match VswMatch, param interface{}) error {
	return i.base.disconnect(match, param)
}

func (i *Interface) String() string {
	return i.name
}

func (i *Interface) Counter() *Counter {
	if cu, ok := i.instance.(CounterUpdater); ok {
		cu.UpdateCounter()
	}
	return i.base.Counter()
}

func (i *Interface) LinkStatus() (bool, error) {
	if ls, ok := i.instance.(LinkStatuser); ok {
		return ls.LinkStatus(), nil
	}
	return false, errors.New("Link status unknown")
}

// Interfaces returns a slice of all registered Interface.
func Interfaces() []*Interface {
	ifMgr.mutex.Lock()
	defer ifMgr.mutex.Unlock()

	var ifs []*Interface
	for _, i := range ifMgr.ifs {
		ifs = append(ifs, i)
	}
	return ifs
}

// GetInterface returns an Interface with the given name.
// Returns nil if no interface is found with the name.
func GetInterface(name string) *Interface {
	ifMgr.mutex.Lock()
	defer ifMgr.mutex.Unlock()

	return ifMgr.ifs[name]
}
