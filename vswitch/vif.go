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
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/notifier"
)

type VIFInstance interface {
	SetVRF(*VRF)
	Instance
}

type VID uint16

type VIF struct {
	index      VIFIndex
	name       string
	enabled    bool
	vid        VID
	instance   VIFInstance
	iface      *Interface
	output     *dpdk.Ring
	vrf        *VRF
	vsi        *VSI
	tap        *os.File
	base       *BaseInstance
	tunnel     *L3Tunnel
	counter    *Counter
	napt       *NAPT
	mutex      sync.Mutex
	lastChange time.Time
	*IPAddrs
	*Neighbours
}

type vifManager struct {
	vifs    map[string]*VIF
	indices map[VIFIndex]*VIF
	mutex   sync.Mutex
}

var vifMgr = &vifManager{
	vifs:    make(map[string]*VIF),
	indices: make(map[VIFIndex]*VIF),
}

func newVIF(i *Interface, name string) (*VIF, error) {
	vifMgr.mutex.Lock()
	defer vifMgr.mutex.Unlock()

	if _, exists := vifMgr.vifs[name]; exists {
		return nil, fmt.Errorf("VIF %s already exists.", name)
	}

	// Allocate VIFIndex from VIFIndexManager
	v := &VIF{}
	index, err := vifIdxMgr.allocVIFIndex(v)
	if err != nil {
		return nil, err
	}

	v.index = index
	v.name = name
	v.iface = i
	v.counter = NewCounter()
	v.lastChange = time.Now()
	v.IPAddrs = newIPAddrs(v)
	v.Neighbours = newNeighbours(v)
	v.base = newSubInstance(i.base, v.name)

	vifMgr.vifs[name] = v
	vifMgr.indices[v.index] = v

	return v, nil
}

func (v *VIF) setVIFInstance(vi VIFInstance) error {
	if v.instance != nil {
		return errors.New("VIFInstance already associated.")
	}
	v.instance = vi
	if v.tunnel != nil {
		if tn, ok := vi.(L3TunnelNotify); ok {
			v.tunnel.setNotify(tn)
		} else {
			logger.Warning("%v is L3 Tunnel. But doesn't support L3TunnelNotify.", v)
		}
	}
	return nil
}

// Free destroys VIF from the interface.
// If the VIF is associated VRF, the VIF is automatically
// deleted from the VRF.
func (v *VIF) Free() {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if v.vrf != nil {
		v.vrf.DeleteVIF(v)
		v.vrf = nil
	}
	if v.vsi != nil {
		v.vsi.DeleteVIF(v)
		v.vsi = nil
	}

	v.iface.deleteVIF(v)
	if v.instance != nil {
		v.instance.Free()
	}

	vifMgr.mutex.Lock()
	defer vifMgr.mutex.Unlock()

	delete(vifMgr.vifs, v.name)
	delete(vifMgr.indices, v.index)

	if err := vifIdxMgr.freeVIFIndex(v.index); err != nil {
		logger.Err("Freeing VIFIndex for %v failed: %v", v.name, err)
	}

	// Notify
	noti.Notify(notifier.Delete, v, nil)
}

func (v *VIF) baseInstance() *BaseInstance {
	return v.base
}

// Name returns name of the VIF.
func (v *VIF) Name() string {
	return v.name
}

func (v *VIF) String() string {
	return v.name
}

// Index returns the VIF index of the given VIF.
func (v *VIF) Index() VIFIndex {
	return v.index
}

// VIFIndex returns the VIF index of the given VIF.
func (v *VIF) VIFIndex() VIFIndex {
	return v.index
}

func (v *VIF) LastChange() time.Time {
	return v.lastChange
}

// IsEnabled returns true if the VIF is enabled.
// Returns false otherwise.
func (v *VIF) IsEnabled() bool {
	return v.enabled
}

func (v *VIF) enable() error {
	if v.output != nil {
		if v.tunnel != nil {
			if v.tunnel.VRF() == nil {
				v.tunnel.SetVRF(v.vrf)
			}

			// Connect L3 Tunnel to the specified VRF
			if err := v.tunnel.VRF().addL3Tunnel(v); err != nil {
				return fmt.Errorf("Can't connect L3 tunnel to VRF: %v", err)
			}
		}

		if err := v.instance.Enable(); err != nil {
			if v.tunnel != nil {
				v.tunnel.VRF().deleteL3Tunnel(v)
			}
			return err
		}

		noti.Notify(notifier.Update, v, true)
	}
	return nil
}

func (v *VIF) disable() {
	v.instance.Disable()
	noti.Notify(notifier.Update, v, false)
}

func (v *VIF) connect(dst *dpdk.Ring, match VswMatch, param interface{}) error {
	return v.base.connect(dst, match, param)
}

func (v *VIF) disconnect(match VswMatch, param interface{}) error {
	return v.base.disconnect(match, param)
}

// Enable enables the VIF.
func (v *VIF) Enable() error {
	if !v.enabled {
		if err := v.enable(); err != nil {
			return err
		}
		v.enabled = true
		v.lastChange = time.Now()
	}
	return nil
}

// Disable disables the VIF.
func (v *VIF) Disable() {
	if v.enabled {
		if v.output != nil {
			v.disable()
		}
		v.enabled = false
		v.lastChange = time.Now()
	}
}

// Input returns an input ring for the VIF
// which is the input ring for the underlying interface.
func (v *VIF) Input() *dpdk.Ring {
	return v.base.Input()
}

// Outbound returns an input ring for outbounds packets, i.e. Lagopus to external.
// Returned ring is same as the one returned by Input.
func (v *VIF) Outbound() *dpdk.Ring {
	return v.base.Outbound()
}

// Inbound returns an input ring for inbounds packets, i.e. external to Lagopus.
// If the underlying interface supports secondary input, then secondary input ring is returned.
// Otherwise, the ring same as Outbound is returned.
func (v *VIF) Inbound() *dpdk.Ring {
	return v.base.Inbound()
}

// Output returns an output ring for the VIF
// This ring is same as the one set in MatchAny rule.
// If the VIF is not added to VRF or VSI, then it returns nil.
func (v *VIF) Output() *dpdk.Ring {
	return v.output
}

// Rules returns rules associated with the VIF.
func (v *VIF) Rules() *Rules {
	return v.base.rules
}

func (v *VIF) setOutput(output *dpdk.Ring) error {
	if v.output != nil && output != nil {
		return errors.New("VIF is already associated.")
	}

	if output != nil {
		if err := v.base.rules.add(MatchAny, nil, output); err != nil {
			return err
		}
	} else {
		v.base.rules.remove(MatchAny, nil)
	}

	v.output = output

	if v.enabled {
		if output == nil {
			v.disable()
		} else {
			if err := v.enable(); err != nil {
				v.output = nil
				return err
			}
		}
	}
	return nil
}

// MACAddress returns MAC address of the interface
func (v *VIF) MACAddress() net.HardwareAddr {
	return v.iface.MACAddress()
}

// MTU returns MTU of the interface
func (v *VIF) MTU() MTU {
	return v.iface.MTU()
}

// VID returns VLAN Tag of the VIF
func (v *VIF) VID() VID {
	return v.vid
}

// SetVID sets VLAN Tag of the VIF
func (v *VIF) SetVID(vid VID) error {
	if v.vid == vid {
		return nil
	}

	if v.enabled {
		return errors.New("Can't change VID when VIF is enabled.")
	}

	if v.output != nil {
		return errors.New("Can't change VID while VIF is connected.")
	}

	if v.vid != 0 && !v.iface.freeVID(v.vid, v) {
		return fmt.Errorf("Can't dissociate from VID %d", v.vid)
	}

	if vid != 0 && !v.iface.reserveVID(vid, v) {
		return fmt.Errorf("Can't associate with VID %d", vid)
	}

	v.vid = vid
	v.lastChange = time.Now()
	return nil
}

// Dump returns descriptive information about the VIF
func (v *VIF) Dump() string {
	str := fmt.Sprintf("%v: Index=%d: VID=%v", v.name, v.index, v.vid)

	if v.IPAddrs != nil {
		ips := v.ListIPAddrs()
		str += fmt.Sprintf(", %d IP Address(es):", len(ips))
		for _, ip := range ips {
			str += fmt.Sprintf(" %s", ip)
		}
	}

	if v.tunnel != nil {
		str += fmt.Sprintf(" %v", v.tunnel)
	}

	return str
}

// Called when VIF is connected to or disconnected from VSI.
func (v *VIF) setVSI(vsi *VSI) error {
	if v.vsi != nil && vsi != nil {
		return fmt.Errorf("%v is already associated with %v", v, vsi)
	}
	v.vsi = vsi
	return nil
}

// Called when VIF is connected to or disconnected from VRF.
func (v *VIF) setVRF(vrf *VRF) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if v.vrf != nil && vrf != nil {
		return fmt.Errorf("%v is already associated with %v", v, vrf)
	}

	v.vrf = vrf
	v.instance.SetVRF(vrf)

	return nil
}

// VRF returns VRF associated with the VIF.
// Returns nil if the VIF is not associated with any VRF.
func (v *VIF) VRF() *VRF {
	return v.vrf
}

// SetTAP associate tap with the VIF.
// Returns error if the VIF already has an associted TAP.
func (v *VIF) SetTAP(tap *os.File) error {
	if tap != nil && v.tap != nil {
		return errors.New("TAP already set.")
	}
	v.tap = tap
	return nil
}

// Tunnel returns IPsec Tunnel information associated with
// the VIF. Return nil, if there's none.
func (v *VIF) Tunnel() *L3Tunnel {
	return v.tunnel
}

// setTunnel shall be called before VIFInstance is instantiated.
// Tunnel module requires this detail to instantiate actual backends.
func (v *VIF) setTunnel(t *L3Tunnel) {
	v.tunnel = t
}

// TAP returns tap associated with the VIF.
func (v *VIF) TAP() *os.File {
	return v.tap
}

func (v *VIF) MarshalJSON() ([]byte, error) {
	return []byte(`"` + v.name + `"`), nil
}

func (v *VIF) Counter() *Counter {
	if v.instance != nil {
		if cu, ok := v.instance.(CounterUpdater); ok {
			cu.UpdateCounter()
		}
	}
	return v.counter
}

func (v *VIF) LinkStatus() (bool, error) {
	return v.iface.LinkStatus()
}

// NAPT returns NAPT configuration.
// Returns nil, if not readied with PrepareNAPT.
func (v *VIF) NAPT() *NAPT {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	return v.napt
}

// PrepareNAPT readies NAPT on this VIF.
// Returns error if NAP is already prepared.
// Otherwise, returns *NAPT.
func (v *VIF) PrepareNAPT() (*NAPT, error) {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if v.napt != nil {
		return nil, errors.New("NAPT is ready")
	}

	v.napt = newNAPT(v)
	return v.napt, nil
}

// Called from NAPT
func (v *VIF) enableNAPT() error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if v.napt == nil {
		return errors.New("NAPT not configured.")
	}

	if v.vrf == nil {
		return nil
	}
	return v.vrf.enableNAPT(v)
}

// Called from NAPT
func (v *VIF) disableNAPT() error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if v.napt == nil {
		return errors.New("NAPT not configured.")
	}

	if v.vrf == nil {
		return nil
	}

	return v.vrf.disableNAPT(v)
}

func (v *VIF) isNAPTEnabled() bool {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	return v.napt != nil && v.napt.IsEnabled()
}

func (v *VIF) Interface() *Interface {
	return v.iface
}

// VIFs returns a slice of all registered VIF.
func VIFs() []*VIF {
	vifMgr.mutex.Lock()
	defer vifMgr.mutex.Unlock()

	var vifs []*VIF
	for _, v := range vifMgr.vifs {
		vifs = append(vifs, v)
	}
	return vifs
}

// GetVIFByIndex returns VIF matches to index
func GetVIFByIndex(index VIFIndex) *VIF {
	vifMgr.mutex.Lock()
	defer vifMgr.mutex.Unlock()

	return vifMgr.indices[index]
}

// GetVIFByName returns VIF matches to name
func GetVIFByName(name string) *VIF {
	vifMgr.mutex.Lock()
	defer vifMgr.mutex.Unlock()

	return vifMgr.vifs[name]
}
