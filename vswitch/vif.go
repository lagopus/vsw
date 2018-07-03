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
	"net"
	"os"
	"sync"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/notifier"
)

type VIFInstance interface {
	SetVRF(*VRF)
	Instance
}

type VID uint16

type VIF struct {
	index    VIFIndex
	name     string
	enabled  bool
	vid      VID
	instance VIFInstance
	iface    *Interface
	output   *dpdk.Ring
	vrf      *VRF
	tap      *os.File
	base     *BaseInstance
	tunnel   *Tunnel
	*IPAddrs
	*Neighbours
}

var vifs = make(map[string]*VIF)
var vifIndices = make(map[VIFIndex]*VIF)
var vifCount uint32 = 0

var vifMutex sync.Mutex

func newVIF(i *Interface, name string) (*VIF, error) {
	vifMutex.Lock()
	defer vifMutex.Unlock()

	if vifCount == MaxVIFIndex {
		return nil, errors.New("Number of VIF exceeded the limit.")
	}

	if _, exists := vifs[name]; exists {
		return nil, fmt.Errorf("VIF %s already exists.", name)
	}

	vifCount++
	v := &VIF{
		index:   VIFIndex(vifCount),
		name:    name,
		iface:   i,
		enabled: false,
	}
	vifs[name] = v
	vifIndices[v.index] = v
	v.IPAddrs = newIPAddrs(v)
	v.Neighbours = newNeighbours(v)
	v.base = newSubInstance(i.base, v.name)

	return v, nil
}

func (v *VIF) setVIFInstance(vi VIFInstance) error {
	if v.instance != nil {
		return errors.New("VIFInstance already associated.")
	}
	v.instance = vi
	if v.tunnel != nil {
		if tn, ok := vi.(TunnelNotify); ok {
			v.tunnel.setNotify(tn)
		}
	}
	return nil
}

// Free destroys VIF from the interface.
// If the VIF is associated VRF, the VIF is automatically
// deleted from the VRF.
func (v *VIF) Free() {
	vifMutex.Lock()
	defer vifMutex.Unlock()

	if v.vrf != nil {
		v.vrf.DeleteVIF(v)
		v.vrf = nil
	}

	v.iface.deleteVIF(v)
	if v.instance != nil {
		v.instance.Free()
	}

	delete(vifs, v.name)
	delete(vifIndices, v.index)

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

// IsEnabled returns true if the VIF is enabled.
// Returns false otherwise.
func (v *VIF) IsEnabled() bool {
	return v.enabled
}

func (v *VIF) enable() error {
	if v.output != nil {
		if err := v.instance.Enable(); err != nil {
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
	}
}

// Input returns an input ring for the VIF
// which is the input ring for the underlying interface.
func (v *VIF) Input() *dpdk.Ring {
	return v.base.input
}

// Outbound returns an input ring for outbounds packets, i.e. Lagopus to external.
// Returned ring is same as the one returned by Input.
func (v *VIF) Outbound() *dpdk.Ring {
	return v.base.input
}

// Inbound returns an input ring for inbounds packets, i.e. external to Lagopus.
// If the underlying interface supports secondary input, then secondary input ring is returned.
// Otherwise, the ring same as Outbound is returned.
func (v *VIF) Inbound() *dpdk.Ring {
	if v.base.input2 != nil {
		return v.base.input2
	}
	return v.base.input
}

// Output returns an output ring for the VIF
// This ring is same as the one set in MATCH_ANY rule.
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
		if err := v.base.rules.add(MATCH_ANY, nil, output); err != nil {
			return err
		}
	} else {
		v.base.rules.remove(MATCH_ANY, nil)
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

func (v *VIF) setVRF(vrf *VRF) error {
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
func (v *VIF) Tunnel() *Tunnel {
	return v.tunnel
}

// setTunnel shall be called before VIFInstance is instantiated.
// Tunnel module requires this detail to instantiate actual backends.
func (v *VIF) setTunnel(t *Tunnel) {
	v.tunnel = t
}

// TAP returns tap associated with the VIF.
func (v *VIF) TAP() *os.File {
	return v.tap
}

// GetVIFByIndex returns VIF matches to index
func GetVIFByIndex(index VIFIndex) *VIF {
	if vif, ok := vifIndices[index]; ok {
		return vif
	}
	return nil
}

// GetVIFByName returns VIF matches to name
func GetVIFByName(name string) *VIF {
	if vif, ok := vifs[name]; ok {
		return vif
	}
	return nil
}
