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
	"fmt"
	"github.com/lagopus/vsw/utils/notifier"
	"net"
	"sync"
)

// Vif provides VIF index of the given VIF module.
// VIF module retrieves its VIF index via this struct.
type Vif struct {
	vifIndex   VifIndex         // VIF Index
	macAddress net.HardwareAddr // MAC Address of the VIF
	mtu        MTU              // MTU of the device
	vifInfo    *VifInfo
	mutex      sync.RWMutex
	op         VifOp
}

type VifInfo struct {
	ModuleService
	vif    *Vif
	bridge *Bridge
	*IPAddrs
	*Neighbours
}

type LinkStatus int

const (
	LinkDown LinkStatus = iota
	LinkUp
)

var linkStatusStrings = [...]string{
	LinkDown: "LINK DOWN",
	LinkUp:   "LINK UP",
}

func (s LinkStatus) String() string { return linkStatusStrings[s] }

// VifOp must be conformed by any VIF module.
type VifOp interface {
	// Link returns the currrent link status.
	Link() LinkStatus

	// SetLink enables or disables the device.
	// Returns true if successively set. Otherwise, false.
	SetLink(LinkStatus) bool
}

type MTU uint

var vifs = make(map[VifIndex]*Vif)
var vifIndices = make(map[string]VifIndex)
var vifCount uint32 = 0

var vifMutex sync.Mutex

func newVif() *Vif {
	vifMutex.Lock()
	defer vifMutex.Unlock()

	var vif *Vif
	if vifCount < VifMaxIndex {
		vifCount++
		vif = &Vif{vifIndex: VifIndex(vifCount)}
		vifs[vif.vifIndex] = vif
		vif.vifInfo = &VifInfo{vif: vif}
		vif.vifInfo.IPAddrs = newIPAddrs(vif.vifInfo)
		vif.vifInfo.Neighbours = newNeighbours(vif.vifInfo)

		// Notification on VIF creation is sent by VRF
	}

	return vif
}

func (v *Vif) free() {
	vifMutex.Lock()
	defer vifMutex.Unlock()

	delete(vifs, v.vifIndex)
	// Notify
	noti.Notify(notifier.Delete, v.vifInfo, nil)
}

// config
func (v *Vif) config(op VifOp, ms ModuleService) {
	v.op = op
	v.vifInfo.ModuleService = ms
	vifIndices[ms.Name()] = v.vifIndex
}

// SetMacAddress sets MAC address of the given VIF.
func (v *Vif) SetMacAddress(macAddress net.HardwareAddr) {
	Logger.Printf("VIF%d: %s", v.vifIndex, macAddress)
	v.macAddress = macAddress

	// Notify
	noti.Notify(notifier.Update, v.vifInfo, macAddress)
}

// SetMtu sets current MTU of the given VIF.
func (v *Vif) SetMTU(mtu MTU) {
	Logger.Printf("VIF%d: MTU %d", v.vifIndex, mtu)
	v.mtu = mtu

	// Notify
	noti.Notify(notifier.Update, v.vifInfo, mtu)
}

// VIFIndex returns the VIF index of the given VIF.
func (v *Vif) VifIndex() VifIndex {
	return v.vifIndex
}

// VifInfo returns the VifInfo of the given VIF.
func (v *Vif) VifInfo() *VifInfo {
	return v.vifInfo
}

func (v *Vif) String() string {
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	ips := v.vifInfo.ListIPAddrs()
	str := fmt.Sprintf("VIF%d: MAC=%v, %d IP Address(es)", v.vifIndex, v.macAddress, len(ips))
	for _, ip := range ips {
		str += fmt.Sprintf("\n\t%s", ip)
	}
	return str
}

// AllVifs returns an array of all VIFs.
func AllVifs() []VifIndex {
	vifMutex.Lock()
	defer vifMutex.Unlock()

	indices := make([]VifIndex, len(vifs))
	i := 0
	for idx := range vifs {
		indices[i] = idx
		i++
	}

	return indices
}

// GetVifIndex returns VifIndex of VIF with the given name
func GetVifIndex(name string) VifIndex {
	return vifIndices[name]
}

// GetVifInfo returns a reference to VifInfo for the given vidx.
func GetVifInfo(vidx VifIndex) *VifInfo {
	if vif, ok := vifs[vidx]; ok {
		return vif.vifInfo
	}
	return nil
}

func (vi *VifInfo) String() string {
	return vi.Name()
}

// Link returns the currrent link status.
func (vi *VifInfo) Link() LinkStatus {
	return vi.vif.op.Link()
}

// SetLink enables or disables the device.
// Returns true if successively set. Otherwise, false.
func (vi *VifInfo) SetLink(stat LinkStatus) bool {
	rc := vi.vif.op.SetLink(stat)
	if rc {
		noti.Notify(notifier.Update, vi, stat)
	}
	return rc
}

// VifIndex returns the index of the VIF.
func (vi *VifInfo) VifIndex() VifIndex {
	return vi.vif.vifIndex
}

// MacAddress returns MAC addres of the VIF.
func (vi *VifInfo) MacAddress() net.HardwareAddr {
	return vi.vif.macAddress
}

// MTU returns MTU of the VIF.
func (vi *VifInfo) MTU() MTU {
	return vi.vif.mtu
}
