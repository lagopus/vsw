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
	"sync"
)

// Vrf represents Virtual Routing & Forwarding instance.
type Vrf struct {
	modules map[string]Module
	*VrfInfo
}

// VrfInfo is an internal data type that represents VRF.
type VrfInfo struct {
	name  string
	vrfrd uint64
	vifs  []VifIndex
	mutex sync.RWMutex
	*RoutingTable
}

var vrfnames = make(map[string]bool)
var vrfrds = make(map[uint64]*Vrf)
var vrfMutex sync.Mutex

// AllVrfs returns a slice of VRF RD currently enabled.
func AllVrfs() []uint64 {
	vrfMutex.Lock()
	defer vrfMutex.Unlock()

	rds := make([]uint64, len(vrfrds))
	i := 0
	for rd := range vrfrds {
		rds[i] = rd
		i++
	}
	return rds
}

// GetVrfInfo returns VrfInfo for the given VRF RD.
func GetVrfInfo(vrfrd uint64) *VrfInfo {
	if vrf, ok := vrfrds[vrfrd]; ok {
		return vrf.VrfInfo
	}
	return nil
}

// NewVRF creates a VRF instance.
func NewVRF(name string, vrfrd uint64) *Vrf {
	vrfMutex.Lock()
	defer vrfMutex.Unlock()

	Logger.Printf("Creating VRF '%s' with RD of %d\n", name, vrfrd)

	if vrfnames[name] {
		Logger.Printf("VRF '%s' already exists\n", name)
		return nil
	}

	if _, exists := vrfrds[vrfrd]; exists {
		Logger.Printf("VRF RD %d already exists\n", vrfrd)
		return nil
	}

	vi := &VrfInfo{name: name, vrfrd: vrfrd}
	vi.RoutingTable = newRoutingTable(vi)

	vrf := &Vrf{
		VrfInfo: vi,
		modules: make(map[string]Module),
	}
	vrfrds[vrfrd] = vrf
	vrfnames[name] = true

	noti.Notify(notifier.Add, vrf.VrfInfo, nil)

	return vrf
}

// TODO: Delete VRF
func (v *Vrf) Free() {
	// TODO:
	// Stop modules if running on this VRF, and then delete.
	// Notify after deletion.
}

// NewModule creates a module in the VRF.
func (v *Vrf) NewModule(moduleName, name string) Module {
	v.VrfInfo.mutex.Lock()
	defer v.VrfInfo.mutex.Unlock()

	Logger.Printf("Creating Module '%s' of type '%s' in VRF %s\n", name, moduleName, v.VrfInfo.name)
	_, exists := v.modules[name]
	if exists {
		Logger.Printf("Module with the name '%s' already exists.\n", name)
		return nil
	}

	module := newModule(moduleName, name, v.VrfInfo)
	if module != nil {
		v.modules[name] = module
		if module.Type() == TypeVif {
			v.VrfInfo.vifs = append(v.VrfInfo.vifs, module.Vif().VifIndex())
			noti.Notify(notifier.Add, v.VrfInfo, module.Vif().VifInfo())
		}
	}
	return v.modules[name]
}

// Name returns the name of the VRF.
func (vi *VrfInfo) Name() string {
	return vi.name
}

// VrfRD returns the route distinguisher of the VRF.
func (vi *VrfInfo) VrfRD() uint64 {
	return vi.vrfrd
}

// Vifs returns a slice of Vif Indices in the VRF.
// Caller may call VifMacAddress() to fetch MAC address of the VIF.
func (vi *VrfInfo) VIFs() []VifIndex {
	return vi.vifs
}

func (vi *VrfInfo) String() string {
	vi.mutex.RLock()
	defer vi.mutex.RUnlock()

	str := fmt.Sprintf("VRF=%s. VRFRD=%d. %d VIF(s) Connected - ", vi.name, vi.vrfrd, len(vi.vifs))
	for _, vif := range vi.vifs {
		str += fmt.Sprintf(" %d", vif)
	}
	return str
}
