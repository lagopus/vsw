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
	"fmt"
	"sync"
)

type VSI struct {
	name         string
	bridges      map[VID]*bridge
	active       map[VID]bool
	mat          *BaseInstance
	enabled      bool
	macAgingTime int
	maxEntries   int
	macLearning  bool
}

type MACEntry struct {
	VID VID
	BridgeMACEntry
}

type vsiManager struct {
	vsi   map[string]*VSI
	mutex sync.Mutex
}

var vsiMgr = &vsiManager{vsi: make(map[string]*VSI)}

const (
	DefaultMACAgingTime       = 300     // Default MAC aging time
	DefaultMaxEntries         = 3000    // Default maximum MAC entries in bridge
	DefaultMACLearningEnabled = true    // Default MAC learning status
	MaxMACAgingTime           = 1000000 // Maximum MAC Aging Time
	MaxMACEntries             = 65536   // Maximum FDB (MAC Entries) size

	matModule = "mat"
)

// NewVSI creates a new VSI.
func NewVSI(name string) (*VSI, error) {
	vsiMgr.mutex.Lock()
	defer vsiMgr.mutex.Unlock()

	if _, exists := vsiMgr.vsi[name]; exists {
		return nil, fmt.Errorf("VSI %v already exists", name)
	}

	vsi := &VSI{
		name:         name,
		bridges:      make(map[VID]*bridge),
		active:       make(map[VID]bool),
		enabled:      false,
		macAgingTime: DefaultMACAgingTime,
		maxEntries:   DefaultMaxEntries,
		macLearning:  DefaultMACLearningEnabled,
	}

	vsiMgr.vsi[name] = vsi

	return vsi, nil
}

// NewMAT creates a new VSI with MAT.
func NewMAT(name string) (*VSI, error) {
	vsi, err := NewVSI(name)
	if err != nil {
		return nil, err
	}

	// Create an MAT module
	matName := name + "-mat"
	vsi.mat, err = newInstance(matModule, matName, nil)
	if err != nil {
		return nil, err
	}

	return vsi, nil
}

func (v *VSI) Free() {
	vsiMgr.mutex.Lock()
	delete(vsiMgr.vsi, v.name)
	vsiMgr.mutex.Unlock()

	for _, b := range v.bridges {
		b.free()
	}

	if v.mat != nil {
		v.mat.free()
		v.mat = nil
	}
}

func (v *VSI) String() string {
	return v.name
}

func (v *VSI) IsEnabled() bool {
	return v.enabled
}

func (v *VSI) Enable() error {
	if !v.enabled {
		if v.mat != nil {
			if err := v.mat.enable(); err != nil {
				return err
			}
		}

		for vid, active := range v.active {
			if active {
				if err := v.bridges[vid].enable(); err != nil {
					return err
				}
			}
		}
		v.enabled = true
	}
	return nil
}

func (v *VSI) Disable() {
	if v.enabled {
		for _, b := range v.bridges {
			b.disable()
		}

		if v.mat != nil {
			v.mat.disable()
		}

		v.enabled = false
	}
	return
}

// VID returns all VID associated with the VSI.
// The returned value is a map with the VID as a key.
// The value is a bool representing whether the VID is active.
func (v *VSI) VID() map[VID]bool {
	vids := make(map[VID]bool)
	for k, v := range v.active {
		vids[k] = v
	}
	return vids
}

// AddVID creates a new bridge instance with the given VID in the VSI.
func (v *VSI) AddVID(vid VID) error {
	if _, exists := v.bridges[vid]; exists {
		return nil
	}

	b, err := newBridge(fmt.Sprintf("%s-%d", v.name, vid), vid, v.mat)
	if err != nil {
		return err
	}

	v.bridges[vid] = b
	v.active[vid] = false

	// configure bridge with the current settings
	b.setMACAgingTime(v.macAgingTime)
	b.setMaxEntries(v.maxEntries)
	if v.macLearning {
		b.enableMACLearning()
	} else {
		b.disableMACLearning()
	}

	return nil
}

// DeleteVID destroys a bridge instance with the given VID.
func (v *VSI) DeleteVID(vid VID) {
	if b, exists := v.bridges[vid]; exists {
		b.free()
		delete(v.active, vid)
	}
}

// EnableVID enables the bridge associated with the given VID.
func (v *VSI) EnableVID(vid VID) error {
	if _, exists := v.active[vid]; !exists {
		return fmt.Errorf("VID %d not registered.", vid)
	}

	if v.enabled {
		if err := v.bridges[vid].enable(); err != nil {
			return err
		}
	}

	v.active[vid] = true
	return nil
}

// DisableVID disables the bridge associated with the given VID.
func (v *VSI) DisableVID(vid VID) error {
	if _, exists := v.active[vid]; !exists {
		return fmt.Errorf("VID %d not registered.", vid)
	}

	if v.enabled {
		v.bridges[vid].disable()
	}

	v.active[vid] = false
	return nil
}

// AddVIF add VIF to the bridge with the same VID.
func (v *VSI) AddVIF(vif *VIF) error {
	b, ok := v.bridges[vif.vid]
	if !ok {
		return fmt.Errorf("VID %d not registered.", vif.vid)
	}
	if err := vif.setVSI(v); err != nil {
		return err
	}
	return b.addVIF(vif)
}

// DeleteVIF deletes VIF from the bridge.
func (v *VSI) DeleteVIF(vif *VIF) error {
	b, ok := v.bridges[vif.vid]
	if !ok {
		return fmt.Errorf("VID %d not registered.", vif.vid)
	}
	vif.setVSI(nil)
	return b.deleteVIF(vif)
}

func (v *VSI) VIF() []*VIF {
	var vifs []*VIF
	for _, b := range v.bridges {
		vifs = append(vifs, b.vif()...)
	}
	return vifs
}

func (v *VSI) UpdateMTU(vif *VIF) error {
	b, ok := v.bridges[vif.vid]
	if !ok {
		return fmt.Errorf("VID %d not registered.", vif.vid)
	}
	b.updateMTU()
	return nil
}

func (v *VSI) MACAgingTime() int {
	return v.macAgingTime
}

func (v *VSI) SetMACAgingTime(time int) error {
	if time < 0 || time > MaxMACAgingTime {
		return fmt.Errorf("MAC aging time outside the range (0-%d): %d", MaxMACAgingTime, time)
	}
	v.macAgingTime = time
	for _, b := range v.bridges {
		b.setMACAgingTime(time)
	}
	return nil
}

func (v *VSI) MaximumEntries() int {
	return v.maxEntries
}

func (v *VSI) SetMaximumEntries(max int) error {
	if max < 0 || max > MaxMACEntries {
		return fmt.Errorf("MAC maximum entries outside the range (0-%d): %d", MaxMACEntries, max)
	}
	v.maxEntries = max
	for _, b := range v.bridges {
		b.setMaxEntries(max)
	}
	return nil
}

func (v *VSI) MACLearning() bool {
	return v.macLearning
}

func (v *VSI) EnableMACLearning() {
	v.macLearning = true
	for _, b := range v.bridges {
		b.enableMACLearning()
	}
}

func (v *VSI) DisableMACLearning() {
	v.macLearning = false
	for _, b := range v.bridges {
		b.disableMACLearning()
	}
}

func (v *VSI) MACTable() []MACEntry {
	var macTable []MACEntry
	for _, b := range v.bridges {
		for _, e := range b.macTable() {
			entry := MACEntry{
				VID:            b.vid,
				BridgeMACEntry: e,
			}
			macTable = append(macTable, entry)
		}
	}
	return macTable
}

func VSIs() []*VSI {
	vsiMgr.mutex.Lock()
	defer vsiMgr.mutex.Unlock()

	var vsi []*VSI
	for _, v := range vsiMgr.vsi {
		vsi = append(vsi, v)
	}
	return vsi
}

func GetVSI(name string) *VSI {
	vsiMgr.mutex.Lock()
	defer vsiMgr.mutex.Unlock()

	return vsiMgr.vsi[name]
}
