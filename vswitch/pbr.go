//
// Copyright 2019 Nippon Telegraph and Telephone Corporation.
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
	"sync"
)

type PBRAction int

const (
	PBRActionNone PBRAction = iota
	PBRActionDrop
	PBRActionPass
	PBRActionForward
)

type PBRNextHop struct {
	Nexthop
	Action PBRAction
}

type PBREntry struct {
	FiveTuple      // ref: fivetuple.go
	Priority  uint // rule priority
	InputVIF  *VIF // input interface
	NextHops  map[string]PBRNextHop
}

type pbrObserver interface {
	pbrEntryAdded(entry PBREntry)
	pbrEntryDeleted(entry PBREntry)
}

type PBR struct {
	observer pbrObserver
	entries  map[string]PBREntry
	mutex    sync.RWMutex
}

func (nh *PBRNextHop) Equal(x PBRNextHop) bool {
	return nh.Weight == x.Weight &&
		nh.Dev.VIFIndex() == x.Dev.VIFIndex() &&
		nh.Action == x.Action &&
		nh.Gw.Equal(x.Gw)
}

func (pe *PBREntry) equal(x *PBREntry) bool {
	if !pe.SrcIP.Equal(x.SrcIP) || !pe.DstIP.Equal(x.DstIP) ||
		!pe.SrcPort.Equal(&x.SrcPort) ||
		!pe.DstPort.Equal(&x.DstPort) ||
		pe.Proto != x.Proto || pe.Priority != x.Priority ||
		pe.InputVIF.Index() != x.InputVIF.Index() {
		return false
	}
	for k, v := range pe.NextHops {
		if !v.Equal(x.NextHops[k]) {
			return false
		}
	}
	return true
}

func newPBR(observer pbrObserver) *PBR {
	return &PBR{
		observer: observer,
		entries:  make(map[string]PBREntry),
	}
}

// AddPBREntry adds PBRentry to PBR held by vrf.
// If the same key has already been registered,
// if the entries are the same, do nothing.
// And if the entry is different, delete it and register as a new entry.
// When key is not registered, register new entry.
// TODO: Automatically notify when PBREntry is changed.
func (p *PBR) AddPBREntry(name string, entry *PBREntry) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if v, exists := p.entries[name]; exists {
		// If the different rule exists with the same name,
		// delete the old one. Otherwise, ignore.
		if v.equal(entry) {
			return
		}
		p.DeletePBREntry(name)
	}

	// When key is not regiseterd.
	p.entries[name] = *entry
	p.observer.pbrEntryAdded(*entry)
}

// DeletePBREntry deletes PBREntry from PBR.
// If the entry is already registered, delete it.
func (p *PBR) DeletePBREntry(name string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if val, exists := p.entries[name]; exists {
		p.observer.pbrEntryDeleted(val)
		delete(p.entries, name)
	}
}
