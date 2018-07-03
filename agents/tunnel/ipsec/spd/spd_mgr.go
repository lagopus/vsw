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

package spd

import (
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/modules/tunnel/ipsec/tick"
	"github.com/lagopus/vsw/vswitch"
)

type spds map[ipsec.IPVersionType]*spd
type spdByEntryID map[uint32]*SPValue

type vrf struct {
	spds         spds
	spdByEntryID spdByEntryID
	isModified   bool
}

// Mgr SPD manager.
type Mgr struct {
	vrfs map[vswitch.VRFIndex]*vrf
	lock sync.Mutex
}

var spdMgr = newSPDMgr()

func newSPDMgr() *Mgr {
	mgr := &Mgr{
		vrfs: map[vswitch.VRFIndex]*vrf{},
	}
	return mgr
}

func init() {
	if err := addTickTask(); err != nil {
		panic("Can't add tick-task in SPD mgr.")
	}
}

// Tick.

func addTickTask() error {
	var task *tick.Task
	var err error
	if task, err = tick.NewTask("spdMake", tickTackFunc, nil); err == nil {
		ticker := tick.GetTicker()
		return ticker.RegisterTask(task)
	}
	log.Println(err)
	return err
}

func tickTackFunc(now time.Time, args []interface{}) error {
	mgr := GetMgr()

	mgr.expiredSP(now)
	if err := mgr.statsSPD(); err != nil {
		log.Println(err)
		return err
	}

	return mgr.makeSPD()
}

func (mgr *Mgr) createPKey(selector *SPSelector, direction ipsec.DirectionType) string {
	key := strconv.FormatUint(uint64(selector.VRFIndex), 10)
	key += selector.LocalIP.IP.String()
	key += selector.LocalIP.Mask.String()
	key += strconv.FormatUint(uint64(selector.LocalPortRangeStart), 10)
	key += strconv.FormatUint(uint64(selector.LocalPortRangeEnd), 10)
	key += selector.RemoteIP.IP.String()
	key += selector.RemoteIP.Mask.String()
	key += strconv.FormatUint(uint64(selector.RemotePortRangeStart), 10)
	key += strconv.FormatUint(uint64(selector.RemotePortRangeEnd), 10)
	key += strconv.FormatUint(uint64(selector.UpperProtocol), 10)
	key += strconv.FormatUint(uint64(direction), 10)

	return key
}

func (mgr *Mgr) isIPv4(selector *SPSelector) bool {
	fn := func(ip net.IP) bool {
		return (ip == nil || ip.To4() != nil)
	}
	return fn(selector.LocalIP.IP) && fn(selector.RemoteIP.IP)
}

func (mgr *Mgr) isIPv6(selector *SPSelector) bool {
	fn := func(ip net.IP) bool {
		return (ip == nil || len(ip) == net.IPv6len && ip.To4() == nil)
	}
	return fn(selector.LocalIP.IP) && fn(selector.RemoteIP.IP)
}

func (mgr *Mgr) newVRF(vrfIndex vswitch.VRFIndex) *vrf {
	vrf := &vrf{
		spds: spds{
			ipsec.IPVersionType4: newSPD4(vrfIndex),
			ipsec.IPVersionType6: newSPD6(vrfIndex),
		},
		spdByEntryID: map[uint32]*SPValue{},
		isModified:   false,
	}
	return vrf
}

func (mgr *Mgr) deleteVRF(vrfIndex vswitch.VRFIndex) {
	delete(mgr.vrfs, vrfIndex)
}

func (mgr *Mgr) vrf(selector *SPSelector) (*vrf, error) {
	var vrf *vrf
	var ok bool

	if selector.VRFIndex >= ipsec.MaxVRFEntries {
		return nil, fmt.Errorf("Out of ragne vrf index: %v", selector.VRFIndex)
	}

	if vrf, ok = mgr.vrfs[selector.VRFIndex]; !ok {
		vrf = mgr.newVRF(selector.VRFIndex)
		mgr.vrfs[selector.VRFIndex] = vrf
	}
	return vrf, nil
}

func (mgr *Mgr) spd(vrf *vrf, selector *SPSelector) *spd {
	if mgr.isIPv4(selector) {
		return vrf.spds[ipsec.IPVersionType4]
	} else if mgr.isIPv6(selector) {
		return vrf.spds[ipsec.IPVersionType6]
	}

	return nil
}

func (mgr *Mgr) makeSPD() error {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	for vrfIndex, vrf := range mgr.vrfs {
		if vrf.isModified {
			var err error
			for _, spd := range vrf.spds {
				if err = spd.makeSPD(); err != nil {
					log.Println(err)
					vrf.isModified = false
					return err
				}
			}
			vrf.isModified = false
		}

		// Delete vrf.
		if vrf.spds[ipsec.IPVersionType4].isEmpty() &&
			vrf.spds[ipsec.IPVersionType6].isEmpty() {
			mgr.deleteVRF(vrfIndex)
		}
	}

	return nil
}

func (mgr *Mgr) statsSPD() error {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	var err error
	for _, vrf := range mgr.vrfs {
		for _, spd := range vrf.spds {
			if err = spd.statsSPD(); err != nil {
				log.Println(err)
				return err
			}
		}
	}

	return nil
}

func (mgr *Mgr) deleteSPNoLock(vrf *vrf, spd *spd, key string, value *SPValue) {
	if !vrf.isModified && value.State == Completed && value.SPI != 0 {
		vrf.isModified = true
	}
	delete(vrf.spdByEntryID, value.EntryID)
	spd.deleteSP(value.Direction, key)
}

func (mgr *Mgr) expiredSP(now time.Time) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	for _, vrf := range mgr.vrfs {
		for _, spd := range vrf.spds {
			fn := func(key string, value *SPValue) error {
				if value.isExpiredLifeTimeHard(now) {
					mgr.deleteSPNoLock(vrf, spd, key, value)
				}
				return nil
			}
			_ = spd.iterate(fn)
		}
	}
}

func (mgr *Mgr) createHash(key string) uint32 {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(key))
	return hash.Sum32()
}

func (mgr *Mgr) createEntryID(key string) uint32 {
	hash := mgr.createHash(key)
	return ((hash >> ipsec.EntryIDBits) ^ hash) & ipsec.EntryIDTinyMask
}

// Public.

// AddSP Add SP.
func (mgr *Mgr) AddSP(direction ipsec.DirectionType,
	selector *SPSelector,
	value *SPValue) (uint32, error) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	if selector == nil || value == nil {
		return 0, fmt.Errorf("Invalid args")
	}

	var vrf *vrf
	var err error
	if vrf, err = mgr.vrf(selector); err != nil {
		return 0, err
	}

	if spd := mgr.spd(vrf, selector); spd != nil {
		key := mgr.createPKey(selector, direction)
		if _, ok := spd.findSP(direction, key); !ok {
			value.EntryID = mgr.createEntryID(key)
			value.SPSelector = *selector
			value.Direction = direction
			spd.addSP(direction, key, value)
			vrf.spdByEntryID[value.EntryID] = value
			if !vrf.isModified && value.State == Completed && value.SPI != 0 {
				vrf.isModified = true
			}
			return value.EntryID, nil
		}
		return 0, fmt.Errorf("Already exists : %v", selector)
	}
	return 0, fmt.Errorf("Not found SPD")
}

// UpdateSP Update SP.
func (mgr *Mgr) UpdateSP(direction ipsec.DirectionType,
	selector *SPSelector,
	value *SPValue) error {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	if selector == nil || value == nil {
		return fmt.Errorf("Invalid args")
	}

	var vrf *vrf
	var err error
	if vrf, err = mgr.vrf(selector); err != nil {
		return err
	}

	if spd := mgr.spd(vrf, selector); spd != nil {
		key := mgr.createPKey(selector, direction)
		if _, ok := spd.findSP(direction, key); ok {
			// Overwrite.
			spd.addSP(direction, key, value)
			vrf.spdByEntryID[value.EntryID] = value
			if !vrf.isModified && value.State == Completed && value.SPI != 0 {
				vrf.isModified = true
			}
			return nil
		}
		return fmt.Errorf("Not found : %v", selector)
	}
	return fmt.Errorf("Not found SPD")
}

// DeleteSP Delete SP.
func (mgr *Mgr) DeleteSP(direction ipsec.DirectionType,
	selector *SPSelector) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	if selector != nil {
		var vrf *vrf
		var err error
		if vrf, err = mgr.vrf(selector); err != nil {
			// ignore.
			return
		}

		if spd := mgr.spd(vrf, selector); spd != nil {
			key := mgr.createPKey(selector, direction)
			if value, ok := spd.findSP(direction, key); ok {
				mgr.deleteSPNoLock(vrf, spd, key, value)
			}
		}
	}
}

// SetSPI Set SPI.
func (mgr *Mgr) SetSPI(direction ipsec.DirectionType,
	selector *SPSelector,
	spi uint32) error {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	if selector == nil {
		return fmt.Errorf("Invalid args")
	}

	var vrf *vrf
	var err error
	if vrf, err = mgr.vrf(selector); err != nil {
		return err
	}

	if spd := mgr.spd(vrf, selector); spd != nil {
		key := mgr.createPKey(selector, direction)

		if v, ok := spd.findSP(direction, key); ok {
			v.SPI = spi
			if !vrf.isModified && v.State == Completed && v.SPI != 0 {
				vrf.isModified = true
			}
		} else {
			return fmt.Errorf("Not found : %v", selector)
		}
	} else {
		return fmt.Errorf("Not found SPD")
	}

	return nil
}

// FindSP Find SP.
func (mgr *Mgr) FindSP(direction ipsec.DirectionType,
	selector *SPSelector) (*SPValue, bool) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	if selector == nil {
		return nil, false
	}

	var vrf *vrf
	var err error
	if vrf, err = mgr.vrf(selector); err != nil {
		return nil, false
	}

	if spd := mgr.spd(vrf, selector); spd != nil {
		key := mgr.createPKey(selector, direction)

		if v, ok := spd.findSP(direction, key); ok {
			return v.Copy(), ok
		}
		return nil, false
	}
	return nil, false
}

// FindSPByEntryID Find SP with Entry ID.
func (mgr *Mgr) FindSPByEntryID(selector *SPSelector, entryID uint32) (*SPValue, bool) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	if selector == nil {
		return nil, false
	}

	if vrf, ok := mgr.vrfs[selector.VRFIndex]; ok {
		if v, ok := vrf.spdByEntryID[entryID]; ok {
			return v.Copy(), ok
		}
	}

	return nil, false
}

// ClearSPD Clear.
func (mgr *Mgr) ClearSPD() {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	for _, vrf := range mgr.vrfs {
		for key := range vrf.spdByEntryID {
			delete(vrf.spdByEntryID, key)
		}
		for _, spd := range vrf.spds {
			spd.clearSPD()
		}
	}
}

// GetMgr Get SPDMgr instance.
func GetMgr() *Mgr {
	return spdMgr
}
