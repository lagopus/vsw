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

package ifaces

import (
	"fmt"
	"sync"
	"time"

	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/modules/tunnel/log"
	"github.com/lagopus/vsw/modules/tunnel/tick"
	"github.com/lagopus/vsw/vswitch"
)

type db struct {
	ifaces     map[vswitch.VIFIndex]*iface
	cifaces    ipsec.Iface
	isModified bool
}

// Mgr Iface manager.
type Mgr struct {
	dbs  map[ipsec.DirectionType]*db
	lock sync.Mutex
}

var ifaceMgr = newIfaceMgr()

func newIfaceMgr() *Mgr {
	mgr := &Mgr{
		dbs: map[ipsec.DirectionType]*db{
			ipsec.DirectionTypeOut: &db{
				ifaces:  map[vswitch.VIFIndex]*iface{},
				cifaces: ipsec.NewCIfaces(),
			},
			ipsec.DirectionTypeIn: &db{
				ifaces:  map[vswitch.VIFIndex]*iface{},
				cifaces: ipsec.NewCIfaces(),
			},
		},
	}
	return mgr
}

func init() {
	if err := addTickTask(); err != nil {
		panic("Can't add tick-task in Iface mgr.")
	}
}

// Tick.

func addTickTask() error {
	var task *tick.Task
	var err error
	if task, err = tick.NewTask("ifaceSetQueues", tickTackFunc, nil); err == nil {
		ticker := ipsec.GetTicker()
		return ticker.RegisterTask(task)
	}
	log.Logger.Err("%v", err)
	return err
}

func tickTackFunc(now time.Time, args []interface{}) error {
	mgr := GetMgr()

	return mgr.push()
}

func (mgr *Mgr) setModified(direction ipsec.DirectionType) {
	mgr.dbs[direction].isModified = true
}

func (mgr *Mgr) cifaces(direction ipsec.DirectionType) (ipsec.Iface, error) {
	if db, ok := mgr.dbs[direction]; ok {
		if db.cifaces != nil {
			return db.cifaces, nil
		}
		return nil, fmt.Errorf("cifaces is nil")
	}
	return nil, fmt.Errorf("not found db")
}

func (mgr *Mgr) iface(direction ipsec.DirectionType,
	vifIndex vswitch.VIFIndex) (*iface, error) {
	if vifIndex >= ipsec.MaxVIFEntries {
		return nil, fmt.Errorf("Out of ragne vif index(%v)",
			vifIndex)
	}

	if _, ok := mgr.dbs[direction].ifaces[vifIndex]; !ok {
		iface := newIface(vifIndex)
		mgr.dbs[direction].ifaces[vifIndex] = iface
	}

	return mgr.dbs[direction].ifaces[vifIndex], nil
}

func (mgr *Mgr) pushIfaces(direction ipsec.DirectionType, db *db) error {
	var array []ipsec.CIface
	var err error
	if array, err = db.cifaces.AllocArray(); err != nil {
		log.Logger.Err("%v", err)
		return err
	}
	defer db.cifaces.FreeArray(array)

	for vifIndex, iface := range db.ifaces {
		if iface.vrfIndex() != nil {
			db.cifaces.SetCIface(&array[vifIndex], &iface.CIfaceValue)
		}
	}
	err = db.cifaces.PushIfaces(direction, array)

	return err
}

func (mgr *Mgr) push() error {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	for direction, db := range mgr.dbs {
		if db.cifaces != nil {
			if db.isModified {
				if err := mgr.pushIfaces(direction, db); err != nil {
					db.isModified = false
					return err
				}
			}
			db.isModified = false
		}
	}

	return nil
}

// Public.

// SetVRFIndex Set VRF index.
func (mgr *Mgr) SetVRFIndex(vifIndex vswitch.VIFIndex,
	vrfIndex *vswitch.VRFIndex) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	log.Logger.Info("vif index: %v, Set vrf index(%v)", vifIndex, *vrfIndex)

	for direction := range mgr.dbs {
		var iface *iface
		var err error
		if iface, err = mgr.iface(direction, vifIndex); err != nil {
			// ignore
			log.Logger.Info("ignore: %v", err)
			return
		}

		iface.setVRFIndex(vrfIndex)
		mgr.setModified(direction)
	}
}

// UnsetVRFIndex Unset VRF index.
func (mgr *Mgr) UnsetVRFIndex(vifIndex vswitch.VIFIndex) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	log.Logger.Info("vif index: %v", vifIndex)

	for direction := range mgr.dbs {
		var iface *iface
		var err error
		if iface, err = mgr.iface(direction, vifIndex); err != nil {
			// ignore
			log.Logger.Info("ignore: %v", err)
			return
		}

		iface.unsetVRFIndex()
		mgr.setModified(direction)
	}
}

// SetRing Set Ring.
func (mgr *Mgr) SetRing(vifIndex vswitch.VIFIndex, rings *ipsec.Rings) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	log.Logger.Info("vif index: %v, Set ring(%v)", vifIndex, rings)

	for direction := range mgr.dbs {
		var iface *iface
		var err error
		if iface, err = mgr.iface(direction, vifIndex); err != nil {
			// ignore
			log.Logger.Info("ignore: %v", err)
			return
		}

		iface.setRings(direction, rings)
		mgr.setModified(direction)
	}
}

// UnsetRing Unset ring.
func (mgr *Mgr) UnsetRing(vifIndex vswitch.VIFIndex) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	log.Logger.Info("vif index: %v, Unset ring", vifIndex)

	for direction := range mgr.dbs {
		var iface *iface
		var err error
		if iface, err = mgr.iface(direction, vifIndex); err != nil {
			// ignore
			log.Logger.Info("ignore: %v", err)
			return
		}

		iface.unsetRings()
		mgr.setModified(direction)
	}
}

// SetTTL Set TTL.
func (mgr *Mgr) SetTTL(vifIndex vswitch.VIFIndex,
	ttl uint8) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	log.Logger.Info("vif index: %v, Set TTL(%v)",
		vifIndex, ttl)

	for direction := range mgr.dbs {
		var iface *iface
		var err error
		if iface, err = mgr.iface(direction, vifIndex); err != nil {
			// ignore
			log.Logger.Info("ignore: %v", err)
			return
		}

		iface.setTTL(ttl)
		mgr.setModified(direction)
	}
}

// SetTOS Set TOS.
func (mgr *Mgr) SetTOS(vifIndex vswitch.VIFIndex,
	tos int8) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	log.Logger.Info("vif index: %v, Set TOS(%v)",
		vifIndex, tos)

	for direction := range mgr.dbs {
		var iface *iface
		var err error
		if iface, err = mgr.iface(direction, vifIndex); err != nil {
			// ignore
			log.Logger.Info("ignore: %v", err)
			return
		}

		iface.setTOS(tos)
		mgr.setModified(direction)
	}
}

// Stats Get stats.
func (mgr *Mgr) Stats(vifIndex vswitch.VIFIndex,
	direction ipsec.DirectionType) *ipsec.CIfaceStats {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	log.Logger.Info("vif index: %v, Get Stats(%v)",
		vifIndex, direction)

	var cifaces ipsec.Iface
	var err error
	if cifaces, err = mgr.cifaces(direction); err != nil {
		// ignore
		log.Logger.Info("ignore: %v", err)
		return &ipsec.CIfaceStats{}
	}

	// get stats pointer.
	var s *ipsec.CIfaceStats
	s, err = cifaces.Stats(direction, vifIndex)
	if err != nil {
		// ignore
		log.Logger.Info("ignore: %v", err)
		return &ipsec.CIfaceStats{}
	}
	// copy.
	stats := *s
	return &stats
}

// ResetStats Reset stats.
func (mgr *Mgr) ResetStats(vifIndex vswitch.VIFIndex,
	direction ipsec.DirectionType) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	log.Logger.Info("vif index: %v, Reset Stats(%v)",
		vifIndex, direction)

	var cifaces ipsec.Iface
	var err error
	if cifaces, err = mgr.cifaces(direction); err != nil {
		// ignore
		log.Logger.Info("ignore: %v", err)
		return
	}

	// get stats pointer.
	var s *ipsec.CIfaceStats
	s, err = cifaces.Stats(direction, vifIndex)
	if err != nil {
		// ignore
		log.Logger.Info("ignore: %v", err)
		return
	}

	*s = ipsec.CIfaceStats{}
}

// ClearIfaces Clear.
func (mgr *Mgr) ClearIfaces() {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	for _, db := range mgr.dbs {
		for key := range db.ifaces {
			delete(db.ifaces, key)
		}
	}
}

// GetMgr Get IfaceMgr instance.
func GetMgr() *Mgr {
	return ifaceMgr
}
