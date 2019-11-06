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

package sad

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/modules/tunnel/log"
	"github.com/lagopus/vsw/modules/tunnel/tick"
	"github.com/lagopus/vsw/vswitch"
)

type vrf struct {
	sad  SAD
	csad ipsec.SAD
}

// Mgr SAD manager.
type Mgr struct {
	dir  ipsec.DirectionType
	vrfs map[vswitch.VRFIndex]*vrf
	lock sync.RWMutex
}

// mgr is a singleton Object.
var _inbound *Mgr
var _outbound *Mgr

func init() {
	// create Mgr
	_inbound = &Mgr{
		dir:  ipsec.DirectionTypeIn,
		vrfs: map[vswitch.VRFIndex]*vrf{},
		lock: sync.RWMutex{},
	}
	_outbound = &Mgr{
		dir:  ipsec.DirectionTypeOut,
		vrfs: map[vswitch.VRFIndex]*vrf{},
		lock: sync.RWMutex{},
	}
	// Register tick
	if registerTickTask() != nil {
		panic("Can't add tick-task in SAD mgr")
	}
}

func registerTickTask() error {
	task, err := tick.NewTask("Push & Pull SAD", tickTask, nil)
	if err != nil {
		return err
	}
	return ipsec.GetTicker().RegisterTask(task)
}

// SAD tick-task
func tickTask(now time.Time, args []interface{}) (err error) {
	in := GetMgr(ipsec.DirectionTypeIn)
	out := GetMgr(ipsec.DirectionTypeOut)
	err = in.tick()
	if err != nil {
		return
	}
	err = out.tick()
	// TBD error handle
	return
}

// tick-task internal
func (mgr *Mgr) tick() (err error) {
	// pull
	pullErr := mgr.PullSAD()
	if pullErr != nil {
		log.Logger.Err("tick-pull-%v: ERR %s", mgr.dir, pullErr)
	}
	// check lifetime
	lifetimeErr := mgr.CheckLifetime()
	if lifetimeErr != nil {
		log.Logger.Err("tick-lifetime-%v: ERR %s", mgr.dir, lifetimeErr)
	}
	// push
	pushErr := mgr.PushSAD()
	if pushErr != nil {
		log.Logger.Err("tick-push-%v: ERR %s", mgr.dir, pushErr)
	}

	// TBD error handle
	return
}

// GetMgr Get SAD Manager Instance
func GetMgr(dir ipsec.DirectionType) *Mgr {
	if dir == ipsec.DirectionTypeIn {
		return _inbound
	} // else, outbound
	return _outbound
}

func (mgr *Mgr) String() string {
	return fmt.Sprintf("SADMgr %v, %d VRFs",
		mgr.dir, len(mgr.vrfs))
}

func (mgr *Mgr) newVRF(vrfIndex vswitch.VRFIndex) *vrf {
	var csad ipsec.SAD
	if mgr.dir == ipsec.DirectionTypeIn {
		csad = ipsec.NewCSADInbound(vrfIndex)
	} else {
		csad = ipsec.NewCSADOutbound(vrfIndex)
	}
	csad.RegisterAcquireFunc(SadbAcquire)

	vrf := &vrf{
		sad:  SAD{},
		csad: csad,
	}
	return vrf
}

func (mgr *Mgr) deleteVRF(vrfIndex vswitch.VRFIndex) {
	delete(mgr.vrfs, vrfIndex)
}

func (mgr *Mgr) vrf(selector *SASelector) (*vrf, error) {
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

// ReserveSA Reserve SA. (SADB_GET_SPI)
func (mgr *Mgr) ReserveSA(selector *SASelector) (err error) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	if selector == nil {
		return fmt.Errorf("Invalid args")
	}

	var vrf *vrf
	if vrf, err = mgr.vrf(selector); err != nil {
		return
	}

	err = vrf.sad.reserve(selector.SPI)
	if err == nil {
		log.Logger.Info("Reserved SA-%v, %s", mgr.dir, vrf.sad.logString(selector.SPI))
	} else {
		log.Logger.Err("ERR: Failed Reserve: %s", err)
	}
	return
}

// UpdateSA Update SA and ready to push.
func (mgr *Mgr) UpdateSA(selector *SASelector, sav *SAValue) (err error) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	if selector == nil || sav == nil {
		return fmt.Errorf("Invalid args")
	}

	var vrf *vrf
	if vrf, err = mgr.vrf(selector); err != nil {
		return
	}

	err = vrf.sad.update(selector.SPI, sav)
	if err == nil {
		log.Logger.Info("Updated SA-%v, %s", mgr.dir, vrf.sad.logString(selector.SPI))
	} else {
		log.Logger.Err("ERR: Failed Update: %s", err)
	}
	return
}

// AddSA Add SA. (equals Reserve & Update)
func (mgr *Mgr) AddSA(selector *SASelector, sav *SAValue) (err error) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	if selector == nil || sav == nil {
		return fmt.Errorf("Invalid args")
	}

	var vrf *vrf
	if vrf, err = mgr.vrf(selector); err != nil {
		return
	}

	err = vrf.sad.add(selector.SPI, sav)
	if err == nil {
		log.Logger.Info("Added SA-%v, %s", mgr.dir, vrf.sad.logString(selector.SPI))
	} else {
		log.Logger.Err("ERR: Failed Add: %s", err)
	}
	return
}

// EnableSA ready to push.
func (mgr *Mgr) EnableSA(selector *SASelector) (err error) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	if selector == nil {
		return fmt.Errorf("Invalid args")
	}

	var vrf *vrf
	if vrf, err = mgr.vrf(selector); err != nil {
		return
	}

	oldStat := vrf.sad[selector.SPI].inStat
	_, err = vrf.sad.enable(selector.SPI)
	if err == nil {
		log.Logger.Info("Enabled SA-%v, %s", mgr.dir, vrf.sad.logStringChanged(selector.SPI, oldStat))
	} else {
		log.Logger.Err("ERR: Failed Enable: %s", err)
	}
	return
}

// DeleteSA Drop or Mark 'deleteing' SA.
func (mgr *Mgr) DeleteSA(selector *SASelector) (err error) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	if selector == nil {
		return fmt.Errorf("Invalid args")
	}

	var vrf *vrf
	if vrf, err = mgr.vrf(selector); err != nil {
		return
	}

	oldStat := vrf.sad[selector.SPI].inStat
	_, err = vrf.sad.delete(selector.SPI)
	if err == nil {
		log.Logger.Info("Deleted SA-%v, %s", mgr.dir, vrf.sad.logStringChanged(selector.SPI, oldStat))
	} else {
		log.Logger.Err("ERR: Failed Delete: %s", err)
	}
	return
}

// FindSA Find SA from SPI.
func (mgr *Mgr) FindSA(selector *SASelector) (retp *SAValue, err error) {
	mgr.lock.RLock()
	defer mgr.lock.RUnlock()

	if selector == nil {
		return nil, fmt.Errorf("Invalid args")
	}

	var vrf *vrf
	if vrf, err = mgr.vrf(selector); err != nil {
		return
	}

	if ret, exists := vrf.sad[selector.SPI]; exists {
		if ret.inStat.findable() {
			copy := ret
			retp = &copy
		} else {
			err = fmt.Errorf("Not Exists : %v", selector.SPI)
		}
	} else {
		err = fmt.Errorf("Not exists : %v", selector.SPI)
	}
	return
}

// FindSAbyIP Find SA from src&dst IP.
func (mgr *Mgr) FindSAbyIP(selector *SASelector, local net.IP,
	remote net.IP) (retk SPI, retv *SAValue, err error) {
	mgr.lock.RLock()
	defer mgr.lock.RUnlock()

	if selector == nil {
		return 0, nil, fmt.Errorf("Invalid args")
	}

	var tmp time.Time
	retk = InvalidSPI

	var vrf *vrf
	if vrf, err = mgr.vrf(selector); err != nil {
		return
	}

	for spi, sav := range vrf.sad {
		if local.Equal(sav.LocalEPIP) && remote.Equal(sav.RemoteEPIP) {
			if sav.inStat.findable() &&
				(sav.LifeTimeCurrent.After(tmp) || sav.LifeTimeCurrent.Equal(tmp)) {
				retk = spi
				copy := sav
				retv = &copy
				tmp = sav.LifeTimeCurrent
			}
		}
	}

	if retk == InvalidSPI {
		err = fmt.Errorf("Not exists : %v %v", local, remote)
	}
	return
}

func (mgr *Mgr) push(vrf *vrf, entries map[SPI]SAValue) int {
	// convert to C data
	entArr := []ipsec.CSA{}
	if len(entries) != 0 {
		for spi, sav := range entries {
			csav := &sav.CSAValue
			csa, err := csav.Sav2sa(ipsec.CSPI(spi))
			if err == nil {
				entArr = append(entArr, csa)
			} else {
				// TBD error handle
				log.Logger.Warning("WARN: failed to convert C struct: %s", err)
			}
		}
	}
	return vrf.csad.Push(entArr)
}

func (mgr *Mgr) pullLifetime(vrf *vrf) error {
	for spi, sav := range vrf.sad {
		if sav.inStat.pullable() {
			if lifetime, byte, err := vrf.csad.PullLifetime(ipsec.CSPI(spi)); err != nil {
				vrf.sad.changeLifetimeCurrent(spi, lifetime, byte)
				//log.Logger.Debug("pull SA-%v %s", vrf.csad.dir, vrf.sad.logString(spi))
			} else {
				return err
			}
		}
	}
	return nil
}

func (mgr *Mgr) pullAcquired(vrf *vrf) (err error) {
	return vrf.csad.PullAcquired()
}

// PushSAD Push SAD to C.
func (mgr *Mgr) PushSAD() (err error) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	for vrfIndex, vrf := range mgr.vrfs {
		if len(vrf.sad) != 0 {
			// check need to push
			changed := vrf.sad.countChanged()
			if changed != 0 {
				// collect to push
				ent, exp := vrf.sad.collectPush()
				// push to C
				result := mgr.push(vrf, ent)
				if result == 0 {
					// change internal status.
					for spi, sav := range ent {
						_, e := vrf.sad.pushed(spi)
						if e == nil {
							log.Logger.Info("pushed SA-%v %s", mgr.dir, vrf.sad.logStringChanged(spi, sav.inStat))
						} else {
							log.Logger.Err("Failed post-push operation: %s", e)
							// TBD error handle
						}
					}
					for _, spi := range exp {
						oldStat := vrf.sad[spi].inStat
						_, e := vrf.sad.pushed(spi)
						if e == nil {
							log.Logger.Info("detached SA-%v %s", mgr.dir, vrf.sad.logStringChanged(spi, oldStat))
						} else {
							log.Logger.Err("Failed post-detach operation: %s", e)
							// TBD error handle
						}
					}
					log.Logger.Info("Pushed SAD-%v(), push=%d (changed=%d), expire=%d",
						mgr.dir, len(ent), changed, len(exp))
				} else {
					err = fmt.Errorf("sad_push returns error code=%d", result)
				}
			}
		} else {
			// Delete vrf.
			mgr.deleteVRF(vrfIndex)
		}
	}
	return
}

// PullSAD pull current SAD from C side
func (mgr *Mgr) PullSAD() (err error) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	for _, vrf := range mgr.vrfs {
		if len(vrf.sad) != 0 {
			err = mgr.pullLifetime(vrf)
			if err == nil {
				err = mgr.pullAcquired(vrf)
			}
		}
	}
	return
}

// CheckLifetime check soft/hard lifetime expired
func (mgr *Mgr) CheckLifetime() (err error) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()
	now := time.Now()

	for vrfIndex, vrf := range mgr.vrfs {
		cntSoft := 0
		cntHard := 0
		for spi, sav := range vrf.sad {
			if sav.isSoftExpired(now) {
				cntSoft++
				if SadbExpire(vrfIndex, mgr.dir, spi, &sav, SoftLifetimeExpired) { // send SADB_EXPIRE(Soft)
					_, e := vrf.sad.softExpired(spi)
					if e == nil {
						log.Logger.Info("softExpired SA-%v: %s", mgr.dir, vrf.sad.logStringChanged(spi, sav.inStat))
					} else {
						log.Logger.Err("ERR: Failed post-softExpired op: %s", e)
						// TBD error handle
					}
				} else {
					err = fmt.Errorf("Failed to send SADB_EXPIRE(soft): spi=%d", spi)
				}
			}
			if sav.isHardExpired(now) {
				cntHard++
				if SadbExpire(vrfIndex, mgr.dir, spi, &sav, HardLifetimeExpired) { // send SADB_EXPIRE(Hard)
					_, e := vrf.sad.hardExpired(spi)
					if e == nil {
						log.Logger.Info("hardExpired SA-%v: %s", mgr.dir, vrf.sad.logStringChanged(spi, sav.inStat))
					} else {
						log.Logger.Err("ERR: Failed post-hardExpired op: %s", e)
						// TBD error handle
					}
				} else {
					err = fmt.Errorf("Failed to send SADB_EXPIRE(hard): spi=%d", spi)
				}
			}
		}
		if cntSoft+cntHard > 0 {
			log.Logger.Info("checked SADB-%v len:%d softExpired: %d hardExpired: %d",
				mgr.dir, len(vrf.sad), cntSoft, cntHard)
		}
	}
	return
}

// CloneSAD Get deep copied SAD (for dump.)
func (mgr *Mgr) CloneSAD(selector *SASelector) SAD {
	mgr.lock.RLock()
	defer mgr.lock.RUnlock()

	if selector != nil {
		if vrf, ok := mgr.vrfs[selector.VRFIndex]; ok {
			return vrf.sad.clone()
		}
	}
	return SAD{}
}
