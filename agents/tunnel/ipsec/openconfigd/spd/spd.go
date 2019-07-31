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

package spd

import (
	"fmt"
	"sync"

	"github.com/lagopus/vsw/agents/tunnel/ipsec/spd"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/modules/tunnel/log"
	"github.com/lagopus/vsw/vswitch"
)

var (
	mgr  *spd.Mgr
	db   map[string]*spd.SPValue
	lock sync.Mutex
)

func init() {
	mgr = spd.GetMgr()
	db = map[string]*spd.SPValue{}
}

func vSP2SPvSPI(sp *vswitch.SP, spv *spd.SPValue) error {
	if sp.SPI == 0 {
		return fmt.Errorf("Bad SPI: %v", sp.SPI)
	}

	spv.SPI = sp.SPI

	return nil
}

func vSP2SPvDirection(sp *vswitch.SP, spv *spd.SPValue) error {
	switch sp.Direction {
	case vswitch.Inbound:
		spv.Direction = ipsec.DirectionTypeIn
	case vswitch.Outbound:
		spv.Direction = ipsec.DirectionTypeOut
	default:
		return fmt.Errorf("Unsupported direction: %v", sp.Direction)
	}

	return nil
}

func vSP2SPvProtocol(sp *vswitch.SP, spv *spd.SPValue) error {
	switch sp.SecurityProtocol {
	case vswitch.IPP_ESP:
		spv.Protocol = ipsec.SecurityProtocolTypeESP
	default:
		return fmt.Errorf("Unsupported protocol: %v", sp.SecurityProtocol)
	}

	return nil
}

func vSP2SPvPolicy(sp *vswitch.SP, spv *spd.SPValue) error {
	switch sp.Policy {
	case vswitch.Discard:
		spv.Policy = ipsec.PolicyTypeDiscard
	case vswitch.Bypass:
		spv.Policy = ipsec.PolicyTypeBypass
	case vswitch.Protect:
		spv.Policy = ipsec.PolicyTypeProtect
	default:
		return fmt.Errorf("Unsupported policy: %v", sp.Policy)
	}

	return nil
}

func vSP2SPvPriority(sp *vswitch.SP, spv *spd.SPValue) error {
	spv.Priority = sp.Priority

	return nil
}

func vSP2SPvLocalIP(sp *vswitch.SP, spv *spd.SPValue) error {
	spv.LocalIP.IP = sp.SrcAddress.IP
	spv.LocalIP.Mask = sp.SrcAddress.Mask

	return nil
}

func vSP2SPvRemoteIP(sp *vswitch.SP, spv *spd.SPValue) error {
	spv.RemoteIP.IP = sp.DstAddress.IP
	spv.RemoteIP.Mask = sp.DstAddress.Mask

	return nil
}

func vSP2SPvUpperProtocol(sp *vswitch.SP, spv *spd.SPValue) error {
	if sp.UpperProtocol == vswitch.IPP_ANY {
		spv.UpperProtocol = ipsec.UpperProtocolTypeAny
	} else {
		spv.UpperProtocol = ipsec.UpperProtocolType(sp.UpperProtocol)
	}

	return nil
}

func vSP2SPvLocalPort(sp *vswitch.SP, spv *spd.SPValue) error {
	if sp.SrcPort == 0 {
		// any.
		spv.LocalPortRangeStart = 0
		spv.LocalPortRangeEnd = 65535
	} else {
		spv.LocalPortRangeStart = sp.SrcPort
		spv.LocalPortRangeEnd = sp.SrcPort
	}

	return nil
}

func vSP2SPvRemotePort(sp *vswitch.SP, spv *spd.SPValue) error {
	if sp.DstPort == 0 {
		// any.
		spv.RemotePortRangeStart = 0
		spv.RemotePortRangeEnd = 65535
	} else {
		spv.RemotePortRangeStart = sp.DstPort
		spv.RemotePortRangeEnd = sp.DstPort
	}

	return nil
}

func vSP2SPvLevel(sp *vswitch.SP, spv *spd.SPValue) error {
	// only support tunnel.
	spv.Level = ipsec.LevelTypeRequire

	return nil
}

func vSP2SPv(sp *vswitch.SP, spv *spd.SPValue) error {
	// SPI.
	if err := vSP2SPvSPI(sp, spv); err != nil {
		return err
	}
	// Direction.
	if err := vSP2SPvDirection(sp, spv); err != nil {
		return err
	}
	// Protocol.
	if err := vSP2SPvProtocol(sp, spv); err != nil {
		return err
	}
	// Policy.
	if err := vSP2SPvPolicy(sp, spv); err != nil {
		return err
	}
	// Priority.
	if err := vSP2SPvPriority(sp, spv); err != nil {
		return err
	}
	// LocalIP.
	if err := vSP2SPvLocalIP(sp, spv); err != nil {
		return err
	}
	// RemoteIP.
	if err := vSP2SPvRemoteIP(sp, spv); err != nil {
		return err
	}
	// UpperProtocol.
	if err := vSP2SPvUpperProtocol(sp, spv); err != nil {
		return err
	}
	// LocalPort.
	if err := vSP2SPvLocalPort(sp, spv); err != nil {
		return err
	}
	// RemotePort.
	if err := vSP2SPvRemotePort(sp, spv); err != nil {
		return err
	}
	// Level.
	if err := vSP2SPvLevel(sp, spv); err != nil {
		return err
	}

	return nil
}

// no lock.
func addSPNoLock(vrf *vswitch.VRF, sp *vswitch.SP) {
	log.Logger.Info("Add SP: %v", sp)

	if _, ok := db[sp.Name]; ok {
		log.Logger.Err("Add SP: Error: already exists: %v", sp.Name)
	}

	value := &spd.SPValue{
		SPSelector: spd.SPSelector{},
	}

	if err := vSP2SPv(sp, value); err != nil {
		log.Logger.Err("Add SP: Error: %v", err)
		return
	}

	value.VRFIndex = vrf.Index()
	value.State = spd.Completed

	if _, err := mgr.AddSP(value.Direction,
		&value.SPSelector,
		value); err != nil {
		log.Logger.Err("Add SP: Error: %v", err)
		return
	}
	db[sp.Name] = value
}

// no lock.
func deleteSPNoLock(vrf *vswitch.VRF, sp *vswitch.SP) {
	log.Logger.Info("Delete SP: %v", sp)

	if spv, ok := db[sp.Name]; ok {
		mgr.DeleteSP(spv.Direction, &spv.SPSelector)
		delete(db, sp.Name)
	} else {
		log.Logger.Err("Delete SP: Error: not found: %v", sp.Name)
	}
}

// no lock.
func updateSPNoLock(vrf *vswitch.VRF, sp *vswitch.SP) {
	log.Logger.Info("Update SP: %v", sp)

	if spv, ok := db[sp.Name]; ok {
		value := &spd.SPValue{
			SPSelector: spd.SPSelector{},
		}
		if err := vSP2SPv(sp, value); err != nil {
			log.Logger.Err("Update SP: Error: %v", err)
			return
		}

		if (spv.Direction != value.Direction) ||
			spv.SPSelector.Modified(value.SPSelector) {
			// Update selector.
			deleteSPNoLock(vrf, sp)
			addSPNoLock(vrf, sp)
		} else {
			value.State = spd.Completed
			if err := mgr.UpdateSP(value.Direction,
				&value.SPSelector,
				value); err != nil {
				log.Logger.Err("Update SP: Error: %v", err)
				return
			}
			*spv = *value
		}
	} else {
		log.Logger.Err("Update SP: Error: not found: %v", sp.Name)
	}
}

// public.

// AddSP Addd SP.
func AddSP(vrf *vswitch.VRF, sp *vswitch.SP) {
	lock.Lock()
	defer lock.Unlock()

	addSPNoLock(vrf, sp)
}

// DeleteSP Delete SP.
func DeleteSP(vrf *vswitch.VRF, sp *vswitch.SP) {
	lock.Lock()
	defer lock.Unlock()

	deleteSPNoLock(vrf, sp)
}

// UpdateSP Update SP.
func UpdateSP(vrf *vswitch.VRF, sp *vswitch.SP) {
	lock.Lock()
	defer lock.Unlock()

	updateSPNoLock(vrf, sp)
}
