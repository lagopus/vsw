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

package ipsec

import (
	"fmt"
	"sync"

	"github.com/lagopus/vsw/agents/tunnel/ipsec/config"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/handlers"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/handlers/openconfigd"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/handlers/pfkey"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/ifaces"
	"github.com/lagopus/vsw/modules/tunnel"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/modules/tunnel/log"
	"github.com/lagopus/vsw/vswitch"
)

const (
	// AgentName Name of IPsec agent.
	AgentName = "ipsec"
)

func init() {
	// Register agent.
	a := &agent{
		name:      AgentName,
		handlers:  map[*vswitch.VRF][]handlers.Handler{},
		ifacesMgr: ifaces.GetMgr(),
	}
	vswitch.RegisterAgent(a)

	// Register accessor.
	accessor := &ipsec.Accessor{
		SetVRFFn:     a.SetVRF,
		UnsetVRFFn:   a.UnsetVRF,
		SetRingFn:    a.SetRing,
		UnsetRingFn:  a.UnsetRing,
		SetTTLFn:     a.SetTTL,
		SetTOSFn:     a.SetTOS,
		StatsFn:      a.Stats,
		ResetStatsFn: a.ResetStats,
	}
	ipsec.RegisterAccessor(accessor)
}

type agent struct {
	name      string
	lock      sync.Mutex
	handlers  map[*vswitch.VRF][]handlers.Handler
	ifacesMgr *ifaces.Mgr
	isEnabled bool
}

// NOTE: no lock, need to lock it.
func (a *agent) addVRF(vrf *vswitch.VRF) error {
	if vrf == nil {
		return fmt.Errorf("%v: VRF is nil", a)
	}

	if _, ok := a.handlers[vrf]; ok {
		// ignore: already exists.
		return nil
	}
	handlers := []handlers.Handler{
		// NOTE: Add new handler here.
		pfkey.NewHandler(vrf),
		openconfigd.NewHandler(vrf),
	}
	a.handlers[vrf] = handlers

	for _, handler := range handlers {
		if err := handler.Start(); err != nil {
			return err
		}
	}

	return nil
}

// NOTE: no lock, need to lock it.
func (a *agent) deleteVRF(vrf *vswitch.VRF) {
	if handlers, ok := a.handlers[vrf]; ok {
		for _, handler := range handlers {
			handler.Stop()
		}
		delete(a.handlers, vrf)
	}
	// ignore: not found.
}

// NOTE: no lock, need to lock it.
func (a *agent) allDeleteVRFs() {
	for vrf := range a.handlers {
		a.deleteVRF(vrf)
	}
}

// Public.

func (a *agent) Init() error {
	log.Logger.Info("Init agent %v", a)

	var conf *tunnel.ModuleConfig
	var err error
	if conf, err = tunnel.GetModuleConfig(tunnel.IPsec); err != nil {
		return err
	}

	if len(conf.RuleFile) != 0 {
		// Parse config.
		rp := config.GetRootParser()
		err = rp.ParseConfigFile(conf.RuleFile)
		if err != nil {
			// ignore error.
			log.Logger.Info("%v: Ignore: %v", a, err)
		}
		log.Logger.Info("%v: Load config file: %v", a, conf.RuleFile)
	}

	log.Logger.Info("Supported %d cipher algos, %d auth algos, %d aead algos",
		len(ipsec.SupportedCipherAlgoByType),
		len(ipsec.SupportedAuthAlgoByType),
		len(ipsec.SupportedAeadAlgoByType))

	return nil
}

// Enable Enable for ipsec agent.
func (a *agent) Enable() error {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.isEnabled {
		log.Logger.Warning("Agent is already enabled")
		return nil
	}

	log.Logger.Info("Enable agent %v", a)
	a.isEnabled = true

	return nil
}

// Disable Disable for ipsec agent.
func (a *agent) Disable() {
	a.lock.Lock()
	defer a.lock.Unlock()

	if !a.isEnabled {
		log.Logger.Warning("Agent is already disabled")
		return
	}

	log.Logger.Info("Disable agent %v", a)
	a.isEnabled = false
	a.allDeleteVRFs()
}

// String Get name.
func (a *agent) String() string {
	return a.name
}

// SetVRF Set VRF.
func (a *agent) SetVRF(vifIndex vswitch.VIFIndex,
	vrf *vswitch.VRF) error {
	a.lock.Lock()
	defer a.lock.Unlock()

	if err := a.addVRF(vrf); err != nil {
		log.Logger.Err("%v: %v", a, err)
		return err
	}

	vrfIndex := vrf.Index()
	a.ifacesMgr.SetVRFIndex(vifIndex, &vrfIndex)

	return nil
}

// UnsetVRF Unset VRF.
func (a *agent) UnsetVRF(vifIndex vswitch.VIFIndex,
	vrf *vswitch.VRF) error {
	a.lock.Lock()
	defer a.lock.Unlock()

	a.deleteVRF(vrf)
	a.ifacesMgr.UnsetVRFIndex(vifIndex)

	return nil
}

// SetRing Set Ring.
func (a *agent) SetRing(vifIndex vswitch.VIFIndex, rings *ipsec.Rings) {
	a.lock.Lock()
	defer a.lock.Unlock()

	a.ifacesMgr.SetRing(vifIndex, rings)
}

// UnsetRing Unset ring.
func (a *agent) UnsetRing(vifIndex vswitch.VIFIndex) {
	a.lock.Lock()
	defer a.lock.Unlock()

	a.ifacesMgr.UnsetRing(vifIndex)
}

// SetTTL Set TTL.
func (a *agent) SetTTL(vifIndex vswitch.VIFIndex,
	ttl uint8) {
	a.lock.Lock()
	defer a.lock.Unlock()

	a.ifacesMgr.SetTTL(vifIndex, ttl)
}

// SetTOS Set TOS.
func (a *agent) SetTOS(vifIndex vswitch.VIFIndex,
	tos int8) {
	a.lock.Lock()
	defer a.lock.Unlock()

	a.ifacesMgr.SetTOS(vifIndex, tos)
}

// Stats Get stats.
func (a *agent) Stats(vifIndex vswitch.VIFIndex,
	direction ipsec.DirectionType) *ipsec.CIfaceStats {
	a.lock.Lock()
	defer a.lock.Unlock()

	return a.ifacesMgr.Stats(vifIndex, direction)
}

// ResetStats Reset stats.
func (a *agent) ResetStats(vifIndex vswitch.VIFIndex,
	direction ipsec.DirectionType) {
	a.lock.Lock()
	defer a.lock.Unlock()

	a.ifacesMgr.ResetStats(vifIndex, direction)
}
