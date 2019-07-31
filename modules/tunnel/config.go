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

package tunnel

import (
	"sync"

	"github.com/lagopus/vsw/modules/tunnel/vxlan"
	"github.com/lagopus/vsw/vswitch"
)

var configLock sync.Mutex
var configs *ModuleConfigs

// ModuleConfigs Config of tunnel modules.
type ModuleConfigs struct {
	// Tunnel config
	Tunnels map[string]*ModuleConfig `toml:"tunnel"`
}

func newModuleConfigs() *ModuleConfigs {
	return &ModuleConfigs{
		Tunnels: make(map[string]*ModuleConfig),
	}
}

// ModuleConfig Config of tunnel module.
type ModuleConfig struct {
	// CoreBind
	CoreBind bool `toml:"core_bind"`
	// InboundCore
	InboundCore uint `toml:"inbound_core"`
	// OutboundCore
	OutboundCore uint `toml:"outbound_core"`
	// InboundCoreMask
	InboundCoreMask uint `toml:"inbound_core_mask"`
	// OutboundCoreMask
	OutboundCoreMask uint   `toml:"outbound_core_mask"`
	AgingTime        uint64 `toml:"aging_time"`
	RuleFile         string `toml:"rule_file"`
}

func newModuleConfig() *ModuleConfig {
	return &ModuleConfig{
		CoreBind:         defaultCoreBind,
		InboundCore:      defaultInboundCore,
		OutboundCore:     defaultOutboundCore,
		InboundCoreMask:  defaultInboundCoreMask,
		OutboundCoreMask: defaultOutboundCoreMask,
		AgingTime:        vxlan.DefaultAgingTime,
		RuleFile:         defaultRuleFile,
	}
}

// GetModuleConfig Get ModuleConfig.
func GetModuleConfig(p ProtocolType) (*ModuleConfig, error) {
	configLock.Lock()
	defer configLock.Unlock()

	if configs == nil {
		configs = newModuleConfigs()
		configs.Tunnels[IPsec.String()] = newModuleConfig()
		configs.Tunnels[IPIP.String()] = newModuleConfig()
		configs.Tunnels[GRE.String()] = newModuleConfig()
		configs.Tunnels[L2GRE.String()] = newModuleConfig()
		configs.Tunnels[VXLAN.String()] = newModuleConfig()

		_, configErr := vswitch.GetConfig().Decode(configs)
		if configErr != nil {
			return nil, configErr
		}
	}

	return configs.Tunnels[p.String()], nil
}
