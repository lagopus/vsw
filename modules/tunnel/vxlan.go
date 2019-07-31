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

// #include "l2tun.h"
import "C"

import (
	"unsafe"

	"github.com/lagopus/vsw/modules/tunnel/vxlan"
)

// VXLANTunnelIF Interface for VXLAN.
type VXLANTunnelIF struct {
	*l2TunnelIF
}

func newVXLANTunnelIF(accessor ifParamAccessor) concreteIF {
	vxlanIF := &VXLANTunnelIF{
		l2TunnelIF: newL2TunnelIF(accessor),
	}
	return vxlanIF
}

// Enable Enable interface.
func (i *VXLANTunnelIF) Enable() error {
	mgr := vxlan.GetMgr()

	var conf *ModuleConfig
	var err error
	if conf, err = GetModuleConfig(VXLAN); err != nil {
		return err
	}

	// callback func (doControlInbound).
	fn := func(p *vxlan.ControlParam) error {
		return i.doControlInbound((*C.struct_l2tun_control_param)(unsafe.Pointer(p)))
	}
	vni := i.l2TunnelIF.l2tunnel.VNI()
	if err := mgr.NewFDB(vxlan.VNI(vni), conf.AgingTime, fn); err != nil {
		return err
	}

	return i.l2TunnelIF.Enable()
}

// Disable Disable interface.
func (i *VXLANTunnelIF) Disable() {
	mgr := vxlan.GetMgr()

	vni := i.l2TunnelIF.l2tunnel.VNI()
	mgr.DeleteFDB(vxlan.VNI(vni))
	i.l2TunnelIF.Disable()
}

func newVXLANConcreteIF(accessor ifParamAccessor) (concreteIF, error) {
	return newVXLANTunnelIF(accessor), nil
}
