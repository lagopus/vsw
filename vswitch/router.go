//
// Copyright 2018 Nippon Telegraph and Telephone Corporation.
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
	"errors"
	"fmt"

	"github.com/lagopus/vsw/dpdk"
)

type RouterInstance interface {
	AddVIF(*VIF) error
	DeleteVIF(*VIF) error
}

type router struct {
	vrf      *VRF
	instance RouterInstance
	base     *BaseInstance
}

func newRouter(vrf *VRF, name string) (*router, error) {
	if routerModuleName == "" {
		return nil, errors.New("Can't find router module")
	}

	base, err := newInstance(routerModuleName, name, vrf)
	if err != nil {
		return nil, err
	}

	instance, ok := base.instance.(RouterInstance)
	if !ok {
		return nil, fmt.Errorf("Not router module: %s", routerModuleName)
	}

	return &router{
		vrf:      vrf,
		instance: instance,
		base:     base,
	}, nil
}

func (r *router) free() {
	r.base.free()
}

func (r *router) enable() error {
	return r.base.enable()
}

func (r *router) disable() {
	r.base.disable()
}

func (r *router) input() *dpdk.Ring {
	return r.base.input
}

func (r *router) connect(dst *dpdk.Ring, match VswMatch, param interface{}) error {
	return r.base.connect(dst, match, param)
}

func (r *router) disconnect(match VswMatch, param interface{}) error {
	return r.base.disconnect(match, param)
}

func (r *router) addVIF(vif *VIF) error {
	// XXX: We may want to use MATCH_OUT_VIF rule.
	if err := r.instance.AddVIF(vif); err != nil {
		return err
	}

	// XXX: We should use BaseInstance.connect() (same for bridge)
	if vif.Output() == nil {
		if err := vif.setOutput(r.base.input); err != nil {
			r.instance.DeleteVIF(vif)
			return err
		}
	}

	// For IP Tunnel
	if t := vif.Tunnel(); t != nil {
		// Forward inbound packets to VIF
		if err := r.base.connect(vif.Inbound(), MATCH_IPV4_PROTO, t.IPProto()); err != nil {
			vif.setOutput(nil)
			r.instance.DeleteVIF(vif)
			return err
		}
	}

	return nil
}

func (r *router) deleteVIF(vif *VIF) {
	r.instance.DeleteVIF(vif)

	// For IP Tunnel
	if t := vif.Tunnel(); t != nil {
		r.disconnect(MATCH_IPV4_PROTO, t.IPProto())

		// XXX: We should use BaseInstance.disconnect() (same for bridge)
		vif.setOutput(nil)
	}
}
