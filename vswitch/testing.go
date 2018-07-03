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

import "github.com/lagopus/vsw/dpdk"

// TestInstance is to test modules indvidually.
// Only test codes shall use this.
type TestInstance BaseInstance

// NewTestModule instantiate the specified instance directly.
// Returns non-nil *TestInstance on success.
// Non-nil error is returned otherwise.
func NewTestModule(moduleName, name string, private interface{}) (*TestInstance, error) {
	b, e := newInstance(moduleName, name, private)
	return (*TestInstance)(b), e
}

// Enable enables the instance.
// Returns non-nil error on failure.
func (t *TestInstance) Enable() error {
	return (*BaseInstance)(t).enable()
}

// Disable disables the instance.
func (t *TestInstance) Disable() {
	(*BaseInstance)(t).disable()
}

// Free frees the instance.
func (t *TestInstance) Free() {
	(*BaseInstance)(t).free()
}

func (t *TestInstance) Instance() interface{} {
	return (*BaseInstance)(t).instance
}

func (t *TestInstance) Input() *dpdk.Ring {
	return (*BaseInstance)(t).input
}

func (t *TestInstance) Connect(dst *dpdk.Ring, m VswMatch, p interface{}) error {
	return (*BaseInstance)(t).connect(dst, m, p)
}

// AddVIF adds VIF to the instance.
// Internally, a rule MATCH_OUT_VIF to the VIF is added to the instance,
// and the VIF's default output is set to the instance.
// Also a rule MATCH_IN_VIF is added, if dedicated VIF.Inbound() is found.
// Returns non-nil error on failure.
func (t *TestInstance) AddVIF(vif *VIF) error {
	b := (*BaseInstance)(t)
	if err := b.connect(vif.Outbound(), MATCH_OUT_VIF, vif); err != nil {
		return err
	}
	if vif.Inbound() != vif.Outbound() {
		if err := b.connect(vif.Inbound(), MATCH_IN_VIF, vif); err != nil {
			b.disconnect(MATCH_OUT_VIF, vif)
			return err
		}
	}
	if err := vif.setOutput(b.input); err != nil {
		b.disconnect(MATCH_OUT_VIF, vif)
		b.disconnect(MATCH_IN_VIF, vif)
		return err
	}

	return nil
}
