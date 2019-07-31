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
	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/vswitch"
)

// mock.

type mockMgr struct {
	suite              *testIPsecTestSuite
	countCallSetVRF    uint64
	countCallUnsetVRF  uint64
	countCallSetRing   uint64
	countCallUnsetRing uint64
	countCallSetTTL    uint64
	countCallSetTOS    uint64
	countCallStats     uint64
	expectedVRF        *vswitch.VRF
	expectedTTL        uint8
	expectedTOS        int8
}

func newMockMgr(suite *testIPsecTestSuite) *mockMgr {
	return &mockMgr{
		suite: suite,
	}
}

func (m *mockMgr) SetVRF(vifIndex vswitch.VIFIndex,
	vrf *vswitch.VRF) error {
	m.suite.Equal(m.expectedVRF, vrf)
	m.countCallSetVRF++
	return nil
}

func (m *mockMgr) UnsetVRF(vifIndex vswitch.VIFIndex,
	vrf *vswitch.VRF) error {
	m.suite.Equal(m.expectedVRF, vrf)
	m.countCallUnsetVRF++
	return nil
}

func (m *mockMgr) SetRing(vifIndex vswitch.VIFIndex,
	rings *Rings) {
	m.countCallSetRing++
}

func (m *mockMgr) UnsetRing(vifIndex vswitch.VIFIndex) {
	m.countCallUnsetRing++
}

func (m *mockMgr) SetTTL(vifIndex vswitch.VIFIndex,
	ttl uint8) {
	m.suite.Equal(m.expectedTTL, ttl)
	m.countCallSetTTL++
}

func (m *mockMgr) SetTOS(vifIndex vswitch.VIFIndex,
	tos int8) {
	m.suite.Equal(m.expectedTOS, tos)
	m.countCallSetTOS++
}

func (m *mockMgr) Stats(vifIndex vswitch.VIFIndex,
	direction DirectionType) *CIfaceStats {
	m.countCallStats++
	return &CIfaceStats{}
}

func (m *mockMgr) ResetStats(vifIndex vswitch.VIFIndex,
	direction DirectionType) {
}

func (m *mockMgr) EqualCountCallSetVRF(count uint64) {
	m.suite.Equal(count, m.countCallSetVRF)
}

func (m *mockMgr) EqualCountCallUnsetVRF(count uint64) {
	m.suite.Equal(count, m.countCallUnsetVRF)
}

func (m *mockMgr) EqualCountCallSetRing(count uint64) {
	m.suite.Equal(count, m.countCallSetRing)
}

func (m *mockMgr) EqualCountCallUnsetRing(count uint64) {
	m.suite.Equal(count, m.countCallUnsetRing)
}

func (m *mockMgr) EqualCountCallSetTTL(count uint64) {
	m.suite.Equal(count, m.countCallSetTTL)
}

func (m *mockMgr) EqualCountCallSetTOS(count uint64) {
	m.suite.Equal(count, m.countCallSetTOS)
}

// mock functions for VIF.
func (v *VIF) Input() *dpdk.Ring {
	return &dpdk.Ring{}
}

func (v *VIF) Inbound() *dpdk.Ring {
	return &dpdk.Ring{}
}

func (v *VIF) Outbound() *dpdk.Ring {
	return &dpdk.Ring{}
}

func (v *VIF) Output() *dpdk.Ring {
	return &dpdk.Ring{}
}

func (v *VIF) Tunnel() *MockTunnel {
	return &MockTunnel{}
}

func (v *VIF) Rules() *MockRules {
	return &MockRules{}
}

// mock for Rules.
type MockRules struct {
	vswitch.Rules
}

func (r *MockRules) Output(match vswitch.VswMatch) *dpdk.Ring {
	return &dpdk.Ring{}
}

// mock for MockTunnel.
type MockTunnel struct {
}

func (t *MockTunnel) HopLimit() uint8 {
	return 0
}

func (t *MockTunnel) TOS() int8 {
	return 0
}
