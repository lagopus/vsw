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
	"testing"

	"github.com/lagopus/vsw/vswitch"
	"github.com/stretchr/testify/suite"
)

var (
	mgr *mockMgr
)

type testIPsecTestSuite struct {
	suite.Suite
}

func (suite *testIPsecTestSuite) SetupTest() {
	mgr = newMockMgr(suite)
	a := &Accessor{
		SetVRFFn:     mgr.SetVRF,
		UnsetVRFFn:   mgr.UnsetVRF,
		SetRingFn:    mgr.SetRing,
		UnsetRingFn:  mgr.UnsetRing,
		SetTTLFn:     mgr.SetTTL,
		SetTOSFn:     mgr.SetTOS,
		StatsFn:      mgr.Stats,
		ResetStatsFn: mgr.ResetStats,
	}
	RegisterAccessor(a)
	suite.NotNil(accessor.SetVRFFn)
	suite.NotNil(accessor.UnsetVRFFn)
	suite.NotNil(accessor.SetRingFn)
	suite.NotNil(accessor.UnsetRingFn)
	suite.NotNil(accessor.SetTTLFn)
	suite.NotNil(accessor.SetTOSFn)
	suite.NotNil(accessor.StatsFn)
	suite.NotNil(accessor.ResetStatsFn)
}

func (suite *testIPsecTestSuite) TearDownTest() {
	RegisterAccessor(&Accessor{})
	suite.Nil(accessor.SetVRFFn)
	suite.Nil(accessor.UnsetVRFFn)
	suite.Nil(accessor.SetRingFn)
	suite.Nil(accessor.UnsetRingFn)
	suite.Nil(accessor.SetTTLFn)
	suite.Nil(accessor.SetTOSFn)
	suite.Nil(accessor.StatsFn)
	suite.Nil(accessor.ResetStatsFn)
}

func newTestVIF() *VIF {
	return &VIF{
		VIF: &vswitch.VIF{},
	}
}

func newTestTunnelIF(isEnabled bool) *TunnelIF {
	for _, direction := range directions {
		modules[direction] = &Module{
			running: true, /* not call C plane. */
		}
	}

	return &TunnelIF{
		name:      "test",
		isEnabled: isEnabled,
	}
}

func newTestTunnelVIF(tif *TunnelIF, vif *VIF, isEnabled bool) *TunnelVIF {
	tvif := &TunnelVIF{
		tif:       tif,
		vif:       vif,
		isEnabled: isEnabled,
	}
	if tif != nil {
		tif.tvif = tvif
	}
	return tvif
}

// TunnelIF

func (suite *testIPsecTestSuite) TestTunnelIFNewVIF() {
	tif := &TunnelIF{
		name: "test",
	}

	// new VIF - OK.
	v := &vswitch.VIF{}
	vif, err := tif.NewVIF(v)
	suite.Empty(err)
	suite.NotEmpty(vif)
}

func (suite *testIPsecTestSuite) TestTunnelIFNewVIFErr() {
	tif := &TunnelIF{
		name: "test",
	}

	// new VIF - ERROR - VIF is nul.
	_, err := tif.NewVIF(nil)
	suite.NotEmpty(err)

	// new VIF - OK.
	v := &vswitch.VIF{}
	vif, err := tif.NewVIF(v)
	suite.Empty(err)
	suite.NotEmpty(vif)

	// new VIF - ERROR - already exists
	_, err = tif.NewVIF(v)
	suite.NotEmpty(err)
}

func (suite *testIPsecTestSuite) TestTunnelIFEnable() {
	tif := newTestTunnelIF(false)
	vif := newTestVIF()
	_ = newTestTunnelVIF(tif, vif, true)

	// enable (call many times) - OK.
	for i := 0; i < 10; i++ {
		err := tif.Enable()
		suite.Empty(err)
		suite.True(tif.isEnabled)
		mgr.EqualCountCallSetRing(1)
		mgr.EqualCountCallUnsetRing(0)
	}
}

func (suite *testIPsecTestSuite) TestTunnelIFEnableNil() {
	// TunnelVIF is nil.
	tif := newTestTunnelIF(false)

	// enable - OK.
	err := tif.Enable()
	suite.Empty(err)
	suite.True(tif.isEnabled)
	mgr.EqualCountCallSetRing(0)
	mgr.EqualCountCallUnsetRing(0)
}

func (suite *testIPsecTestSuite) TestTunnelIFDisable() {
	tif := newTestTunnelIF(true)
	vif := newTestVIF()
	_ = newTestTunnelVIF(tif, vif, true)

	// disable (call many times) - OK.
	for i := 0; i < 10; i++ {
		tif.Disable()
		suite.False(tif.isEnabled)
		mgr.EqualCountCallSetRing(0)
		mgr.EqualCountCallUnsetRing(1)
	}
}

func (suite *testIPsecTestSuite) TestTunnelIFDisableNil() {
	// TunnelVIF is nil.
	tif := newTestTunnelIF(true)

	// disable - OK.
	tif.Disable()
	suite.False(tif.isEnabled)
	mgr.EqualCountCallSetRing(0)
	mgr.EqualCountCallUnsetRing(0)
}

func (suite *testIPsecTestSuite) TestTunnelIFFree() {
	tif := newTestTunnelIF(true)
	vif := newTestVIF()
	tvif := newTestTunnelVIF(tif, vif, true)

	// Free - OK.
	tif.Free()
	suite.False(tif.isEnabled)
	mgr.EqualCountCallSetRing(0)
	mgr.EqualCountCallUnsetRing(1)
	suite.Empty(tif.tvif)
	suite.Empty(tvif.tif)
}

// TunnelVIF

func (suite *testIPsecTestSuite) TestTunnelVIFEnable() {
	tif := newTestTunnelIF(true)
	vif := newTestVIF()
	tvif := newTestTunnelVIF(tif, vif, false)

	// enable (call many times) - OK.
	for i := 0; i < 10; i++ {
		err := tvif.Enable()
		suite.Empty(err)
		suite.True(tvif.isEnabled)
		mgr.EqualCountCallSetRing(1)
		mgr.EqualCountCallUnsetRing(0)
	}
}

func (suite *testIPsecTestSuite) TestTunnelVIFEnableNil() {
	_ = newTestTunnelIF(true)
	vif := newTestVIF()
	// TunnelIF is nil.
	tvif := newTestTunnelVIF(nil, vif, false)

	// enable - OK.
	err := tvif.Enable()
	suite.Empty(err)
	suite.True(tvif.isEnabled)
	mgr.EqualCountCallSetRing(0)
	mgr.EqualCountCallUnsetRing(0)
}

func (suite *testIPsecTestSuite) TestTunnelVIFDisable() {
	tif := newTestTunnelIF(true)
	vif := newTestVIF()
	tvif := newTestTunnelVIF(tif, vif, true)

	// disable (call many times) - OK.
	for i := 0; i < 10; i++ {
		tvif.Disable()
		suite.False(tvif.isEnabled)
		mgr.EqualCountCallSetRing(0)
		mgr.EqualCountCallUnsetRing(1)
	}
}

func (suite *testIPsecTestSuite) TestTunnelVIFDisableNil() {
	_ = newTestTunnelIF(true)
	vif := newTestVIF()
	// TunnelIF is nil.
	tvif := newTestTunnelVIF(nil, vif, true)

	// disable - OK.
	tvif.Disable()
	suite.False(tvif.isEnabled)
	mgr.EqualCountCallSetRing(0)
	mgr.EqualCountCallUnsetRing(0)
}

func (suite *testIPsecTestSuite) TestTunnelVIFFree() {
	tif := newTestTunnelIF(true)
	vif := newTestVIF()
	tvif := newTestTunnelVIF(tif, vif, true)

	// free.
	tvif.Free()
	suite.False(tvif.isEnabled)
	mgr.EqualCountCallSetRing(0)
	mgr.EqualCountCallUnsetRing(1)
	suite.Empty(tif.tvif)
	suite.Empty(tvif.tif)
}

func (suite *testIPsecTestSuite) TestTunnelVIFSetVRF() {
	tif := newTestTunnelIF(true)
	vif := newTestVIF()
	tvif := newTestTunnelVIF(tif, vif, true)

	vrf := &vswitch.VRF{} // VRFIndex is 0.
	mgr.expectedVRF = vrf

	// set VRF - OK.
	tvif.SetVRF(vrf)
	suite.Equal(vrf, tvif.vrf)
	mgr.EqualCountCallSetVRF(1)
	mgr.EqualCountCallUnsetVRF(0)
}

func (suite *testIPsecTestSuite) TestTunnelVIFSetVRFNil() {
	tif := newTestTunnelIF(true)
	vif := newTestVIF()
	tvif := newTestTunnelVIF(tif, vif, true)

	tvif.vrf = &vswitch.VRF{} // VRFIndex is 0.
	mgr.expectedVRF = tvif.vrf

	// set VRF - OK.
	tvif.SetVRF(nil)
	suite.Empty(tvif.vrf)
	mgr.EqualCountCallSetVRF(0)
	mgr.EqualCountCallUnsetVRF(1)
}

func (suite *testIPsecTestSuite) TestTunnelVIFSetVRFNothingIF() {
	vif := newTestVIF()
	// TunnelIF is nil.
	tvif := newTestTunnelVIF(nil, vif, true)

	vrf := &vswitch.VRF{}

	// set VRF - ERROR.
	tvif.SetVRF(vrf)
	mgr.EqualCountCallSetVRF(0)
	mgr.EqualCountCallUnsetVRF(0)
}

func (suite *testIPsecTestSuite) TestTunnelVIFHopLimitUpdated() {
	tif := newTestTunnelIF(true)
	vif := newTestVIF()
	tvif := newTestTunnelVIF(tif, vif, true)
	ttl := uint8(100)
	mgr.expectedTTL = ttl

	// set TTL - OK.
	tvif.HopLimitUpdated(ttl)
	mgr.EqualCountCallSetTTL(1)
}

func (suite *testIPsecTestSuite) TestTunnelVIFHopLimitUpdatedNothingIF() {
	vif := newTestVIF()
	// TunnelIF is nil.
	tvif := newTestTunnelVIF(nil, vif, true)
	ttl := uint8(100)

	// set TTL - ERROR.
	tvif.HopLimitUpdated(ttl)
	mgr.EqualCountCallSetTTL(0)
}

func (suite *testIPsecTestSuite) TestTunnelVIFTOSUpdated() {
	tif := newTestTunnelIF(true)
	vif := newTestVIF()
	tvif := newTestTunnelVIF(tif, vif, true)
	tos := int8(100)
	mgr.expectedTOS = tos

	// set TOS - OK.
	tvif.L3TOSUpdated(tos)
	mgr.EqualCountCallSetTOS(1)
}

func (suite *testIPsecTestSuite) TestTunnelVIFTOSUpdatedNothingIF() {
	vif := newTestVIF()
	// TunnelIF is nil.
	tvif := newTestTunnelVIF(nil, vif, true)
	tos := int8(100)

	// set TOS - ERROR.
	tvif.L3TOSUpdated(tos)
	mgr.EqualCountCallSetTOS(0)
}

var testSuite *testIPsecTestSuite

func TestIPsecTestSuites(t *testing.T) {
	testSuite = new(testIPsecTestSuite)
	suite.Run(t, testSuite)
}
