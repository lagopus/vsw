//
// Copyright 2017 Nippon Telegraph and Telephone Corporation.
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
	"testing"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/vswitch"
	"github.com/stretchr/testify/suite"
)

type testIfaceMgrTestSuite struct {
	suite.Suite
}

func (suite *testIfaceMgrTestSuite) SetupTest() {
	ifaceMgr = newIfaceMgr()
	ifaceMgr.dbs[ipsec.DirectionTypeIn].cifaces = newMockCIfaces(suite)
	ifaceMgr.dbs[ipsec.DirectionTypeOut].cifaces = newMockCIfaces(suite)
}

func (suite *testIfaceMgrTestSuite) TearDownTest() {
	mgr := GetMgr()
	mgr.ClearIfaces()
}

func (suite *testIfaceMgrTestSuite) TestSetVRFIndex() {
	mgr := GetMgr()

	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
	}
	vifIndexes := []vswitch.VIFIndex{0, 1}

	// SetVRFIndex - OK.
	for _, vifIndex := range vifIndexes {
		expectedIface := newIface(vifIndex)
		expectedIface.VRFIndex = 1

		mgr.SetVRFIndex(vifIndex, 1)
		for _, direction := range directions {
			suite.True(mgr.dbs[direction].isModified)
			suite.Equal(mgr.dbs[direction].ifaces[vifIndex], expectedIface)
		}
	}
}

func (suite *testIfaceMgrTestSuite) TestSetUnsetRing() {
	mgr := GetMgr()

	vifIndexes := []vswitch.VIFIndex{0, 1}

	inputs := map[ipsec.DirectionType]*dpdk.Ring{
		ipsec.DirectionTypeIn:  &dpdk.Ring{},
		ipsec.DirectionTypeOut: &dpdk.Ring{},
	}
	output := &dpdk.Ring{}

	// SetRing - OK.
	for _, vifIndex := range vifIndexes {
		expectedIface := newIface(vifIndex)
		expectedIface.Output = output
		rings := ipsec.NewRings(inputs[ipsec.DirectionTypeIn],
			inputs[ipsec.DirectionTypeOut], output)

		mgr.SetRing(vifIndex, rings)
		for direction, input := range inputs {
			expectedIface.Input = input
			suite.Equal(mgr.dbs[direction].ifaces[vifIndex], expectedIface)
			suite.True(mgr.dbs[direction].isModified)
		}
	}

	// Reset isModified flags.
	for direction := range inputs {
		mgr.dbs[direction].isModified = false
	}

	// UnsetRing - OK.
	for _, vifIndex := range vifIndexes {
		expectedIface := newIface(vifIndex)
		expectedIface.Input = nil
		expectedIface.Output = nil

		mgr.UnsetRing(vifIndex)
		for direction := range inputs {
			suite.Equal(mgr.dbs[direction].ifaces[vifIndex], expectedIface)
			suite.True(mgr.dbs[direction].isModified)
		}
	}
}

func (suite *testIfaceMgrTestSuite) TestSetTTL() {
	mgr := GetMgr()

	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
	}
	vifIndexes := []vswitch.VIFIndex{0, 1}

	// SetTTL - OK.
	for _, vifIndex := range vifIndexes {
		expectedIface := newIface(vifIndex)
		expectedIface.TTL = 1

		mgr.SetTTL(vifIndex, 1)
		for _, direction := range directions {
			suite.True(mgr.dbs[direction].isModified)
			suite.Equal(mgr.dbs[direction].ifaces[vifIndex], expectedIface)
		}
	}
}

func (suite *testIfaceMgrTestSuite) TestSetTOS() {
	mgr := GetMgr()

	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
	}
	vifIndexes := []vswitch.VIFIndex{0, 1}

	// SetTOS - OK.
	for _, vifIndex := range vifIndexes {
		expectedIface := newIface(vifIndex)
		expectedIface.TOS = 1

		mgr.SetTOS(vifIndex, 1)
		for _, direction := range directions {
			suite.True(mgr.dbs[direction].isModified)
			suite.Equal(mgr.dbs[direction].ifaces[vifIndex], expectedIface)
		}
	}
}

func (suite *testIfaceMgrTestSuite) TestPushIfaces() {
	mgr := GetMgr()

	vifIndexes := []vswitch.VIFIndex{0, 1}

	inputs := map[ipsec.DirectionType]*dpdk.Ring{
		ipsec.DirectionTypeIn:  &dpdk.Ring{},
		ipsec.DirectionTypeOut: &dpdk.Ring{},
	}
	output := &dpdk.Ring{}

	// SetRing.
	for _, vifIndex := range vifIndexes {
		expectedIface := newIface(vifIndex)
		expectedIface.Output = output
		rings := ipsec.NewRings(inputs[ipsec.DirectionTypeIn],
			inputs[ipsec.DirectionTypeOut], output)

		mgr.SetRing(vifIndex, rings)
		for direction, input := range inputs {
			expectedIface.Input = input
			suite.Equal(mgr.dbs[direction].ifaces[vifIndex], expectedIface)
			suite.True(mgr.dbs[direction].isModified)
		}
	}

	// push - OK.
	err := mgr.push()
	suite.Empty(err)
	for direction := range inputs {
		suite.False(mgr.dbs[direction].isModified)
		cif := mgr.dbs[direction].cifaces.(*mockCIfaces)
		cif.EqualCountPushIfaces(1)
	}
}

func (suite *testIfaceMgrTestSuite) TestPushIfacesErr() {
	mgr := GetMgr()

	vifIndexes := []vswitch.VIFIndex{0, 1}

	inputs := map[ipsec.DirectionType]*dpdk.Ring{
		ipsec.DirectionTypeIn:  &dpdk.Ring{},
		ipsec.DirectionTypeOut: &dpdk.Ring{},
	}
	output := &dpdk.Ring{}

	// set mock for err.
	for direction := range inputs {
		mgr.dbs[direction].cifaces = newMockCIfacesErr(suite)
	}

	// SetRing.
	for _, vifIndex := range vifIndexes {
		expectedIface := newIface(vifIndex)
		expectedIface.Output = output
		rings := ipsec.NewRings(inputs[ipsec.DirectionTypeIn],
			inputs[ipsec.DirectionTypeOut], output)

		mgr.SetRing(vifIndex, rings)
		for direction, input := range inputs {
			expectedIface.Input = input
			suite.Equal(mgr.dbs[direction].ifaces[vifIndex], expectedIface)
			suite.True(mgr.dbs[direction].isModified)
		}
	}

	// push - ERR.
	err := mgr.push()
	suite.NotEmpty(err)
}

var testSuite *testIfaceMgrTestSuite

func TestIfaceMgrTestSuites(t *testing.T) {
	testSuite = new(testIfaceMgrTestSuite)
	suite.Run(t, testSuite)
}
