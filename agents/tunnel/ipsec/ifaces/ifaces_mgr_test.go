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
		vrfIndex := vswitch.VRFIndex(1)
		expectedIface.VRFIndex = &vrfIndex

		mgr.SetVRFIndex(vifIndex, &vrfIndex)
		for _, direction := range directions {
			suite.True(mgr.dbs[direction].isModified)
			suite.Equal(mgr.dbs[direction].ifaces[vifIndex], expectedIface)
		}
	}
}

func (suite *testIfaceMgrTestSuite) TestUnsetVRFIndex() {
	mgr := GetMgr()

	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
	}
	vifIndexes := []vswitch.VIFIndex{0, 1}

	// UnsetVRFIndex - OK.
	for _, vifIndex := range vifIndexes {
		expectedIface := newIface(vifIndex)
		expectedIface.VRFIndex = nil

		mgr.UnsetVRFIndex(vifIndex)
		for _, direction := range directions {
			suite.True(mgr.dbs[direction].isModified)
			suite.Equal(mgr.dbs[direction].ifaces[vifIndex], expectedIface)
		}
	}
}

func (suite *testIfaceMgrTestSuite) TestSetUnsetRing() {
	mgr := GetMgr()

	vifIndexes := []vswitch.VIFIndex{0, 1}

	rings := map[ipsec.DirectionType][2]*dpdk.Ring{
		ipsec.DirectionTypeIn: [2]*dpdk.Ring{
			&dpdk.Ring{},
			&dpdk.Ring{},
		},
		ipsec.DirectionTypeOut: [2]*dpdk.Ring{
			&dpdk.Ring{},
			&dpdk.Ring{},
		},
	}

	// SetRing - OK.
	for _, vifIndex := range vifIndexes {
		expectedIface := newIface(vifIndex)
		rs := ipsec.NewRings(
			rings[ipsec.DirectionTypeIn][0],
			rings[ipsec.DirectionTypeOut][0],
			rings[ipsec.DirectionTypeIn][1],
			rings[ipsec.DirectionTypeOut][1],
		)

		mgr.SetRing(vifIndex, rs)
		for direction, ring := range rings {
			expectedIface.Input = ring[0]
			expectedIface.Output = ring[1]
			suite.Equal(mgr.dbs[direction].ifaces[vifIndex], expectedIface)
			suite.True(mgr.dbs[direction].isModified)
		}
	}

	// Reset isModified flags.
	for direction := range rings {
		mgr.dbs[direction].isModified = false
	}

	// UnsetRing - OK.
	for _, vifIndex := range vifIndexes {
		expectedIface := newIface(vifIndex)
		expectedIface.Input = nil
		expectedIface.Output = nil

		mgr.UnsetRing(vifIndex)
		for direction := range rings {
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

	rings := map[ipsec.DirectionType][2]*dpdk.Ring{
		ipsec.DirectionTypeIn: [2]*dpdk.Ring{
			&dpdk.Ring{},
			&dpdk.Ring{},
		},
		ipsec.DirectionTypeOut: [2]*dpdk.Ring{
			&dpdk.Ring{},
			&dpdk.Ring{},
		},
	}

	// SetRing.
	for _, vifIndex := range vifIndexes {
		expectedIface := newIface(vifIndex)
		rs := ipsec.NewRings(
			rings[ipsec.DirectionTypeIn][0],
			rings[ipsec.DirectionTypeOut][0],
			rings[ipsec.DirectionTypeIn][1],
			rings[ipsec.DirectionTypeOut][1],
		)

		mgr.SetRing(vifIndex, rs)
		for direction, ring := range rings {
			expectedIface.Input = ring[0]
			expectedIface.Output = ring[1]
			suite.Equal(mgr.dbs[direction].ifaces[vifIndex], expectedIface)
			suite.True(mgr.dbs[direction].isModified)
		}
	}

	// push - OK.
	err := mgr.push()
	suite.Empty(err)
	for direction := range rings {
		suite.False(mgr.dbs[direction].isModified)
		cif := mgr.dbs[direction].cifaces.(*mockCIfaces)
		cif.EqualCountPushIfaces(1)
	}
}

func (suite *testIfaceMgrTestSuite) TestPushIfacesErr() {
	mgr := GetMgr()

	vifIndexes := []vswitch.VIFIndex{0, 1}

	rings := map[ipsec.DirectionType][2]*dpdk.Ring{
		ipsec.DirectionTypeIn: [2]*dpdk.Ring{
			&dpdk.Ring{},
			&dpdk.Ring{},
		},
		ipsec.DirectionTypeOut: [2]*dpdk.Ring{
			&dpdk.Ring{},
			&dpdk.Ring{},
		},
	}

	// set mock for err.
	for direction := range rings {
		mgr.dbs[direction].cifaces = newMockCIfacesErr(suite)
	}

	// SetRing.
	for _, vifIndex := range vifIndexes {
		expectedIface := newIface(vifIndex)
		rs := ipsec.NewRings(
			rings[ipsec.DirectionTypeIn][0],
			rings[ipsec.DirectionTypeOut][0],
			rings[ipsec.DirectionTypeIn][1],
			rings[ipsec.DirectionTypeOut][1],
		)

		mgr.SetRing(vifIndex, rs)
		for direction, ring := range rings {
			expectedIface.Input = ring[0]
			expectedIface.Output = ring[1]
			suite.Equal(mgr.dbs[direction].ifaces[vifIndex], expectedIface)
			suite.True(mgr.dbs[direction].isModified)
		}
	}

	// push - ERR.
	err := mgr.push()
	suite.NotEmpty(err)
}

func (suite *testIfaceMgrTestSuite) TestStats() {
	mgr := GetMgr()

	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
	}

	vifIndex := vswitch.VIFIndex(1)

	// SetVRFIndex.
	vrfIndex := vswitch.VRFIndex(1)
	mgr.SetVRFIndex(vifIndex, &vrfIndex)

	// stats - OK.
	for _, direction := range directions {
		stats := mgr.Stats(vifIndex, direction)
		suite.Equal(newDummyStats(), stats)
		cif := mgr.dbs[direction].cifaces.(*mockCIfaces)
		cif.EqualCountStats(1)
	}
}

func (suite *testIfaceMgrTestSuite) TestStatsErr() {
	mgr := GetMgr()

	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
	}

	vifIndex := vswitch.VIFIndex(1)

	// set mock for err.
	for _, direction := range directions {
		mgr.dbs[direction].cifaces = newMockCIfacesErr(suite)
	}

	// SetVRFIndex.
	vrfIndex := vswitch.VRFIndex(1)
	mgr.SetVRFIndex(vifIndex, &vrfIndex)

	// stats - ERROR (return empty stats).
	for _, direction := range directions {
		stats := mgr.Stats(vifIndex, direction)
		suite.Equal(newDummyStats(), stats)
	}
}

var testSuite *testIfaceMgrTestSuite

func TestIfaceMgrTestSuites(t *testing.T) {
	testSuite = new(testIfaceMgrTestSuite)
	suite.Run(t, testSuite)
}
