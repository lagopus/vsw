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
	"net"
	"testing"
	"time"

	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/stretchr/testify/suite"
)

type testSPDMgrTestSuite struct {
	suite.Suite
}

func (suite *testSPDMgrTestSuite) SetupTest() {
	spdMgr = newSPDMgr()
}

func (suite *testSPDMgrTestSuite) TearDownTest() {
	mgr := GetMgr()
	mgr.ClearSPD()

	for _, vrf := range mgr.vrfs {
		for _, spd := range vrf.spds {
			for _, d := range spd.dbs {
				suite.Equal(0, len(d))
			}
		}
	}
}

func (suite *testSPDMgrTestSuite) TestGetSPD() {
	ipv4 := net.IPv4(192, 168, 0, 1)
	ipv6 := net.ParseIP("2001:db8:1:2:3:4:5:1")
	mgr := GetMgr()

	// LocalIP:IPv4, RemoteIP:IPv4
	selector := &SPSelector{
		CSPSelector: ipsec.CSPSelector{
			VRFIndex: 0,
			LocalIP: net.IPNet{
				IP: ipv4,
			},
			RemoteIP: net.IPNet{
				IP: ipv4,
			},
		},
	}

	vrf, err := mgr.vrf(selector)
	suite.Empty(err)
	suite.NotEmpty(vrf)
	spd := mgr.spd(vrf, selector)
	suite.NotEmpty(spd)
	suite.Equal(mgr.vrfs[0].spds[ipsec.IPVersionType4], spd)

	// LocalIP:IPv6, RemoteIP:IPv6
	selector = &SPSelector{
		CSPSelector: ipsec.CSPSelector{
			VRFIndex: 0,
			LocalIP: net.IPNet{
				IP: ipv6,
			},
			RemoteIP: net.IPNet{
				IP: ipv6,
			},
		},
	}

	vrf, err = mgr.vrf(selector)
	suite.Empty(err)
	suite.NotEmpty(vrf)
	spd = mgr.spd(vrf, selector)
	suite.NotEmpty(spd)
	suite.Equal(mgr.vrfs[0].spds[ipsec.IPVersionType6], spd)
}

func (suite *testSPDMgrTestSuite) TestGetSPDError() {
	ipv4 := net.IPv4(192, 168, 0, 1)
	ipv6 := net.ParseIP("2001:db8:1:2:3:4:5:1")
	mgr := GetMgr()

	// LocalIP:IPv4, RemoteIP:IPv6
	selector := &SPSelector{
		CSPSelector: ipsec.CSPSelector{
			VRFIndex: 0,
			LocalIP: net.IPNet{
				IP: ipv4,
			},
			RemoteIP: net.IPNet{
				IP: ipv6,
			},
		},
	}

	vrf, err := mgr.vrf(selector)
	suite.Empty(err)
	suite.NotEmpty(vrf)
	spd := mgr.spd(vrf, selector)
	suite.Empty(spd)

	// LocalIP:IPv6, RemoteIP:IPv4
	selector = &SPSelector{
		CSPSelector: ipsec.CSPSelector{
			VRFIndex: 0,
			LocalIP: net.IPNet{
				IP: ipv6,
			},
			RemoteIP: net.IPNet{
				IP: ipv4,
			},
		},
	}

	vrf, err = mgr.vrf(selector)
	suite.Empty(err)
	suite.NotEmpty(vrf)
	spd = mgr.spd(vrf, selector)
	suite.Empty(spd)

	// Bad IP.
	selector = &SPSelector{
		CSPSelector: ipsec.CSPSelector{
			VRFIndex: 0,
			LocalIP: net.IPNet{
				IP: make([]byte, 9),
			},
		},
	}

	vrf, err = mgr.vrf(selector)
	suite.Empty(err)
	suite.NotEmpty(vrf)
	spd = mgr.spd(vrf, selector)
	suite.Empty(spd)
}

func (suite *testSPDMgrTestSuite) TestAddDelFindSP() {
	mgr := GetMgr()
	suite.NotEmpty(mgr)
	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
		ipsec.DirectionTypeFwd,
	}
	ipVersions := []ipsec.IPVersionType{
		ipsec.IPVersionType4,
		ipsec.IPVersionType6,
	}

	for i, direction := range directions {
		for j, ipv := range ipVersions {
			data := newTestData(uint8(i+j), ipv)
			expectedEID := mgr.createEntryID(mgr.createPKey(data.selector, direction))

			// Add - OK.
			eID, err := mgr.AddSP(direction, data.selector, data.value)
			suite.Empty(err)
			suite.Equal(expectedEID, eID)

			// Find.
			// FindSP.
			value, ok := mgr.FindSP(direction, data.selector)
			suite.True(ok)
			suite.Equal(data.value, value)
			suite.Equal(expectedEID, value.EntryID)
			// FindSP by EntryIDa.
			value, ok = mgr.FindSPByEntryID(data.selector, expectedEID)
			suite.True(ok)
			suite.Equal(data.value, value)

			// Delete.
			mgr.DeleteSP(direction, data.selector)
			// FindSP.
			value, ok = mgr.FindSP(direction, data.selector)
			suite.False(ok)
			// FindSP By EntryID.
			value, ok = mgr.FindSPByEntryID(data.selector, expectedEID)
			suite.False(ok)
		}
	}
}

func (suite *testSPDMgrTestSuite) TestAddError() {
	mgr := GetMgr()
	suite.NotEmpty(mgr)
	data := newTestData(1, ipsec.IPVersionType4)

	// Add - OK.
	_, err := mgr.AddSP(ipsec.DirectionTypeIn, data.selector, data.value)
	suite.Empty(err)

	// Add - Already exists.
	_, err = mgr.AddSP(ipsec.DirectionTypeIn, data.selector, data.value)
	errMsg := fmt.Sprintf("Already exists : %v", data.selector)
	suite.EqualError(err, errMsg)

	_, err = mgr.AddSP(ipsec.DirectionTypeIn, nil, data.value)
	suite.EqualError(err, "Invalid args")
	_, err = mgr.AddSP(ipsec.DirectionTypeIn, data.selector, nil)
	suite.EqualError(err, "Invalid args")

	// Add - Noy found SPD
	selectorBad := &SPSelector{
		CSPSelector: ipsec.CSPSelector{
			VRFIndex: 0,
			LocalIP: net.IPNet{
				IP: make([]byte, 9),
			},
		},
	}
	_, err = mgr.AddSP(ipsec.DirectionTypeIn, selectorBad, data.value)
	suite.EqualError(err, "Not found SPD")
}

func (suite *testSPDMgrTestSuite) TestUpdateSP() {
	mgr := GetMgr()
	suite.NotEmpty(mgr)
	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
		ipsec.DirectionTypeFwd,
	}
	ipVersions := []ipsec.IPVersionType{
		ipsec.IPVersionType4,
		ipsec.IPVersionType6,
	}

	for i, direction := range directions {
		for j, ipv := range ipVersions {
			data := newTestData(uint8(i+j), ipv)

			expectedEID := mgr.createEntryID(mgr.createPKey(data.selector, direction))

			// Add
			eID, err := mgr.AddSP(direction, data.selector, data.value)
			suite.Empty(err)
			suite.Equal(expectedEID, eID)

			// Find.
			value, ok := mgr.FindSP(direction, data.selector)
			suite.True(ok)
			suite.Equal(data.value, value)
			suite.Equal(expectedEID, value.EntryID)

			// Update
			value.State = Uncompleted
			err = mgr.UpdateSP(direction, data.selector, value)
			suite.Empty(err)

			//Find.
			value, ok = mgr.FindSP(direction, data.selector)
			suite.True(ok)
			suite.NotEqual(data.value, value)
			suite.NotEqual(data.value.State, value.State)
			suite.Equal(Uncompleted, value.State)
			suite.Equal(expectedEID, value.EntryID)
			suite.Equal(data.value.SPSelector, value.SPSelector)
		}
	}
}

func (suite *testSPDMgrTestSuite) TestUpdateSPError() {
	mgr := GetMgr()
	suite.NotEmpty(mgr)
	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
		ipsec.DirectionTypeFwd,
	}
	ipVersions := []ipsec.IPVersionType{
		ipsec.IPVersionType4,
		ipsec.IPVersionType6,
	}

	for i, direction := range directions {
		for j, ipv := range ipVersions {
			data := newTestData(uint8(i+j), ipv)
			notFoundData := newTestData(uint8(i+j+1), ipv)

			// Add
			_, err := mgr.AddSP(direction, data.selector, data.value)
			suite.Empty(err)

			// selector is nil
			err = mgr.UpdateSP(direction, nil, data.value)
			suite.EqualError(err, "Invalid args")

			// value is nil
			err = mgr.UpdateSP(direction, data.selector, nil)
			suite.EqualError(err, "Invalid args")

			// Not found selector.
			err = mgr.UpdateSP(direction, notFoundData.selector, notFoundData.value)
			errMsg := fmt.Sprintf("Not found : %v", notFoundData.selector)
			suite.EqualError(err, errMsg)
		}
	}
}

func (suite *testSPDMgrTestSuite) TestFindNotFound() {
	mgr := GetMgr()
	suite.NotEmpty(mgr)
	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
		ipsec.DirectionTypeFwd,
	}
	ipVersions := []ipsec.IPVersionType{
		ipsec.IPVersionType4,
		ipsec.IPVersionType6,
	}

	for i, direction := range directions {
		for j, ipv := range ipVersions {
			data := newTestData(uint8(i+j), ipv)

			// Not found.
			_, ok := mgr.FindSP(direction, data.selector)
			suite.False(ok)

			_, ok = mgr.FindSP(direction, data.selector)
			suite.False(ok)

			_, ok = mgr.FindSP(direction, nil)
			suite.False(ok)

			// Set SPI - Noy found SPD
			selectorBad := &SPSelector{
				CSPSelector: ipsec.CSPSelector{
					LocalIP: net.IPNet{
						IP: make([]byte, 9),
					},
				},
			}
			_, ok = mgr.FindSP(direction, selectorBad)
			suite.False(ok)
		}
	}
}

func (suite *testSPDMgrTestSuite) TestSetSPI() {
	mgr := GetMgr()
	suite.NotEmpty(mgr)
	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
		ipsec.DirectionTypeFwd,
	}
	ipVersions := []ipsec.IPVersionType{
		ipsec.IPVersionType4,
		ipsec.IPVersionType6,
	}

	for i, direction := range directions {
		for j, ipv := range ipVersions {
			data := newTestData(uint8(i+j), ipv)

			// Add.
			_, err := mgr.AddSP(direction, data.selector, data.value)
			suite.Empty(err)

			// Set SPI.
			err = mgr.SetSPI(direction, data.selector, 100)

			// Find.
			value, ok := mgr.FindSP(direction, data.selector)
			suite.True(ok)
			suite.Equal(uint32(100), value.SPI)
		}
	}
}

func (suite *testSPDMgrTestSuite) TestSetSPIError() {
	mgr := GetMgr()
	suite.NotEmpty(mgr)
	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
		ipsec.DirectionTypeFwd,
	}
	ipVersions := []ipsec.IPVersionType{
		ipsec.IPVersionType4,
		ipsec.IPVersionType6,
	}

	for i, direction := range directions {
		for j, ipv := range ipVersions {
			data := newTestData(uint8(i+j), ipv)

			// Set SPI - Not found.
			err := mgr.SetSPI(direction, data.selector, 100)
			errMsg := fmt.Sprintf("Not found : %v", data.selector)
			suite.EqualError(err, errMsg)

			err = mgr.SetSPI(direction, nil, 100)
			suite.EqualError(err, "Invalid args")

			// Set SPI - Noy found SPD
			selectorBad := &SPSelector{
				CSPSelector: ipsec.CSPSelector{
					LocalIP: net.IPNet{
						IP: make([]byte, 9),
					},
				},
			}
			err = mgr.SetSPI(direction, selectorBad, 100)
			suite.EqualError(err, "Not found SPD")
		}
	}
}

func (suite *testSPDMgrTestSuite) TestNewDumpFreeRulesv4() {
	mgr := GetMgr()
	suite.NotEmpty(mgr)
	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
	}

	for i, direction := range directions {
		data := newTestData(uint8(i), ipsec.IPVersionType4)

		// Add.
		_, err := mgr.AddSP(direction, data.selector, data.value)
		suite.Empty(err)

		spd4 := mgr.vrfs[0].spds[ipsec.IPVersionType4]
		spd := spd4.dbs[direction]

		// SPD-IN/OUT
		rules, size, err := spd4.newRules(spd)
		suite.Empty(err)
		suite.NotEmpty(rules)
		suite.Equal(len(spd), int(size))
		spd4.dumpRulesSPD(rules, size)
		spd4.freeRules(rules)
	}
}

func (suite *testSPDMgrTestSuite) TestNewDumpFreeRulesv6() {
	mgr := GetMgr()
	suite.NotEmpty(mgr)
	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
	}

	for i, direction := range directions {
		data := newTestData(uint8(i), ipsec.IPVersionType6)

		// Add.
		_, err := mgr.AddSP(direction, data.selector, data.value)
		suite.Empty(err)

		spd6 := mgr.vrfs[0].spds[ipsec.IPVersionType6]
		spd := spd6.dbs[direction]

		// SPD-IN/OUT
		rules, size, err := spd6.newRules(spd)
		suite.Empty(err)
		suite.NotEmpty(rules)
		suite.Equal(len(spd), int(size))
		spd6.dumpRulesSPD(rules, size)
		spd6.freeRules(rules)
	}
}

func (suite *testSPDMgrTestSuite) TestMakeSPDv4() {
	mgr := GetMgr()
	suite.NotEmpty(mgr)
	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
	}

	for num := 0; num < 2; num++ {
		for i, direction := range directions {
			data := newTestData(uint8(i+num), ipsec.IPVersionType4)

			// Add.
			_, err := mgr.AddSP(direction, data.selector, data.value)
			suite.Empty(err)
		}
	}

	spd4 := mgr.vrfs[0].spds[ipsec.IPVersionType4]
	dmspd4 := newMockCSPD()
	spd4.cspd = dmspd4
	spd6 := mgr.vrfs[0].spds[ipsec.IPVersionType6]
	dmspd6 := newMockCSPD()
	spd6.cspd = dmspd6

	// exists entries.
	dmspd4.makeInRulesSize = 2
	dmspd4.makeOutRulesSize = 2
	expectedCount4 := mockCount{
		callRllocRules: 2,
		callFreeRules:  2,
		callMake:       2,
		callSetRule:    4, // call.
		callNewParams:  4, // call.
	}

	// not exists entries.
	dmspd6.makeInRulesSize = 0
	dmspd6.makeOutRulesSize = 0
	expectedCount6 := mockCount{
		callRllocRules: 2,
		callFreeRules:  2,
		callMake:       2,
		callSetRule:    0, // not call.
		callNewParams:  0, // not call.
	}

	// makeSPD.
	err := mgr.makeSPD()
	suite.Empty(err)
	suite.Equal(expectedCount4, dmspd4.mockCount)
	suite.Equal(expectedCount6, dmspd6.mockCount)
}

func (suite *testSPDMgrTestSuite) TestMakeSPDv6() {
	mgr := GetMgr()
	suite.NotEmpty(mgr)
	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
	}

	for num := 0; num < 2; num++ {
		for i, direction := range directions {
			data := newTestData(uint8(i+num), ipsec.IPVersionType6)

			// Add.
			_, err := mgr.AddSP(direction, data.selector, data.value)
			suite.Empty(err)
		}
	}

	spd4 := mgr.vrfs[0].spds[ipsec.IPVersionType4]
	dmspd4 := newMockCSPD()
	spd4.cspd = dmspd4
	spd6 := mgr.vrfs[0].spds[ipsec.IPVersionType6]
	dmspd6 := newMockCSPD()
	spd6.cspd = dmspd6

	// not exists entries.
	dmspd4.makeInRulesSize = 0
	dmspd4.makeOutRulesSize = 0
	expectedCount4 := mockCount{
		callRllocRules: 2,
		callFreeRules:  2,
		callMake:       2,
		callSetRule:    0, // not call.
		callNewParams:  0, // not call.
	}

	// exists entries.
	dmspd6.makeInRulesSize = 2
	dmspd6.makeOutRulesSize = 2
	expectedCount6 := mockCount{
		callRllocRules: 2,
		callFreeRules:  2,
		callMake:       2,
		callSetRule:    4, // call.
		callNewParams:  4, // call.
	}

	// makeSPD.
	err := mgr.makeSPD()
	suite.Empty(err)
	suite.Equal(expectedCount4, dmspd4.mockCount)
	suite.Equal(expectedCount6, dmspd6.mockCount)
}

func (suite *testSPDMgrTestSuite) TestMakeSPDError() {
	mgr := GetMgr()
	suite.NotEmpty(mgr)

	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
	}

	errs := []mockcErr{
		mockcErr{
			cspd: newMockCSPDAllocRulesErr(),
			err:  "No memory",
		},
		mockcErr{
			cspd: newMockCSPDMakeErr(),
			err:  "Make, mockCSPD Error",
		},
		mockcErr{
			cspd: newMockCSPDSetRuleErr(),
			err:  "SetRule, mockCSPD Error",
		},
	}

	dmspd6 := newMockCSPD()
	for _, direction := range directions {
		for i, e := range errs {
			data := newTestData(uint8(i), ipsec.IPVersionType4)
			// Add.
			_, err := mgr.AddSP(direction, data.selector, data.value)
			suite.Empty(err)

			spd4 := mgr.vrfs[0].spds[ipsec.IPVersionType4]
			spd6 := mgr.vrfs[0].spds[ipsec.IPVersionType6]
			spd6.cspd = dmspd6

			// return Error.
			spd4.cspd = e.cspd
			err = mgr.makeSPD()
			suite.NotEmpty(err)
			suite.EqualError(err, e.err)
			spd4.clearSPD()
		}
	}
}

func (suite *testSPDMgrTestSuite) TestExpireSP() {
	mgr := GetMgr()
	suite.NotEmpty(mgr)
	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
		ipsec.DirectionTypeFwd,
	}
	ipVersions := []ipsec.IPVersionType{
		ipsec.IPVersionType4,
		ipsec.IPVersionType6,
	}
	now := time.Now()

	for i, direction := range directions {
		for j, ipv := range ipVersions {
			// not to expire.
			NotExpireData := newTestData(uint8(i+j), ipv)
			NotExpireData.value.LifeTimeHard = now.Add(time.Duration(1) * time.Hour)

			// to expire.
			ExpireData := newTestData(uint8(i+j+1), ipv)
			ExpireData.value.LifeTimeHard = now.Add(-time.Duration(1) * time.Hour)

			// Add.
			_, err := mgr.AddSP(direction, NotExpireData.selector, NotExpireData.value)
			suite.Empty(err)
			_, err = mgr.AddSP(direction, ExpireData.selector, ExpireData.value)
			suite.Empty(err)

			// expire.
			mgr.expiredSP(now)

			// Find.
			// FindSP.
			value, ok := mgr.FindSP(direction, NotExpireData.selector)
			suite.True(ok)
			suite.Equal(NotExpireData.value, value)

			value, ok = mgr.FindSP(direction, ExpireData.selector)
			suite.False(ok)
		}
	}
}

func (suite *testSPDMgrTestSuite) TestGetStatsSPDv4() {
	mgr := GetMgr()
	suite.NotEmpty(mgr)
	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
	}

	testData := []*testData{}
	for num := 0; num < 2; num++ {
		for i, direction := range directions {
			data := newTestData(uint8(i+num), ipsec.IPVersionType4)

			// Add.
			_, err := mgr.AddSP(direction, data.selector, data.value)
			suite.Empty(err)
			testData = append(testData, data)
		}
	}

	spd4 := mgr.vrfs[0].spds[ipsec.IPVersionType4]
	dmspd4 := newMockCSPD()
	spd4.cspd = dmspd4
	spd6 := mgr.vrfs[0].spds[ipsec.IPVersionType6]
	dmspd6 := newMockCSPD()
	spd6.cspd = dmspd6

	// exists entries.
	expectedCount4 := mockCount{
		callGetStats: 4,
	}

	// statsSPD.
	err := mgr.statsSPD()
	suite.Empty(err)
	suite.Equal(expectedCount4, dmspd4.mockCount)
	suite.Equal(mockCount{}, dmspd6.mockCount)
}

func (suite *testSPDMgrTestSuite) TestGetStatsSPDv6() {
	mgr := GetMgr()
	suite.NotEmpty(mgr)
	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
	}

	testData := []*testData{}
	for num := 0; num < 2; num++ {
		for i, direction := range directions {
			data := newTestData(uint8(i+num), ipsec.IPVersionType6)

			// Add.
			_, err := mgr.AddSP(direction, data.selector, data.value)
			suite.Empty(err)
			testData = append(testData, data)
		}
	}

	spd4 := mgr.vrfs[0].spds[ipsec.IPVersionType4]
	dmspd4 := newMockCSPD()
	spd4.cspd = dmspd4
	spd6 := mgr.vrfs[0].spds[ipsec.IPVersionType6]
	dmspd6 := newMockCSPD()
	spd6.cspd = dmspd6

	// exists entries.
	expectedCount6 := mockCount{
		callGetStats: 4,
	}

	// statsSPD.
	err := mgr.statsSPD()
	suite.Empty(err)
	suite.Equal(mockCount{}, dmspd4.mockCount)
	suite.Equal(expectedCount6, dmspd6.mockCount)
}

func (suite *testSPDMgrTestSuite) TestGetStatsSPDErr() {
	mgr := GetMgr()
	suite.NotEmpty(mgr)

	directions := []ipsec.DirectionType{
		ipsec.DirectionTypeIn,
		ipsec.DirectionTypeOut,
	}

	errs := []mockcErr{
		mockcErr{
			cspd: newMockCSPDGetStatsErr(),
			err:  "Stats, mockCSPD Error",
		},
	}

	dmspd6 := newMockCSPD()
	for i, direction := range directions {
		for _, e := range errs {
			data := newTestData(uint8(i), ipsec.IPVersionType4)
			// Add.
			_, err := mgr.AddSP(direction, data.selector, data.value)
			suite.Empty(err)

			spd4 := mgr.vrfs[0].spds[ipsec.IPVersionType4]
			spd6 := mgr.vrfs[0].spds[ipsec.IPVersionType6]
			spd6.cspd = dmspd6

			// return Error.
			spd4.cspd = e.cspd
			err = mgr.statsSPD()
			suite.NotEmpty(err)
			suite.EqualError(err, e.err)
			spd4.clearSPD()
		}
	}
}

var testSuite *testSPDMgrTestSuite

func TestSPDMgrTestSuites(t *testing.T) {
	testSuite = new(testSPDMgrTestSuite)
	suite.Run(t, testSuite)
}
