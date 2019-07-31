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

	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/vswitch"
)

// test data for SP.

type testData struct {
	selector *SPSelector
	value    *SPValue
}

func newTestData(i uint8, t ipsec.IPVersionType) *testData {
	selector, value := newData(i, t)
	return &testData{
		selector: selector,
		value:    value,
	}
}

func newData(i uint8, t ipsec.IPVersionType) (*SPSelector, *SPValue) {
	var localIP net.IPNet
	var remoteIP net.IPNet
	if t == ipsec.IPVersionType4 {
		localIP = net.IPNet{
			IP:   net.IPv4(192, 168, 0, i),
			Mask: net.CIDRMask(24, 32),
		}
		remoteIP = net.IPNet{
			IP:   net.IPv4(192, 168, 0, i+1),
			Mask: net.CIDRMask(24, 32),
		}
	} else {
		var ipSrt string
		ipSrt = fmt.Sprintf("2001:db8:1:2:3:4:5:%v", i)
		localIP = net.IPNet{
			IP:   net.ParseIP(ipSrt),
			Mask: net.CIDRMask(47, 128),
		}
		ipSrt = fmt.Sprintf("2002:db9:2:3:4:5:6:%v", i+1)
		remoteIP = net.IPNet{
			IP:   net.ParseIP(ipSrt),
			Mask: net.CIDRMask(47, 128),
		}
	}

	selector := &SPSelector{
		CSPSelector: ipsec.CSPSelector{
			VRFIndex:             0,
			LocalIP:              localIP,
			LocalPortRangeStart:  uint16(i),
			LocalPortRangeEnd:    uint16(i + 1),
			RemoteIP:             remoteIP,
			RemotePortRangeStart: uint16(i + 2),
			RemotePortRangeEnd:   uint16(i + 3),
			UpperProtocol:        ipsec.UpperProtocolType(i + 4),
		},
	}
	value := &SPValue{
		CSPValue: ipsec.CSPValue{
			Policy:   ipsec.PolicyTypeProtect,
			Priority: int32(i),
			SPI:      uint32(i + 1),
		},
		Protocol: ipsec.SecurityProtocolTypeESP,
		Mode:     ipsec.ModeTypeTunnel,
		State:    Completed,
	}

	return selector, value
}

// dummy.
type dummy struct{}

// mockSPD.

type mockCount struct {
	callRllocRules uint64
	callFreeRules  uint64
	callMake       uint64
	callGetStats   uint64
	callSetRule    uint64
	callDumpRules  uint64
	callNewParams  uint64
}

type mockExpected struct {
	makeInRulesSize  uint32
	makeOutRulesSize uint32
}

type mockCSPD struct {
	mockCount
	mockExpected
}

func newMockCSPD() *mockCSPD {
	return &mockCSPD{}
}

func (cs *mockCSPD) AllocRules(size uint32) ipsec.CACLRules {
	cs.callRllocRules++
	testSuite.NotEqual(0, size)
	return dummy{}
}

func (cs *mockCSPD) FreeRules(rules ipsec.CACLRules) {
	cs.callFreeRules++
	testSuite.NotNil(rules)
}

func (cs *mockCSPD) Make(spd ipsec.CSPD, inRules ipsec.CACLRules, inRulesSize uint32,
	outRules ipsec.CACLRules, outRulesSize uint32) error {
	cs.callMake++
	testSuite.NotNil(spd)
	testSuite.NotNil(inRules)
	testSuite.NotNil(outRules)
	testSuite.Equal(cs.makeInRulesSize, inRulesSize)
	testSuite.Equal(cs.makeOutRulesSize, outRulesSize)
	return nil
}

func (cs *mockCSPD) Stats(spd ipsec.CSPD, spi uint32) (*ipsec.CSPDStats, error) {
	testSuite.NotNil(spd)
	cs.callGetStats++
	return &ipsec.CSPDStats{}, nil
}

func (cs *mockCSPD) SetRule(index uint32, rules ipsec.CACLRules,
	params ipsec.CACLParams) error {
	cs.callSetRule++
	testSuite.NotNil(rules)
	testSuite.NotNil(params)
	return nil
}

func (cs *mockCSPD) DumpRules(rules ipsec.CACLRules, size uint32) {
	cs.callDumpRules++
	testSuite.NotNil(rules)
	testSuite.NotEqual(0, size)
}

func (cs *mockCSPD) NewParams(args *ipsec.CACLParamsArgs) ipsec.CACLParams {
	cs.callNewParams++
	testSuite.NotNil(args)
	return dummy{}
}

func (cs *mockCSPD) ModuleCSPD(vrfIndex vswitch.VRFIndex,
	direction ipsec.DirectionType) (ipsec.CSPD, error) {
	return dummy{}, nil
}

func (cs *mockCSPD) String() string {
	return "mockCSPD"
}

// For Error.

type mockcErr struct {
	cspd ipsec.SPD
	err  string
}

// AllocRulesErr
type mockCSPDAllocRulesErr struct {
	mockCSPD
}

func newMockCSPDAllocRulesErr() *mockCSPDAllocRulesErr {
	return &mockCSPDAllocRulesErr{}
}

func (cs *mockCSPDAllocRulesErr) AllocRules(size uint32) ipsec.CACLRules {
	return nil
}

// MakeErr
type mockCSPDMakeErr struct {
	mockCSPD
}

func newMockCSPDMakeErr() *mockCSPDMakeErr {
	return &mockCSPDMakeErr{}
}

func (cs *mockCSPDMakeErr) Make(spd ipsec.CSPD, inRules ipsec.CACLRules, inRulesSize uint32,
	outRules ipsec.CACLRules, outRulesSize uint32) error {
	return fmt.Errorf("Make, %v Error", cs)
}

// SetRuleErr
type mockCSPDSetRuleErr struct {
	mockCSPD
}

func newMockCSPDSetRuleErr() *mockCSPDSetRuleErr {
	return &mockCSPDSetRuleErr{}
}

func (cs *mockCSPDSetRuleErr) SetRule(index uint32, rules ipsec.CACLRules,
	params ipsec.CACLParams) error {
	return fmt.Errorf("SetRule, %v Error", cs)
}

// GetStatsErr
type mockCSPDGetStatsErr struct {
	mockCSPD
}

func newMockCSPDGetStatsErr() *mockCSPDGetStatsErr {
	return &mockCSPDGetStatsErr{}
}

func (cs *mockCSPDGetStatsErr) Stats(spd ipsec.CSPD, spi uint32) (*ipsec.CSPDStats, error) {
	return nil, fmt.Errorf("Stats, %v Error", cs)
}
