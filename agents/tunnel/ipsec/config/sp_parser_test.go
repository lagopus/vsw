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

package config

import (
	"net"
	"strings"
	"testing"

	"github.com/lagopus/vsw/agents/tunnel/ipsec/spd"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/stretchr/testify/suite"
)

type testSPParserTestSuite struct {
	suite.Suite
}

func (suite *testSPParserTestSuite) TearDownTest() {
	mgr := spd.GetMgr()
	mgr.ClearSPD()
}

func (suite *testSPParserTestSuite) TestParse() {
	expectedSelector := &spd.SPSelector{
		Direction: ipsec.DirectionTypeOut,
		CSPSelector: ipsec.CSPSelector{
			VRFIndex: 1,
			LocalIP: net.IPNet{
				IP:   net.ParseIP("192.168.100.0").To4(),
				Mask: net.CIDRMask(24, 32),
			},
			LocalPortRangeStart: 0,
			LocalPortRangeEnd:   65535,
			RemoteIP: net.IPNet{
				IP:   net.ParseIP("192.168.200.0").To4(),
				Mask: net.CIDRMask(24, 32),
			},
			RemotePortRangeStart: 0,
			RemotePortRangeEnd:   65535,
			UpperProtocol:        100,
		},
	}

	expectedValue := &spd.SPValue{
		SPSelector: *expectedSelector,
		State:      spd.Completed,
		Protocol:   ipsec.SecurityProtocolTypeESP,
		Mode:       ipsec.ModeTypeTunnel,
		Level:      ipsec.LevelTypeRequire,
		CSPValue: ipsec.CSPValue{
			Policy:   ipsec.PolicyTypeProtect,
			Priority: 2,
			SPI:      1,
		},
	}

	confStr := "ipv4 out esp protect 1 vrf 1 pri 2 " +
		"src 192.168.100.0/24 dst 192.168.200.0/24 " +
		"sport 0:65535 dport 0:65535 proto 100"
	mgr := spd.GetMgr()

	err := spParser.Parse(strings.Fields(confStr))
	suite.Empty(err)
	spv, ok := mgr.FindSP(ipsec.DirectionTypeOut, expectedSelector)
	suite.True(ok)
	// EntryID is internally generated. So do not compare.
	expectedValue.EntryID = spv.EntryID
	suite.Equal(expectedValue, spv)
}

func (suite *testSPParserTestSuite) TestParseErrorBadParam() {
	// Bad param length.
	confStr := "ipv4"
	err := spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")

	// Bad required parameter(ipv4/6).
	confStr = "ip out esp"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "unrecognizable input: ip")

	// Bad required parameter(out/in).
	confStr = "ipv4 hoge esp"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "unrecognizable input: hoge")

	// Bad param.
	confStr = "ipv4 out hoge"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "unrecognizable input: hoge")

	// not esp param.
	confStr = "ipv4 out protect 1 pri 2 " +
		"src 192.168.100.0/24 dst 192.168.200.0/24 " +
		"sport 0:65535 dport 0:65535 proto 100"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "missing argument ESP")

	// not protect or bypass or discard param.
	confStr = "ipv4 out esp pri 2 " +
		"src 192.168.100.0/24 dst 192.168.200.0/24 " +
		"sport 0:65535 dport 0:65535 proto 100"
}

func (suite *testSPParserTestSuite) TestParseErrorProtect() {
	// Bad SPI.
	confStr := "ipv4 out protect hoge"
	err := spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"hoge\": invalid syntax")

	// Out of range.
	confStr = "ipv4 out protect 4294967296"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"4294967296\": value out of range")

	// Empty value.
	confStr = "ipv4 out protect "
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSPParserTestSuite) TestParseErrorPriority() {
	// Bad priority.
	confStr := "ipv4 out pri hoge"
	err := spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseInt: parsing \"hoge\": invalid syntax")

	// Out of range.
	confStr = "ipv4 out pri 2147483648"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseInt: parsing \"2147483648\": value out of range")

	// Out of range.
	confStr = "ipv4 out pri -2147483649"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseInt: parsing \"-2147483649\": value out of range")

	// Empty value.
	confStr = "ipv4 out pri "
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSPParserTestSuite) TestParseErrorSrcIP() {
	// Bad IP.
	confStr := "ipv4 out src 192.168.0.1000/24"
	err := spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "invalid CIDR address: 192.168.0.1000/24")

	// Bad Mask.
	confStr = "ipv4 out src 192.168.0.0/1000"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "invalid CIDR address: 192.168.0.0/1000")

	// Empty value.
	confStr = "ipv4 out src "
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSPParserTestSuite) TestParseErrorDstIP() {
	// Bad IP.
	confStr := "ipv4 out dst 192.168.0.1000/24"
	err := spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "invalid CIDR address: 192.168.0.1000/24")

	// Bad Mask.
	confStr = "ipv4 out dst 192.168.0.0/1000"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "invalid CIDR address: 192.168.0.0/1000")

	// Empty value.
	confStr = "ipv4 out dst "
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSPParserTestSuite) TestParseErrorUpperProtocol() {
	// Bad Protocol.
	confStr := "ipv4 out proto hoge"
	err := spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"hoge\": invalid syntax")

	// Out of range.
	confStr = "ipv4 out proto 65536"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"65536\": value out of range")

	// Empty value.
	confStr = "ipv4 out proto "
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSPParserTestSuite) TestParseErrorSrcPort() {
	// Bad port.
	confStr := "ipv4 out sport hoge"
	err := spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Invalid range: hoge")

	// Bad port(low).
	confStr = "ipv4 out sport hoge:0"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"hoge\": invalid syntax")

	// Bad port(high).
	confStr = "ipv4 out sport 0:hoge"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"hoge\": invalid syntax")

	// Out of range(low).
	confStr = "ipv4 out sport 65536:0"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"65536\": value out of range")

	// Out of range(high).
	confStr = "ipv4 out sport 0:65536"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"65536\": value out of range")

	// Empty value.
	confStr = "ipv4 out sport "
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSPParserTestSuite) TestParseErrorDstPort() {
	// Bad port.
	confStr := "ipv4 out dport hoge"
	err := spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Invalid range: hoge")

	// Bad port(low).
	confStr = "ipv4 out dport hoge:0"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"hoge\": invalid syntax")

	// Bad port(high).
	confStr = "ipv4 out dport 0:hoge"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"hoge\": invalid syntax")

	// Out of range(low).
	confStr = "ipv4 out dport 65536:0"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"65536\": value out of range")

	// Out of range(high).
	confStr = "ipv4 out dport 0:65536"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"65536\": value out of range")

	// Empty value.
	confStr = "ipv4 out dport "
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSPParserTestSuite) TestParseErrorVRF() {
	// Bad vrf.
	confStr := "ipv4 out vrf hoge"
	err := spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"hoge\": invalid syntax")

	// Out of range.
	confStr = "ipv4 out vrf 256"
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"256\": value out of range")

	// Empty value.
	confStr = "ipv4 out vrf "
	err = spParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func TestSPParserTestSuites(t *testing.T) {
	suite.Run(t, new(testSPParserTestSuite))
}
