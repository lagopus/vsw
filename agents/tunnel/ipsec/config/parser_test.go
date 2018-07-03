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
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/suite"
)

type testParserTestSuite struct {
	suite.Suite
}

func (suite *testParserTestSuite) TestReadConf() {
	rp := GetRootParser()
	err := rp.ParseConfigFile("test.conf")
	suite.Empty(err)
}

func (suite *testParserTestSuite) TestParseIP() {
	// IPv4.
	ipv4 := "192.168.0.1"
	expectedIPv4 := net.ParseIP(ipv4).To4()

	rp := GetRootParser()
	ip, err := rp.ParseIP(ipv4, true)
	suite.Empty(err)
	suite.Equal(expectedIPv4, ip)

	// IPv6.
	ipv6 := "2001:db8::68"
	expectedIPv6 := net.ParseIP(ipv6)

	ip, err = rp.ParseIP(ipv6, false)
	suite.Empty(err)
	suite.Equal(expectedIPv6, ip)
}

func (suite *testParserTestSuite) TestParseIPError() {
	rp := GetRootParser()

	// bad IP.
	str := "foo"
	_, err := rp.ParseIP(str, true)
	errMsg := fmt.Sprintf("Invalid IP address: %v", str)
	suite.EqualError(err, errMsg)

	// empty string.
	str = ""
	_, err = rp.ParseIP(str, true)
	errMsg = fmt.Sprintf("Invalid IP address: %v", str)
	suite.EqualError(err, errMsg)

	// IPv4 & isIPv4 = false.
	str = "192.168.0.1"
	_, err = rp.ParseIP(str, false)
	errMsg = fmt.Sprintf("Invalid IP address: %v", str)
	suite.EqualError(err, errMsg)

	// IPv6 & isIPv4 = true.
	str = "2001:db8::68"
	_, err = rp.ParseIP(str, true)
	errMsg = fmt.Sprintf("Invalid IP address: %v", str)
	suite.EqualError(err, errMsg)
}

func (suite *testParserTestSuite) TestParseIPNet() {
	// IPv4.
	ipv4 := "192.168.0.1/24"
	_, expectedIPv4, _ := net.ParseCIDR(ipv4)

	rp := GetRootParser()
	ip, err := rp.ParseIPNet(ipv4, true)
	suite.Empty(err)
	suite.Equal(expectedIPv4, ip)

	// IPv6.
	ipv6 := "2001:db8::68/32"
	_, expectedIPv6, _ := net.ParseCIDR(ipv6)

	ip, err = rp.ParseIPNet(ipv6, false)
	suite.Empty(err)
	suite.Equal(expectedIPv6, ip)
}

func (suite *testParserTestSuite) TestParseIPNetError() {
	rp := GetRootParser()

	// bad IP.
	str := "foo"
	_, err := rp.ParseIPNet(str, true)
	errMsg := fmt.Sprintf("invalid CIDR address: %v", str)
	suite.EqualError(err, errMsg)

	// empty string.
	str = ""
	_, err = rp.ParseIPNet(str, true)
	errMsg = fmt.Sprintf("invalid CIDR address: %v", str)
	suite.EqualError(err, errMsg)

	// IPv4 & isIPv4 = false.
	str = "192.168.0.1/24"
	_, err = rp.ParseIPNet(str, false)
	errMsg = fmt.Sprintf("Invalid IP address: %v", str)
	suite.EqualError(err, errMsg)

	// IPv6 & isIPv4 = true.
	str = "2001:db8::68/32"
	_, err = rp.ParseIPNet(str, true)
	errMsg = fmt.Sprintf("Invalid IP address: %v", str)
	suite.EqualError(err, errMsg)
}

func (suite *testParserTestSuite) TestParseRange() {
	// low < high
	expectedLow := uint16(0)
	expectedHigh := uint16(65535)

	rp := GetRootParser()
	low, high, err := rp.ParseRange("0:65535")
	suite.Empty(err)
	suite.Equal(expectedLow, low)
	suite.Equal(expectedHigh, high)

	// low == high
	expectedLow = uint16(0)
	expectedHigh = uint16(0)

	rp = GetRootParser()
	low, high, err = rp.ParseRange("0:0")
	suite.Empty(err)
	suite.Equal(expectedLow, low)
	suite.Equal(expectedHigh, high)
}

func (suite *testParserTestSuite) TestParseRangeError() {
	rp := GetRootParser()

	// bad format.
	str := "10"
	_, _, err := rp.ParseRange(str)
	errMsg := fmt.Sprintf("Invalid range: %v", str)
	suite.EqualError(err, errMsg)

	// bad string.
	_, _, err = rp.ParseRange("0:h")
	suite.EqualError(err, "strconv.ParseUint: parsing \"h\": invalid syntax")
	_, _, err = rp.ParseRange("h:0")
	suite.EqualError(err, "strconv.ParseUint: parsing \"h\": invalid syntax")

	// over.
	_, _, err = rp.ParseRange("0:65536")
	suite.EqualError(err, "strconv.ParseUint: parsing \"65536\": value out of range")
	_, _, err = rp.ParseRange("65536:0")
	suite.EqualError(err, "strconv.ParseUint: parsing \"65536\": value out of range")

	// low > high
	_, _, err = rp.ParseRange("65535:0")
	suite.EqualError(err, "bad low(65535) > high(0)")
}

func TestParserTestSuites(t *testing.T) {
	suite.Run(t, new(testParserTestSuite))
}
