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

package vrrp

import (
	"net"
	"testing"

	"github.com/lagopus/vsw/dpdk"
	_ "github.com/lagopus/vsw/modules/dumb"
	_ "github.com/lagopus/vsw/modules/testvif"
	"github.com/stretchr/testify/suite"
)

var tx_chan chan *dpdk.Mbuf
var rx_chan chan *dpdk.Mbuf
var vif_mac net.HardwareAddr
var pool *dpdk.MemPool

type testVRRPTestSuite struct {
	suite.Suite
}

func (suite *testVRRPTestSuite) TestSplitAddrPrefix1() {
	expectedIP := net.ParseIP("192.168.0.1")
	expectedMask := net.CIDRMask(24, 32)

	str := "192.168.0.1/24"
	ip, mask, err := splitAddrPrefix(str)
	suite.Empty(err)
	suite.Equal(expectedIP, ip)
	suite.Equal(expectedMask, mask)
}

func (suite *testVRRPTestSuite) TestSplitAddrPrefix2() {
	_, _, err := splitAddrPrefix("invalid_addr")
	suite.NotEmpty(err)
}

func (suite *testVRRPTestSuite) TestSplitAddrPrefix3() {
	_, _, err := splitAddrPrefix("")
	suite.NotEmpty(err)
}

var testSuite *testVRRPTestSuite

func TestVRRPTestSuites(t *testing.T) {
	testSuite = new(testVRRPTestSuite)
	suite.Run(t, testSuite)
}
