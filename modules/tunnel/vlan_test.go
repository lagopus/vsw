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

// +build test

package tunnel

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type testVLANTestSuite struct {
	suite.Suite
}

var vlanTestSuite *testVLANTestSuite

func (suite *testVLANTestSuite) TestPopVLAN() {
	mbuf := allocMbuf()
	suite.NotEmpty(mbuf)
	defer mbuf.Free()

	// data.
	ether := []byte{
		0x52, 0x54, 0x00, 0x00, 0x00, 0x01, // dst mac.
		0x52, 0x54, 0x00, 0x00, 0x00, 0x02, // src mac.
	}
	vlan := []byte{
		0x00, 0x01, // vlan_tci (VID: 1)
	}
	protoDot1Q := []byte{
		0x81, 0x00, // proto (IEEE 802.1Q)
	}
	protoIPv4 := []byte{
		0x08, 0x00, // proto (IPv4)
	}
	ip := []byte{
		0x45, 0x00, 0x00, 0x20,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x7c, 0xca,
		0x7f, 0x00, 0x00, 0x01, // src IP
		0x7f, 0x00, 0x00, 0x01, // dst IP
	}

	data := append(ether, protoDot1Q...)
	data = append(data, vlan...)
	data = append(data, protoIPv4...)
	data = append(data, ip...)
	mbuf.SetData(data)

	expectedData := append(ether, protoIPv4...)
	expectedData = append(expectedData, ip...)

	expectedVID := uint16(0x1)

	var vid uint16
	// vlanPop: OK.
	err := vlanPop(mbuf, &vid)
	suite.Empty(err)
	mdata := mbuf.Data()
	suite.Equal(expectedData, mdata)
	suite.Equal(expectedVID, vid)
	suite.Equal(PktRxVLANStripped, mbuf.OLFlags()&PktRxVLANStripped)
	suite.Equal(PktRxVLAN, mbuf.OLFlags()&PktRxVLAN)
}

func (suite *testVLANTestSuite) TestPopVLANErr() {
	mbuf := allocMbuf()
	suite.NotEmpty(mbuf)
	defer mbuf.Free()

	var vid uint16
	// vlanPop: NG, mbuf is nil.
	err := vlanPop(nil, &vid)
	suite.NotEmpty(err)

	// vlanPop: NG, Bad proto.
	// data.
	data := []byte{
		0x52, 0x54, 0x00, 0x00, 0x00, 0x01, // dst mac.
		0x52, 0x54, 0x00, 0x00, 0x00, 0x02, // src mac.
		0xff, 0xff, // proto (BAD)
		0x00, 0x01, // vlan_tci (VID: 1)
	}
	mbuf.SetData(data)

	err = vlanPop(mbuf, &vid)
	suite.NotEmpty(err)
}

func (suite *testVLANTestSuite) TestPushVLAN() {
	mbuf := allocMbuf()
	suite.NotEmpty(mbuf)
	defer mbuf.Free()

	// data.
	ether := []byte{
		0x52, 0x54, 0x00, 0x00, 0x00, 0x01, // dst mac.
		0x52, 0x54, 0x00, 0x00, 0x00, 0x02, // src mac.
	}
	vlan := []byte{
		0x00, 0x01, // vlan_tci (VID: 1)
	}
	protoDot1Q := []byte{
		0x81, 0x00, // proto (IEEE 802.1Q)
	}
	protoIPv4 := []byte{
		0x08, 0x00, // proto (IPv4)
	}
	ip := []byte{
		0x45, 0x00, 0x00, 0x20,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x7c, 0xca,
		0x7f, 0x00, 0x00, 0x01, // src IP
		0x7f, 0x00, 0x00, 0x01, // dst IP
	}

	data := append(ether, protoIPv4...)
	data = append(data, ip...)
	mbuf.SetData(data)
	mbuf.SetVlanTCI(0x1)

	expectedData := append(ether, protoDot1Q...)
	expectedData = append(expectedData, vlan...)
	expectedData = append(expectedData, protoIPv4...)
	expectedData = append(expectedData, ip...)

	// vlanPush: OK.
	err := vlanPush(mbuf)
	suite.Empty(err)
	mdata := mbuf.Data()
	suite.Equal(expectedData, mdata)
	suite.Equal(uint64(0), mbuf.OLFlags()&PktRxVLANStripped)
}

func (suite *testVLANTestSuite) TestPushVLANErr() {
	mbuf := allocMbuf()
	suite.NotEmpty(mbuf)
	defer mbuf.Free()

	// vlanPush: mbuf is nil.
	err := vlanPush(nil)
	suite.NotEmpty(err)
}

func TestVLANTestSuites(t *testing.T) {
	vlanTestSuite = new(testVLANTestSuite)
	suite.Run(t, vlanTestSuite)
}
