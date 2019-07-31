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
	"net"
	"syscall"
	"testing"

	"github.com/lagopus/vsw/agents/tunnel/ipsec/spd"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/vswitch"
	"github.com/stretchr/testify/suite"
)

type testSPDTestSuite struct {
	suite.Suite
}

func (suite *testSPDTestSuite) TestAddDeleteSP() {
	// data.
	vrf := &vswitch.VRF{}
	spi := uint32(1)
	vSP := &vswitch.SP{
		Name:             "sp1",
		SPI:              spi,
		Direction:        vswitch.Outbound,
		SecurityProtocol: vswitch.IPP_ESP,
		SrcPort:          1,
		DstPort:          1,
		UpperProtocol:    vswitch.IPP_TCP,
	}

	// Add: OK.
	AddSP(vrf, vSP)

	selector := &spd.SPSelector{
		Direction: ipsec.DirectionTypeOut,
	}
	selector.LocalPortRangeStart = 1
	selector.LocalPortRangeEnd = 1
	selector.RemotePortRangeStart = 1
	selector.RemotePortRangeEnd = 1
	selector.UpperProtocol = ipsec.UpperProtocolType(syscall.IPPROTO_TCP)

	// find.
	spv, ok := mgr.FindSP(selector.Direction, selector)
	suite.True(ok)
	suite.NotEmpty(spv)

	spv, ok = db[vSP.Name]
	suite.True(ok)
	suite.NotEmpty(spv)

	spi = uint32(2)
	vSP.SPI = spi

	// Update spi: OK.
	UpdateSP(vrf, vSP)

	// find.
	spv, ok = mgr.FindSP(selector.Direction, selector)
	suite.True(ok)
	suite.NotEmpty(spv)
	suite.Equal(spv.SPI, spi)

	spv, ok = db[vSP.Name]
	suite.True(ok)
	suite.NotEmpty(spv)
	suite.Equal(spv.SPI, spi)

	vSP.SrcPort = 2
	selector.LocalPortRangeStart = vSP.SrcPort
	selector.LocalPortRangeEnd = vSP.SrcPort

	// Update src port: OK.
	UpdateSP(vrf, vSP)

	// find.
	spv, ok = mgr.FindSP(selector.Direction, selector)
	suite.True(ok)
	suite.NotEmpty(spv)
	suite.Equal(spv.LocalPortRangeStart, vSP.SrcPort)
	suite.Equal(spv.LocalPortRangeEnd, vSP.SrcPort)

	spv, ok = db[vSP.Name]
	suite.True(ok)
	suite.NotEmpty(spv)
	suite.Equal(spv.LocalPortRangeStart, vSP.SrcPort)
	suite.Equal(spv.LocalPortRangeEnd, vSP.SrcPort)

	// Delete: OK.
	DeleteSP(vrf, vSP)

	spv, ok = mgr.FindSP(selector.Direction, selector)
	suite.False(ok)
	suite.Empty(spv)

	spv, ok = db[vSP.Name]
	suite.False(ok)
	suite.Empty(spv)
}

func (suite *testSPDTestSuite) TestSPI() {
	// data.
	spi := uint32(1)
	vSP := &vswitch.SP{
		SPI: spi,
	}
	spValue := &spd.SPValue{}

	// convert SPI: OK.
	err := vSP2SPvSPI(vSP, spValue)
	suite.Empty(err)
	suite.Equal(vSP.SPI, spValue.SPI)
}

func (suite *testSPDTestSuite) TestSPIError() {
	// data.
	spi := uint32(0)
	vSP := &vswitch.SP{
		SPI: spi,
	}
	spValue := &spd.SPValue{}

	// convert SPI: NG.
	// SPI is 0.
	err := vSP2SPvSPI(vSP, spValue)
	suite.NotEmpty(err)
}

func (suite *testSPDTestSuite) TestDirection() {
	// data.
	spi := uint32(1)

	directions := map[vswitch.Direction]ipsec.DirectionType{
		vswitch.Inbound:  ipsec.DirectionTypeIn,
		vswitch.Outbound: ipsec.DirectionTypeOut,
	}

	for vDirection, sDirection := range directions {
		// data.
		vSP := &vswitch.SP{
			SPI:       spi,
			Direction: vDirection,
		}
		spValue := &spd.SPValue{}

		// convert Direction: OK.
		err := vSP2SPvDirection(vSP, spValue)
		suite.Empty(err)
		suite.Equal(sDirection, spValue.Direction)
	}
}

func (suite *testSPDTestSuite) TestProtocol() {
	// data.
	spi := uint32(1)
	vSP := &vswitch.SP{
		SPI:              spi,
		SecurityProtocol: vswitch.IPP_ESP,
	}
	spValue := &spd.SPValue{}

	// convert Protocol: OK.
	err := vSP2SPvProtocol(vSP, spValue)
	suite.Empty(err)
	suite.Equal(ipsec.SecurityProtocolTypeESP, spValue.Protocol)
}

func (suite *testSPDTestSuite) TestProtocolError() {
	// data.
	spi := uint32(1)
	vSP := &vswitch.SP{
		SPI:              spi,
		SecurityProtocol: vswitch.IPP_IP,
	}
	spValue := &spd.SPValue{}

	// convert Protocol: NG.
	// Bad Protocol.
	err := vSP2SPvProtocol(vSP, spValue)
	suite.NotEmpty(err)
}

func (suite *testSPDTestSuite) TestPolicy() {
	// data.
	spi := uint32(1)
	policies := map[vswitch.Policy]ipsec.PolicyType{
		vswitch.Discard: ipsec.PolicyTypeDiscard,
		vswitch.Bypass:  ipsec.PolicyTypeBypass,
		vswitch.Protect: ipsec.PolicyTypeProtect,
	}

	for vPolicy, sPolicy := range policies {
		// data.
		vSP := &vswitch.SP{
			SPI:    spi,
			Policy: vPolicy,
		}
		spValue := &spd.SPValue{}

		// convert Policy: OK.
		err := vSP2SPvPolicy(vSP, spValue)
		suite.Empty(err)
		suite.Equal(sPolicy, spValue.Policy)
	}
}

func (suite *testSPDTestSuite) TestPriority() {
	// data.
	spi := uint32(1)
	priority := int32(1)
	vSP := &vswitch.SP{
		SPI:      spi,
		Priority: priority,
	}
	spValue := &spd.SPValue{}

	// convert Priority: OK.
	err := vSP2SPvPriority(vSP, spValue)
	suite.Empty(err)
	suite.Equal(priority, spValue.Priority)
}

func (suite *testSPDTestSuite) TestLocalIP() {
	// data.
	spi := uint32(1)
	ip := net.ParseIP("192.168.100.0").To4()
	mask := net.CIDRMask(24, 32)
	vSP := &vswitch.SP{
		SPI: spi,
		SrcAddress: vswitch.IPAddr{
			IP:   ip,
			Mask: mask,
		},
	}
	spValue := &spd.SPValue{}

	// convert LocalIP: OK.
	err := vSP2SPvLocalIP(vSP, spValue)
	suite.Empty(err)
	suite.Equal(ip, spValue.LocalIP.IP)
	suite.Equal(mask, spValue.LocalIP.Mask)
}

func (suite *testSPDTestSuite) TestRemoteIP() {
	// data.
	spi := uint32(1)
	ip := net.ParseIP("192.168.100.0").To4()
	mask := net.CIDRMask(24, 32)
	vSP := &vswitch.SP{
		SPI: spi,
		DstAddress: vswitch.IPAddr{
			IP:   ip,
			Mask: mask,
		},
	}
	spValue := &spd.SPValue{}

	// convert RemoteIP: OK.
	err := vSP2SPvRemoteIP(vSP, spValue)
	suite.Empty(err)
	suite.Equal(ip, spValue.RemoteIP.IP)
	suite.Equal(mask, spValue.RemoteIP.Mask)
}

func (suite *testSPDTestSuite) TestUpperProtocol() {
	// data.
	spi := uint32(1)
	protocols := map[vswitch.IPProto]ipsec.UpperProtocolType{
		vswitch.IPP_TCP: syscall.IPPROTO_TCP,        // Protocol == TCP
		vswitch.IPP_ANY: ipsec.UpperProtocolTypeAny, // Protocol == any
	}

	for vProtocol, sProtocol := range protocols {
		vSP := &vswitch.SP{
			SPI:           spi,
			UpperProtocol: vProtocol,
		}
		spValue := &spd.SPValue{}

		// convert UpperProtocol: OK.
		err := vSP2SPvUpperProtocol(vSP, spValue)
		suite.Empty(err)
		suite.Equal(sProtocol, spValue.UpperProtocol)
	}
}

func (suite *testSPDTestSuite) TestLocalPort() {
	// data.
	spi := uint32(1)
	ports := map[uint16][]uint16{
		1: []uint16{1, 1},     // port == 1
		0: []uint16{0, 65535}, // port == any
	}

	for vPort, sPort := range ports {
		// data.
		vSP := &vswitch.SP{
			SPI:     spi,
			SrcPort: vPort,
		}
		spValue := &spd.SPValue{}

		// convert LocalPort: OK.
		err := vSP2SPvLocalPort(vSP, spValue)
		suite.Empty(err)
		suite.Equal(sPort[0], spValue.LocalPortRangeStart)
		suite.Equal(sPort[1], spValue.LocalPortRangeEnd)
	}
}

func (suite *testSPDTestSuite) TestRemotePort() {
	// data.
	spi := uint32(1)
	ports := map[uint16][]uint16{
		1: []uint16{1, 1},     // port == 1
		0: []uint16{0, 65535}, // port == any
	}

	for vPort, sPort := range ports {
		// data.
		vSP := &vswitch.SP{
			SPI:     spi,
			DstPort: vPort,
		}
		spValue := &spd.SPValue{}

		// convert RemotePort: OK.
		err := vSP2SPvRemotePort(vSP, spValue)
		suite.Empty(err)
		suite.Equal(sPort[0], spValue.RemotePortRangeStart)
		suite.Equal(sPort[1], spValue.RemotePortRangeEnd)
	}
}

func (suite *testSPDTestSuite) TestLevel() {
	// data.
	spi := uint32(1)
	vSP := &vswitch.SP{
		SPI: spi,
	}
	spValue := &spd.SPValue{}

	// convert Level: OK.
	err := vSP2SPvLevel(vSP, spValue)
	suite.Empty(err)
	suite.Equal(ipsec.LevelTypeRequire, spValue.Level)
}

var testSuite *testSPDTestSuite

func TestSPDTestSuites(t *testing.T) {
	testSuite = new(testSPDTestSuite)
	suite.Run(t, testSuite)
}
