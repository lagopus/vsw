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

package sad

import (
	"net"
	"testing"

	"github.com/lagopus/vsw/agents/tunnel/ipsec/sad"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/vswitch"
	"github.com/stretchr/testify/suite"
)

type testSADTestSuite struct {
	suite.Suite
}

func (suite *testSADTestSuite) TestAddDeleteSA() {
	// data.
	vrf := &vswitch.VRF{}
	spi := uint32(1)
	vSA := &vswitch.SA{
		SPI:        spi,
		Mode:       vswitch.ModeTunnel,
		RemotePeer: net.ParseIP("127.0.0.1"),
		Encrypt:    vswitch.EncryptNULL,
		Auth:       vswitch.AuthNULL,
	}

	// Add: OK.
	AddSA(vrf, vSA)

	selector := &sad.SASelector{
		VRFIndex: vrf.Index(),
		SPI:      sad.SPI(spi),
	}

	// find.
	for _, mgr := range mgrs {
		sa, err := mgr.FindSA(selector)
		suite.Empty(err)
		suite.NotEmpty(sa)
		// check field val.
		suite.Equal(vSA.RemotePeer, sa.RemoteEPIP.IP)
	}

	// Update.
	vSA.RemotePeer = net.ParseIP("127.0.0.2")
	UpdateSA(vrf, vSA)

	// find.
	for _, mgr := range mgrs {
		sa, err := mgr.FindSA(selector)
		suite.Empty(err)
		suite.NotEmpty(sa)
		// check field val.
		suite.Equal(vSA.RemotePeer, sa.RemoteEPIP.IP)
	}

	// Delete: OK.
	DeleteSA(vrf, vSA)

	// find.
	for _, mgr := range mgrs {
		_, err := mgr.FindSA(selector)
		suite.NotEmpty(err)
	}
}

func (suite *testSADTestSuite) TestMode() {
	// data.
	spi := uint32(1)
	ips := map[string]ipsec.SAFlag{
		"127.0.0.1": ipsec.IP4Tunnel,
		"::1":       ipsec.IP6Tunnel,
	}
	for ip, mode := range ips {
		// data.
		vSA := &vswitch.SA{
			SPI:        spi,
			Mode:       vswitch.ModeTunnel,
			RemotePeer: net.ParseIP(ip),
			LocalPeer:  net.ParseIP(ip),
		}
		saValue := &sad.SAValue{
			CSAValue: ipsec.CSAValue{
				LocalEPIP: net.IPNet{
					IP: vSA.LocalPeer,
				},
				RemoteEPIP: net.IPNet{
					IP: vSA.RemotePeer,
				},
			},
		}

		// convert Mode: OK.
		err := vSA2SAvMode(vSA, saValue)
		suite.Empty(err)
		suite.Equal(mode, saValue.Flags)
	}
}

func (suite *testSADTestSuite) TestModeError() {
	// data.
	spi := uint32(1)
	vSA := &vswitch.SA{
		SPI:  spi,
		Mode: vswitch.ModeUndefined,
	}
	saValue := &sad.SAValue{}

	// convert Mode: NG.
	// Bad Mode.
	err := vSA2SAvMode(vSA, saValue)
	suite.NotEmpty(err)
}

func (suite *testSADTestSuite) TestCipherAlgo() {
	// data.
	spi := uint32(1)
	algos := map[vswitch.ESPEncrypt]ipsec.CipherAlgoType{
		vswitch.EncryptNULL: ipsec.CipherAlgoTypeNull,
		vswitch.EncryptAES:  ipsec.CipherAlgoTypeAesCbc,
	}
	keys := map[vswitch.ESPEncrypt]string{
		vswitch.EncryptNULL: "",
		vswitch.EncryptAES:  "00112233445566778899aabbccddeeff",
	}

	for vAlgo, sAlgo := range algos {
		// data.
		vSA := &vswitch.SA{
			SPI:     spi,
			Encrypt: vAlgo,
			EncKey:  keys[vAlgo],
		}
		saValue := &sad.SAValue{}

		// convert CipherAlgo: OK.
		err := vSA2SAvCipherAlgo(vSA, saValue)
		suite.Empty(err)
		suite.Equal(sAlgo, saValue.CipherAlgo)
	}
}

func (suite *testSADTestSuite) TestCipherAlgoError() {
	// data.
	spi := uint32(1)

	vSA := &vswitch.SA{
		SPI:     spi,
		Encrypt: vswitch.EncryptUndefined,
	}
	saValue := &sad.SAValue{}

	// convert CipherAlgo: NG.
	// Bad Encrypt type.
	err := vSA2SAvCipherAlgo(vSA, saValue)
	suite.NotEmpty(err)

	vSA = &vswitch.SA{
		Encrypt: vswitch.EncryptNULL,
		EncKey:  "0001",
	}

	// convert CipherAlgo: NG.
	// Bad Key length(NULL).
	err = vSA2SAvCipherAlgo(vSA, saValue)
	suite.NotEmpty(err)

	vSA = &vswitch.SA{
		Encrypt: vswitch.EncryptAES,
		EncKey:  "0001",
	}

	// convert CipherAlgo: NG.
	// Bad Key length(AES).
	err = vSA2SAvCipherAlgo(vSA, saValue)
	suite.NotEmpty(err)
}

func (suite *testSADTestSuite) TestAuthAlgo() {
	// data.
	spi := uint32(1)
	algos := map[vswitch.ESPAuth]ipsec.AuthAlgoType{
		vswitch.AuthNULL: ipsec.AuthAlgoTypeNull,
		vswitch.AuthSHA1: ipsec.AuthAlgoTypeSha1Hmac,
	}
	keys := map[vswitch.ESPAuth]string{
		vswitch.AuthNULL: "",
		vswitch.AuthSHA1: "00112233445566778899aabbccddeeff00112233",
	}

	for vAlgo, sAlgo := range algos {
		// data.
		vSA := &vswitch.SA{
			SPI:     spi,
			Auth:    vAlgo,
			AuthKey: keys[vAlgo],
		}
		saValue := &sad.SAValue{}

		// convert AuthAlgo: OK.
		err := vSA2SAvAuthAlgo(vSA, saValue)
		suite.Empty(err)
		suite.Equal(sAlgo, saValue.AuthAlgo)
	}
}

func (suite *testSADTestSuite) TestAuthAlgoError() {
	// data.
	spi := uint32(1)

	vSA := &vswitch.SA{
		SPI:  spi,
		Auth: vswitch.AuthUndefined,
	}
	saValue := &sad.SAValue{}

	// convert AuthAlgo: NG.
	// Bad Auth type.
	err := vSA2SAvAuthAlgo(vSA, saValue)
	suite.NotEmpty(err)

	vSA = &vswitch.SA{
		Auth:    vswitch.AuthNULL,
		AuthKey: "0001",
	}

	// convert AuthAlgo: NG.
	// Bad Key length(NULL).
	err = vSA2SAvAuthAlgo(vSA, saValue)
	suite.NotEmpty(err)

	vSA = &vswitch.SA{
		Auth:    vswitch.AuthSHA1,
		AuthKey: "0001",
	}

	// convert AuthAlgo: NG.
	// Bad Key length(HMAC-SHA1).
	err = vSA2SAvAuthAlgo(vSA, saValue)
	suite.NotEmpty(err)
}

func (suite *testSADTestSuite) TestLocalEPIP() {
	// data.
	spi := uint32(1)
	vSA := &vswitch.SA{
		SPI:       spi,
		LocalPeer: net.ParseIP("127.0.0.1"),
	}
	saValue := &sad.SAValue{}

	// convert LocalEPIP: OK.
	err := vSA2SAvLocalEPIP(vSA, saValue)
	suite.Empty(err)
	suite.Equal(vSA.LocalPeer, saValue.LocalEPIP.IP)
	suite.Equal(net.CIDRMask(len(vSA.LocalPeer)*8, len(vSA.LocalPeer)*8),
		saValue.LocalEPIP.Mask)
}

func (suite *testSADTestSuite) TestRmoteEPIP() {
	// data.
	spi := uint32(1)
	vSA := &vswitch.SA{
		SPI:        spi,
		RemotePeer: net.ParseIP("127.0.0.1"),
	}
	saValue := &sad.SAValue{}

	// convert RemoteEPIP: OK.
	err := vSA2SAvRemoteEPIP(vSA, saValue)
	suite.Empty(err)
	suite.Equal(vSA.RemotePeer, saValue.RemoteEPIP.IP)
	suite.Equal(net.CIDRMask(len(vSA.RemotePeer)*8, len(vSA.RemotePeer)*8),
		saValue.RemoteEPIP.Mask)
}

func (suite *testSADTestSuite) TestLifeTimeHard() {
	// data.
	spi := uint32(1)
	vSA := &vswitch.SA{
		SPI:               spi,
		LifeTimeInSeconds: 1000,
	}
	saValue := &sad.SAValue{}

	// convert LifeTimeHard: OK.
	err := vSA2SAvLifeTimeHard(vSA, saValue)
	suite.Empty(err)
	suite.NotEqual(0, saValue.LifeTimeHard)
}

func (suite *testSADTestSuite) TestLifeTimeByteHard() {
	// data.
	spi := uint32(1)
	vSA := &vswitch.SA{
		SPI:            spi,
		LifeTimeInByte: 1000,
	}
	saValue := &sad.SAValue{}

	// convert LifeTimeByteHard: OK.
	err := vSA2SAvLifeTimeByteHard(vSA, saValue)
	suite.Empty(err)
	suite.NotEqual(0, saValue.LifeTimeByteHard)
}

func (suite *testSADTestSuite) TestProtocol() {
	// data.
	spi := uint32(1)
	vSA := &vswitch.SA{
		SPI: spi,
	}
	saValue := &sad.SAValue{}

	// convert Protocol(: OK.
	err := vSA2SAvProtocol(vSA, saValue)
	suite.Empty(err)
	suite.Equal(ipsec.SecurityProtocolTypeESP, saValue.Protocol)
}

var testSuite *testSADTestSuite

func TestSADTestSuites(t *testing.T) {
	testSuite = new(testSADTestSuite)
	suite.Run(t, testSuite)
}
