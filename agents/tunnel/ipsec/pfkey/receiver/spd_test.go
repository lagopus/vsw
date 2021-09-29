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

package receiver

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	"github.com/lagopus/vsw/agents/tunnel/ipsec/spd"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/stretchr/testify/suite"
)

type SpdTestSuit struct {
	suite.Suite
}

func Test_SpdTestSuite(t *testing.T) {
	suite.Run(t, new(SpdTestSuit))
}

func (s *SpdTestSuit) TesttoSadbSPSSPV() {
	b := []byte{
		0x08, 0x00, 0x12, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xda, 0x05, 0x00,
		0x30, 0x00, 0x32, 0x00, 0x02, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x0a, 0x0a, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x0a, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 0x00, 0x05, 0x00, 0xff, 0x10, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xbf, 0xff, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x06, 0x00, 0xff, 0x10, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	r := bytes.NewReader(b)
	smsg := sadbXSPDAddMsg{}
	err := smsg.Parse(r)

	s.Assert().NoError(err)
	s.Assert().NotNil(smsg)

	sps, spv, err := smsg.toSadbSPSSPV(0)
	s.Assert().NoError(err)
	s.Assert().NotNil(sps)
	s.Assert().Equal(net.IPv4(191, 255, 0, 0), sps.LocalIP.IP)
	s.Assert().Equal(net.IPv4Mask(255, 255, 0, 0), sps.LocalIP.Mask)
	s.Assert().Equal(uint16(0), sps.LocalPortRangeStart)
	s.Assert().Equal(uint16(65535), sps.LocalPortRangeEnd)
	s.Assert().Equal(net.IPv4(192, 0, 0, 0), sps.RemoteIP.IP)
	s.Assert().Equal(net.IPv4Mask(255, 255, 0, 0), sps.RemoteIP.Mask)
	s.Assert().Equal(uint16(0), sps.RemotePortRangeStart)
	s.Assert().Equal(uint16(65535), sps.RemotePortRangeEnd)
	s.Assert().Equal(ipsec.UpperProtocolTypeAny, sps.UpperProtocol)
	fmt.Println(sps)

	s.Assert().NotNil(spv)
	s.Assert().Equal(ipsec.PolicyTypeProtect, spv.Policy)
	s.Assert().Equal(int32(383615), spv.Priority)
	s.Assert().Equal(ipsec.SecurityProtocolTypeESP, spv.Protocol)
	s.Assert().Equal(ipsec.ModeTypeTunnel, spv.Mode)
	s.Assert().Equal(ipsec.LevelTypeUnique, spv.Level)
	s.Assert().Equal(uint32(2), spv.RequestID)
	s.Assert().Equal(net.IPv4(10, 10, 0, 2), spv.LocalEPIP.IP)
	s.Assert().Equal(net.IPv4Mask(0, 0, 0, 0), spv.LocalEPIP.Mask)
	s.Assert().Equal(net.IPv4(10, 10, 0, 1), spv.RemoteEPIP.IP)
	s.Assert().Equal(net.IPv4Mask(0, 0, 0, 0), spv.RemoteEPIP.Mask)
	fmt.Println(*spv)
}

func (s *SpdTestSuit) TesttoSadbSPS() {
	b := []byte{
		0x02, 0x00, 0x12, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 0x00, 0x05, 0x00, 0xff, 0x10, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x06, 0x00, 0xff, 0x10, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0xbf, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	r := bytes.NewReader(b)
	smsg := sadbXSPDDeleteMsg{}
	err := smsg.Parse(r)

	s.Assert().NoError(err)
	s.Assert().NotNil(smsg)

	sps := smsg.toSadbSPS(0)
	s.Assert().NotNil(sps)
	s.Assert().Equal(net.IPv4(192, 0, 0, 0), sps.LocalIP.IP)
	s.Assert().Equal(net.IPv4Mask(255, 255, 0, 0), sps.LocalIP.Mask)
	s.Assert().Equal(uint16(0), sps.LocalPortRangeStart)
	s.Assert().Equal(uint16(65535), sps.LocalPortRangeEnd)
	s.Assert().Equal(net.IPv4(191, 255, 0, 0), sps.RemoteIP.IP)
	s.Assert().Equal(net.IPv4Mask(255, 255, 0, 0), sps.RemoteIP.Mask)
	s.Assert().Equal(uint16(0), sps.RemotePortRangeStart)
	s.Assert().Equal(uint16(65535), sps.RemotePortRangeEnd)
	s.Assert().Equal(ipsec.UpperProtocolTypeAny, sps.UpperProtocol)
}

func (s *SpdTestSuit) TesttoSadbXSPDGetMsgReply() {
	sps := spd.SPSelector{
		Direction: ipsec.DirectionTypeIn,
		CSPSelector: ipsec.CSPSelector{
			VRFIndex: 0,
			LocalIP: net.IPNet{
				IP:   net.IPv4(191, 255, 0, 0),
				Mask: net.IPv4Mask(255, 255, 0, 0),
			},
			LocalPortRangeStart: 0,
			LocalPortRangeEnd:   65535,
			RemoteIP: net.IPNet{
				IP:   net.IPv4(191, 0, 0, 0),
				Mask: net.IPv4Mask(255, 255, 0, 0),
			},
			RemotePortRangeStart: 0,
			RemotePortRangeEnd:   65535,
			UpperProtocol:        ipsec.UpperProtocolTypeAny,
		},
	}
	spv := spd.SPValue{
		CSPValue: ipsec.CSPValue{
			Policy:   ipsec.PolicyTypeProtect,
			Priority: 383615,
		},
		Protocol:  ipsec.SecurityProtocolTypeESP,
		Mode:      ipsec.ModeTypeTunnel,
		Level:     ipsec.LevelTypeUnique,
		RequestID: 2,
		LocalEPIP: net.IPNet{
			IP:   net.IPv4(10, 10, 0, 2),
			Mask: net.IPv4Mask(0, 0, 0, 0),
		},
		RemoteEPIP: net.IPNet{
			IP:   net.IPv4(10, 10, 0, 1),
			Mask: net.IPv4Mask(0, 0, 0, 0),
		},
	}
	reply := toSadbXSPDGetMsgReply(&sps, &spv)
	b := []byte{
		0x08, 0x00, 0x12, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xda, 0x05, 0x00,
		0x30, 0x00, 0x32, 0x00, 0x02, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x0a, 0x0a, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x0a, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 0x00, 0x05, 0x00, 0xff, 0x10, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xbf, 0xff, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x06, 0x00, 0xff, 0x10, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	r := bytes.NewReader(b)
	smsg := sadbXSPDAddMsg{}
	err := smsg.Parse(r)
	smsg.Policy.IpsecRequest.SadbXIpsecrequestLen = 0
	smsg.Policy.SadbXPolicyLen = 0
	s.Assert().NoError(err)
	s.Assert().NotNil(smsg)
	s.Assert().Equal(smsg.Policy, reply.Policy)
}
