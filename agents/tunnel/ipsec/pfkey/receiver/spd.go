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
	"github.com/lagopus/vsw/agents/tunnel/ipsec/pfkey"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/spd"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/vswitch"
)

var mgr *spd.Mgr

func init() {
	mgr = spd.GetMgr()
}

func addSP(direction ipsec.DirectionType,
	selector *spd.SPSelector, value *spd.SPValue) (uint32, error) {
	return mgr.AddSP(direction, selector, value)
}

func updateSP(direction ipsec.DirectionType,
	selector *spd.SPSelector, value *spd.SPValue) error {
	return mgr.UpdateSP(direction, selector, value)
}

func deleteSP(direction ipsec.DirectionType, selector *spd.SPSelector) {
	mgr.DeleteSP(direction, selector)
	return
}

func findSP(direction ipsec.DirectionType,
	selector *spd.SPSelector) (*spd.SPValue, bool) {
	return mgr.FindSP(direction, selector)
}

func findSPByEntryID(selector *spd.SPSelector, entryID uint32) (*spd.SPValue, bool) {
	return mgr.FindSPByEntryID(selector, entryID)
}

func setSPI(direction ipsec.DirectionType,
	selector *spd.SPSelector, spi uint32) error {
	return mgr.SetSPI(direction, selector, spi)
}

func (s *sadbXSPDAddMsg) toSadbSPSSPV(i vswitch.VRFIndex) (*spd.SPSelector, *spd.SPValue) {
	sps := spd.SPSelector{
		CSPSelector: ipsec.CSPSelector{
			VRFIndex:      i,
			LocalIP:       *s.SrcAddress.ToIPNet(),
			RemoteIP:      *s.DstAddress.ToIPNet(),
			UpperProtocol: ipsec.UpperProtocolType(s.SrcAddress.Addr.SadbAddressProto),
		},
	}
	if s.SrcAddress.SockAddr.Port() != 0 {
		sps.LocalPortRangeStart = uint16(s.SrcAddress.SockAddr.Port())
		sps.LocalPortRangeEnd = uint16(s.SrcAddress.SockAddr.Port())
	} else {
		sps.LocalPortRangeStart = 0
		sps.LocalPortRangeEnd = 65535
	}
	if s.DstAddress.SockAddr.Port() != 0 {
		sps.RemotePortRangeStart = uint16(s.DstAddress.SockAddr.Port())
		sps.RemotePortRangeStart = uint16(s.DstAddress.SockAddr.Port())
	} else {
		sps.RemotePortRangeStart = 0
		sps.RemotePortRangeEnd = 65535
	}
	spv := spd.SPValue{
		CSPValue: ipsec.CSPValue{
			Policy:   ipsec.PolicyType(s.Policy.Policy.SadbXPolicyType),
			Priority: int32(s.Policy.Policy.SadbXpolicyPriority),
		},
		Protocol: ipsec.SecurityProtocolType(
			s.Policy.IpsecRequest.SadbXIpsecrequestProto), // only support esp.
		Mode:      ipsec.ModeType(s.Policy.IpsecRequest.SadbXIpsecrequestMode), // only support tunnel.
		Level:     ipsec.LevelType(s.Policy.IpsecRequest.SadbXIpsecrequestLevel),
		RequestID: s.Policy.IpsecRequest.SadbXIpsecrequestReqid,
	}
	if s.Policy.TunnelSrcAddr != nil {
		spv.LocalEPIP = *s.Policy.TunnelSrcAddr.ToIPNet(0)
	}
	if s.Policy.TunnelDstAddr != nil {
		spv.RemoteEPIP = *s.Policy.TunnelDstAddr.ToIPNet(0)
	}
	return &sps, &spv
}

func (s *sadbXSPDDeleteMsg) toSadbSPS(i vswitch.VRFIndex) *spd.SPSelector {
	sps := spd.SPSelector{
		Direction: ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir),
		CSPSelector: ipsec.CSPSelector{
			VRFIndex:      i,
			LocalIP:       *s.SrcAddress.ToIPNet(),
			RemoteIP:      *s.DstAddress.ToIPNet(),
			UpperProtocol: ipsec.UpperProtocolType(s.SrcAddress.Addr.SadbAddressProto),
			// XXX set port ranges?
		},
	}
	return &sps
}

func toSadbXSPDGetMsgReply(sps *spd.SPSelector, spv *spd.SPValue) *sadbXSPDGetMsgReply {
	policy := pfkey.Policy{
		Policy: pfkey.SadbXPolicy{
			SadbXPolicyType:     uint16(spv.Policy),
			SadbXPolicyDir:      uint8(sps.Direction),
			SadbXPolicyID:       spv.EntryID,
			SadbXpolicyPriority: uint32(spv.Priority),
		},
		IpsecRequest: pfkey.SadbXIpsecrequest{
			SadbXIpsecrequestProto: uint16(spv.Protocol),
			SadbXIpsecrequestMode:  uint8(spv.Mode),
			SadbXIpsecrequestLevel: uint8(spv.Level),
			SadbXIpsecrequestReqid: spv.RequestID,
		},
		TunnelSrcAddr: pfkey.ToSockaddr(&spv.LocalEPIP),
		TunnelDstAddr: pfkey.ToSockaddr(&spv.RemoteEPIP),
	}
	p, _ := sps.LocalIP.Mask.Size()
	sAddr := pfkey.AddrPair{
		Addr: pfkey.SadbAddress{
			SadbAddressPrefixlen: uint8(p),
		},
		SockAddr: pfkey.ToSockaddr(&sps.LocalIP),
	}
	p, _ = sps.RemoteIP.Mask.Size()
	dAddr := pfkey.AddrPair{
		Addr: pfkey.SadbAddress{
			SadbAddressPrefixlen: uint8(p),
		},
		SockAddr: pfkey.ToSockaddr(&sps.RemoteIP),
	}
	cTime := pfkey.SadbLifetime{
		SadbLifetimeBytes:   spv.SPStats.LifeTimeByteCurrent,
		SadbLifetimeAddtime: 0,
		SadbLifetimeUsetime: uint64(spv.SPStats.LifeTimeCurrent.Unix()),
	}
	return &sadbXSPDGetMsgReply{
		sadbXSPDAddMsg{
			pfkey.SadbBaseMsg{
				Policy:          &policy,
				CurrentLifetime: &cTime,
				SrcAddress:      &sAddr,
				DstAddress:      &dAddr,
			},
		},
	}
}
