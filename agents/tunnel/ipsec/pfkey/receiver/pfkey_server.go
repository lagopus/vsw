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

package receiver

import (
	"io"
	"math/rand"
	"sync"
	"syscall"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/pfkey"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/sad"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/spd"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/modules/tunnel/log"
	"github.com/lagopus/vsw/vswitch"
)

// NewSPIRetryMax Limit of retry for new SPI.
const NewSPIRetryMax = 1000

type sadbAddMsg struct {
	pfkey.SadbBaseMsg
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func (s *sadbAddMsg) Parse(r io.Reader) error {
	err := s.ParseSadbMsg(r)
	if err != nil {
		return err
	}
	/* checking necessary options */
	if s.Sa == nil || s.SrcAddress == nil ||
		s.DstAddress == nil ||
		s.EncKey == nil {
		return syscall.EINVAL
	}
	return err
}

func (s *sadbAddMsg) Handle(w io.Writer, sadbMsg *pfkey.SadbMsg) error {
	log.Logger.Info("SadbAddMsg: handle spi %d", s.Sa.SadbSaSpi)

	i := vrfs.load(s)
	selector := &sad.SASelector{
		VRFIndex: i,
	}
	if err := s.addSA(selector); err != nil {
		sadbMsg.SadbMsgErrno = uint8(err.(syscall.Errno))
		smsg := pfkey.SadbMsgTransport{
			SadbMsg: sadbMsg,
		}
		_ = smsg.Serialize(w)
		return nil
	}
	serializer := []pfkey.Serializer{
		&pfkey.SadbExtTransport{
			&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_SA},
			s.Sa,
		},
		&pfkey.SadbExtTransport{
			&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_SRC},
			s.SrcAddress,
		},
		&pfkey.SadbExtTransport{
			&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_DST},
			s.DstAddress,
		},
		&pfkey.SadbExtTransport{
			&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_LIFETIME_HARD},
			s.HardLifetime,
		},
		&pfkey.SadbExtTransport{
			&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_LIFETIME_SOFT},
			s.SoftLifetime,
		},
	}
	if s.NatTType != nil {
		serializer = append(serializer,
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_X_EXT_NAT_T_TYPE},
				s.NatTType,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_X_EXT_NAT_T_SPORT},
				s.NatTSrcPort,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_X_EXT_NAT_T_DPORT},
				s.NatTDstPort,
			},
		)
	}
	smsg := pfkey.SadbMsgTransport{
		sadbMsg,
		serializer,
	}
	err := smsg.Serialize(w)
	return err
}

type sadbUpdateMsg struct {
	sadbAddMsg
}

func (s *sadbUpdateMsg) Parse(r io.Reader) error {
	smsg := sadbAddMsg{}
	err := smsg.Parse(r)
	if err != nil {
		return err
	}
	*s = sadbUpdateMsg{smsg}
	return nil
}

func (s *sadbUpdateMsg) Handle(w io.Writer, sadbMsg *pfkey.SadbMsg) error {
	i := vrfs.load(s)
	selector := &sad.SASelector{
		VRFIndex: i,
	}
	err := s.updateSA(selector)
	if err != nil {
		sadbMsg.SadbMsgErrno = uint8(err.(syscall.Errno))
		smsg := pfkey.SadbMsgTransport{
			SadbMsg: sadbMsg,
		}
		_ = smsg.Serialize(w)
		log.Logger.Err("SadbUpdateMsg Handle err: %v", err.(syscall.Errno))
		return nil
	}
	serializer := []pfkey.Serializer{
		&pfkey.SadbExtTransport{
			&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_SA},
			s.Sa,
		},
		&pfkey.SadbExtTransport{
			&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_SRC},
			s.SrcAddress,
		},
		&pfkey.SadbExtTransport{
			&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_DST},
			s.DstAddress,
		},
	}
	if s.NatTType != nil {
		serializer = append(serializer,
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_X_EXT_NAT_T_TYPE},
				s.NatTType,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_X_EXT_NAT_T_SPORT},
				s.NatTSrcPort,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_X_EXT_NAT_T_DPORT},
				s.NatTDstPort,
			},
		)
	}
	smsg := pfkey.SadbMsgTransport{
		sadbMsg,
		serializer,
	}
	err = smsg.Serialize(w)
	return err
}

type sadbGetSPIMsg struct {
	pfkey.SadbBaseMsg
}

func (s *sadbGetSPIMsg) Parse(r io.Reader) error {
	err := s.ParseSadbMsg(r)
	if err != nil {
		log.Logger.Err("parse err")
		return err
	}
	/* checking necessary options */
	if (s.SrcAddress == nil && s.DstAddress == nil) ||
		s.SadbSPIRange == nil {
		log.Logger.Err("option err")
		return syscall.EINVAL
	}
	return err
}

func (s *sadbGetSPIMsg) Handle(w io.Writer, sadbMsg *pfkey.SadbMsg) error {
	i := vrfs.load(s)
	selector := &sad.SASelector{
		VRFIndex: i,
	}
	min := s.SadbSPIRange.SadbSpirangeMin
	max := s.SadbSPIRange.SadbSpirangeMax
	var retry int
	var f func() uint32
	if min == max {
		f = func() uint32 {
			return min
		}
		retry = 1 /* once. */
	} else {
		f = func() uint32 {
			return min + rand.Uint32()%(max-min+1)
		}
		retry = NewSPIRetryMax
	}

	sav := sad.SAValue{}
	var err error
	var spi uint32
	for i := 0; i < retry; i++ {
		spi = f()
		selector.SPI = sad.SPI(spi)
		if err = addSA(selector, &sav); err == nil {
			break
		}
		log.Logger.Err("SadbGetSPIMsg Handle err: spi range: %d-%d, spi = %d, retry = %d",
			min, max, spi, retry)
	}

	if err != nil {
		sadbMsg.SadbMsgErrno = uint8(syscall.EEXIST)
		smsg := pfkey.SadbMsgTransport{
			SadbMsg: sadbMsg,
		}
		_ = smsg.Serialize(w)
		return nil
	}

	sa := pfkey.SadbSa{SadbSaSpi: spi}
	smsg := pfkey.SadbMsgTransport{
		sadbMsg,
		[]pfkey.Serializer{
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_SA},
				&sa,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_SRC},
				s.SrcAddress,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_DST},
				s.DstAddress,
			},
		},
	}
	err = smsg.Serialize(w)
	return err
}

type sadbGetMsg struct {
	pfkey.SadbBaseMsg
}

type sadbGetMsgReply struct {
	sa              *pfkey.SadbSa
	currentLifetime *pfkey.SadbLifetime
	hardLifetime    *pfkey.SadbLifetime
	softLifetime    *pfkey.SadbLifetime
	srcAddress      *pfkey.AddrPair
	dstAddress      *pfkey.AddrPair
	authKey         *pfkey.KeyPair
	encKey          *pfkey.KeyPair
}

func (s *sadbGetMsg) Parse(r io.Reader) error {
	err := s.ParseSadbMsg(r)
	if err != nil {
		log.Logger.Err("parse err")
		return err
	}
	/* checking necessary options */
	if s.Sa == nil ||
		(s.SrcAddress == nil && s.DstAddress == nil) {
		log.Logger.Err("option err")
		return syscall.EINVAL
	}
	return err
}

func (s *sadbGetMsg) Handle(w io.Writer, sadbMsg *pfkey.SadbMsg) error {
	i := vrfs.load(s)
	selector := &sad.SASelector{
		VRFIndex: i,
		SPI:      sad.SPI(s.Sa.SadbSaSpi),
	}
	sav, err := findSA(selector)
	if err != nil {
		sadbMsg.SadbMsgErrno = uint8(syscall.ESRCH)
		smsg := pfkey.SadbMsgTransport{
			SadbMsg: sadbMsg,
		}
		_ = smsg.Serialize(w)
		log.Logger.Err("SadbGetMsg Handle err: %v spi %d", syscall.ESRCH, s.Sa.SadbSaSpi)
		return nil
	}
	reply, ok := s.toSadbGetMsgReply(sav, s.Sa.SadbSaSpi)
	if !ok {
		sadbMsg.SadbMsgErrno = uint8(syscall.EINVAL)
		smsg := pfkey.SadbMsgTransport{
			SadbMsg: sadbMsg,
		}
		_ = smsg.Serialize(w)
		log.Logger.Err("SadbGetMsg Handle err: %v spi %d", syscall.EINVAL, s.Sa.SadbSaSpi)
		return nil
	}

	serializer := []pfkey.Serializer{
		&pfkey.SadbExtTransport{
			&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_SA},
			reply.sa,
		},
		&pfkey.SadbExtTransport{
			&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_LIFETIME_CURRENT},
			reply.currentLifetime,
		},
		&pfkey.SadbExtTransport{
			&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_LIFETIME_HARD},
			reply.hardLifetime,
		},
		&pfkey.SadbExtTransport{
			&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_LIFETIME_SOFT},
			reply.softLifetime,
		},
		&pfkey.SadbExtTransport{
			&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_SRC},
			reply.srcAddress,
		},
		&pfkey.SadbExtTransport{
			&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_DST},
			reply.dstAddress,
		},
		&pfkey.SadbExtTransport{
			&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_KEY_ENCRYPT},
			reply.encKey,
		},
	}

	if reply.authKey != nil {
		serializer = append(serializer,
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_KEY_AUTH},
				reply.authKey,
			})
	}

	smsg := pfkey.SadbMsgTransport{
		sadbMsg,
		serializer,
	}
	err = smsg.Serialize(w)
	return err
}

type sadbDeleteMsg struct {
	sadbGetMsg
}

func (s *sadbDeleteMsg) Parse(r io.Reader) error {
	smsg := sadbGetMsg{}
	err := smsg.Parse(r)
	if err != nil {
		return err
	}
	*s = sadbDeleteMsg{smsg}
	return nil
}

func (s *sadbDeleteMsg) Handle(w io.Writer, sadbMsg *pfkey.SadbMsg) error {
	log.Logger.Info("SadbDeleteMsg: handle spi %d", s.Sa.SadbSaSpi)

	i := vrfs.load(s)
	selector := &sad.SASelector{
		VRFIndex: i,
		SPI:      sad.SPI(s.Sa.SadbSaSpi),
	}
	deleteSA(selector)
	smsg := pfkey.SadbMsgTransport{
		sadbMsg,
		[]pfkey.Serializer{
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_SA},
				s.Sa,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_SRC},
				s.SrcAddress,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_DST},
				s.DstAddress,
			},
		},
	}
	err := smsg.Serialize(w)
	return err
}

type sadbRegisterMsg struct {
	pfkey.SadbBaseMsg
}

func (s *sadbRegisterMsg) Parse(r io.Reader) error {
	return nil
}

func (s *sadbRegisterMsg) Handle(w io.Writer, sadbMsg *pfkey.SadbMsg) error {
	// XXX: regist pid/seq to memory.
	smsg := pfkey.SadbMsgTransport{
		sadbMsg,
		[]pfkey.Serializer{
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_SUPPORTED_AUTH},
				&pfkey.SupportedAlgPair{
					Sup: pfkey.SadbSupported{0},
					Alg: *getSupportedAuth(),
				},
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_SUPPORTED_ENCRYPT},
				&pfkey.SupportedAlgPair{
					Sup: pfkey.SadbSupported{0},
					Alg: *getSupportedEnc(),
				},
			},
		},
	}
	err := smsg.Serialize(w)
	return err
}

type sadbXSPDAddMsg struct {
	pfkey.SadbBaseMsg
}

func (s *sadbXSPDAddMsg) Parse(r io.Reader) error {
	err := s.ParseSadbMsg(r)
	if err != nil {
		log.Logger.Err("parse err")
		return err
	}
	/* checking necessary options */
	if s.Policy == nil ||
		(s.SrcAddress == nil && s.DstAddress == nil) {
		log.Logger.Err("option err")
		return syscall.EINVAL
	}
	return err
}

func (s *sadbXSPDAddMsg) Handle(w io.Writer, sadbMsg *pfkey.SadbMsg) error {
	var spi uint32
	var err error

	i := vrfs.load(s)
	selector := &sad.SASelector{
		VRFIndex: i,
	}
	if s.Policy.TunnelSrcAddr != nil &&
		s.Policy.TunnelDstAddr != nil {
		spi, err = findSPIbyIP(selector, s.Policy.TunnelSrcAddr.ToIPNet(0).IP,
			s.Policy.TunnelDstAddr.ToIPNet(0).IP)
		if err != nil {
			sadbMsg.SadbMsgErrno = uint8(syscall.ESRCH)
			smsg := pfkey.SadbMsgTransport{
				SadbMsg: sadbMsg,
			}
			_ = smsg.Serialize(w)
			log.Logger.Err("SadbXSPDAddMsg Handle err: %v", syscall.ESRCH)
			return nil
		}
		selector.SPI = sad.SPI(spi)
		if ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir) == ipsec.DirectionTypeIn {
			log.Logger.Info("enable spi:%d inbound", spi)
			enableSA(selector, ipsec.DirectionTypeIn)
		} else if ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir) == ipsec.DirectionTypeOut {
			log.Logger.Info("enable spi:%d outbound", spi)
			enableSA(selector, ipsec.DirectionTypeOut)
		} else {
			log.Logger.Err("no direction spi:%d", spi)
		}
	}
	sps, spv := s.toSadbSPSSPV(i)
	if spi != 0 {
		spv.State = spd.Completed
	}
	spv.SPI = spi
	spdi, err := addSP(ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir), sps, spv)
	log.Logger.Info("SadbXSPDAddMsg: add spdi %d, spi %d", spdi, spi)
	if err != nil {
		sadbMsg.SadbMsgErrno = uint8(syscall.EEXIST)
		smsg := pfkey.SadbMsgTransport{
			SadbMsg: sadbMsg,
		}
		_ = smsg.Serialize(w)
		log.Logger.Err("SadbXSPDAddMsg Handle err: %v", syscall.EEXIST)
		return nil
	}
	if spi != 0 {
		log.Logger.Info("SadbXSPDAddMsg: completed spdi %d, spi %d", spdi, spi)
	}
	s.Policy.Policy.SadbXPolicyID = spdi
	smsg := pfkey.SadbMsgTransport{
		sadbMsg,
		[]pfkey.Serializer{
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_X_EXT_POLICY},
				s.Policy,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_SRC},
				s.SrcAddress,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_DST},
				s.DstAddress,
			},
		},
	}
	err = smsg.Serialize(w)
	return err
}

type sadbXSPDUpdateMsg struct {
	sadbXSPDAddMsg
}

func (s *sadbXSPDUpdateMsg) Handle(w io.Writer, sadbMsg *pfkey.SadbMsg) error {
	var spi uint32
	var err error

	i := vrfs.load(s)
	selector := &sad.SASelector{
		VRFIndex: i,
	}
	if s.Policy.TunnelSrcAddr != nil &&
		s.Policy.TunnelDstAddr != nil {
		spi, err = findSPIbyIP(selector, s.Policy.TunnelSrcAddr.ToIPNet(0).IP,
			s.Policy.TunnelDstAddr.ToIPNet(0).IP)
		if err != nil {
			sadbMsg.SadbMsgErrno = uint8(syscall.EINVAL)
			smsg := pfkey.SadbMsgTransport{
				SadbMsg: sadbMsg,
			}
			_ = smsg.Serialize(w)
			log.Logger.Err("SadbXSPDUpdateMsg Handle err: %v", syscall.EINVAL)
			return nil
		}
		selector.SPI = sad.SPI(spi)
		if ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir) == ipsec.DirectionTypeIn {
			log.Logger.Info("enable spi:%d inbound", spi)
			enableSA(selector, ipsec.DirectionTypeIn)
		} else if ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir) == ipsec.DirectionTypeOut {
			log.Logger.Info("enable spi:%d outbound", spi)
			enableSA(selector, ipsec.DirectionTypeOut)
		}
	}
	log.Logger.Info("get spi:%d", spi)
	log.Logger.Info("receive policy_id :%d", s.Policy.Policy.SadbXPolicyID)
	sps, spvNew := s.toSadbSPSSPV(i)
	spvOld, ok := findSP(ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir), sps)
	if !ok {
		sadbMsg.SadbMsgErrno = uint8(syscall.EINVAL)
		smsg := pfkey.SadbMsgTransport{
			SadbMsg: sadbMsg,
		}
		_ = smsg.Serialize(w)
		log.Logger.Err("SadbXSPDUpdateMsg Handle err: %v", syscall.EINVAL)
		return nil
	}
	// directly modified spd entry.
	spvOld.Policy = spvNew.Policy
	spvOld.Priority = spvNew.Priority
	spvOld.Protocol = spvNew.Protocol
	spvOld.Mode = spvNew.Mode
	spvOld.Level = spvNew.Level
	spvOld.RequestID = spvNew.RequestID
	spvOld.LocalEPIP = spvNew.LocalEPIP
	spvOld.RemoteEPIP = spvNew.RemoteEPIP
	if spi != 0 {
		log.Logger.Info("set spi:%d", spi)
		spvOld.SPI = spi
		spvOld.State = spd.Completed
		err = updateSP(ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir), sps, spvOld)
		if err != nil {
			sadbMsg.SadbMsgErrno = uint8(syscall.EINVAL)
			smsg := pfkey.SadbMsgTransport{
				SadbMsg: sadbMsg,
			}
			_ = smsg.Serialize(w)
			log.Logger.Err("SadbXSPDUpdateMsg Handle err: %v", syscall.EINVAL)
			return nil
		}
	}
	s.Policy.Policy.SadbXPolicyID = spvOld.EntryID
	smsg := pfkey.SadbMsgTransport{
		sadbMsg,
		[]pfkey.Serializer{
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_X_EXT_POLICY},
				s.Policy,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_SRC},
				s.SrcAddress,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_DST},
				s.DstAddress,
			},
		},
	}
	err = smsg.Serialize(w)
	return err
}

func (s *sadbXSPDUpdateMsg) Parse(r io.Reader) error {
	smsg := sadbXSPDAddMsg{}
	err := smsg.Parse(r)
	if err != nil {
		return err
	}
	*s = sadbXSPDUpdateMsg{smsg}
	return nil
}

type sadbXSPDGetMsg struct {
	pfkey.SadbBaseMsg
}

func (s *sadbXSPDGetMsg) Parse(r io.Reader) error {
	err := s.ParseSadbMsg(r)
	if err != nil {
		log.Logger.Err("parse err")
		return err
	}
	if s.Policy == nil {
		log.Logger.Err("option err")
		return syscall.EINVAL
	}
	return nil
}

type sadbXSPDGetMsgReply struct {
	sadbXSPDAddMsg
}

func (s *sadbXSPDGetMsg) Handle(w io.Writer, sadbMsg *pfkey.SadbMsg) error {
	i := vrfs.load(s)
	selector := &spd.SPSelector{
		CSPSelector: ipsec.CSPSelector{
			VRFIndex: i,
		},
	}
	log.Logger.Info("SadbXSPDGetMsg: spdi %d, priority %d",
		s.Policy.Policy.SadbXPolicyID, s.Policy.Policy.SadbXpolicyPriority)
	spv, ok := findSPByEntryID(selector, s.Policy.Policy.SadbXPolicyID)
	if !ok {
		sadbMsg.SadbMsgErrno = uint8(syscall.ESRCH)
		smsg := pfkey.SadbMsgTransport{
			SadbMsg: sadbMsg,
		}
		_ = smsg.Serialize(w)
		log.Logger.Err("SadbXSPDGetMsg Handle err: %v", syscall.ESRCH)
		return nil
	}
	reply := toSadbXSPDGetMsgReply(&spv.SPSelector, spv)
	smsg := pfkey.SadbMsgTransport{
		sadbMsg,
		[]pfkey.Serializer{
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_X_EXT_POLICY},
				reply.Policy,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_SRC},
				reply.SrcAddress,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_DST},
				reply.DstAddress,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_LIFETIME_CURRENT},
				reply.CurrentLifetime,
			},
		},
	}
	err := smsg.Serialize(w)
	return err
}

type sadbXSPDDeleteMsg struct {
	pfkey.SadbBaseMsg
}

func (s *sadbXSPDDeleteMsg) Parse(r io.Reader) error {
	err := s.ParseSadbMsg(r)
	if err != nil {
		log.Logger.Err("parse err")
		return err
	}
	/* checking necessary options */
	if s.Policy == nil ||
		(s.SrcAddress == nil && s.DstAddress == nil) {
		log.Logger.Err("option err")
		return syscall.EINVAL
	}
	return err
}

func (s *sadbXSPDDeleteMsg) Handle(w io.Writer, sadbMsg *pfkey.SadbMsg) error {
	i := vrfs.load(s)
	sps := s.toSadbSPS(i)
	deleteSP(ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir), sps)
	smsg := pfkey.SadbMsgTransport{
		sadbMsg,
		[]pfkey.Serializer{
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_X_EXT_POLICY},
				s.Policy,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_SRC},
				s.SrcAddress,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_DST},
				s.DstAddress,
			},
		},
	}
	err := smsg.Serialize(w)
	return err
}

type sadbDumpMsg struct {
	sadbGetMsg
}

func (s *sadbDumpMsg) Parse(r io.Reader) error {
	return nil
}

func (s *sadbDumpMsg) Handle(w io.Writer, sadbMsg *pfkey.SadbMsg) error {
	i := vrfs.load(s)
	selector := &sad.SASelector{
		VRFIndex: i,
	}
	sad := cloneSA(selector)
	spew.Dump(sad)
	nSad := len(sad)
	for spi, sav := range sad {
		reply, ok := s.toSadbGetMsgReply(&sav, uint32(spi))
		if !ok {
			return syscall.EINVAL
		}
		if nSad == 1 {
			sadbMsg.SadbMsgSeq = 0
		}
		nSad--

		serializer := []pfkey.Serializer{
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_SA},
				reply.sa,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_LIFETIME_CURRENT},
				reply.currentLifetime,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_LIFETIME_HARD},
				reply.hardLifetime,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_LIFETIME_SOFT},
				reply.softLifetime,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_SRC},
				reply.srcAddress,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_DST},
				reply.dstAddress,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_KEY_ENCRYPT},
				reply.encKey,
			},
		}

		if reply.authKey != nil {
			serializer = append(serializer,
				&pfkey.SadbExtTransport{
					&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_KEY_AUTH},
					reply.authKey,
				})
		}

		smsg := pfkey.SadbMsgTransport{
			sadbMsg,
			serializer,
		}
		err := smsg.Serialize(w)
		if err != nil {
			return err
		}
	}
	return nil
}

type sadbExpireMsg struct {
	sa              *pfkey.SadbSa
	currentLifetime *pfkey.SadbLifetime
	hardLifetime    *pfkey.SadbLifetime
	softLifetime    *pfkey.SadbLifetime
	srcAddress      *pfkey.AddrPair
	dstAddress      *pfkey.AddrPair
}

type sadbAcquireMsg struct {
	sa         *pfkey.SadbSa
	srcAddress *pfkey.AddrPair
	dstAddress *pfkey.AddrPair
	Policy     *pfkey.Policy
}

type vrfMap struct {
	sm sync.Map
}

func (v *vrfMap) store(h pfkey.ParseHandler, i vswitch.VRFIndex) {
	v.sm.Store(h, i)
}

func (v *vrfMap) load(h pfkey.ParseHandler) vswitch.VRFIndex {
	if i, ok := v.sm.Load(h); ok {
		return i.(vswitch.VRFIndex)
	}
	panic("No vrf index found.")
}

func (v *vrfMap) delete(h pfkey.ParseHandler) {
	v.sm.Delete(h)
}

var vrfs = vrfMap{}

var msgMuxDefault = pfkey.MsgMux{
	pfkey.SADB_GETSPI:      &sadbGetSPIMsg{},
	pfkey.SADB_UPDATE:      &sadbUpdateMsg{},
	pfkey.SADB_ADD:         &sadbAddMsg{},
	pfkey.SADB_DELETE:      &sadbDeleteMsg{},
	pfkey.SADB_GET:         &sadbGetMsg{},
	pfkey.SADB_REGISTER:    &sadbRegisterMsg{},
	pfkey.SADB_DUMP:        &sadbDumpMsg{},
	pfkey.SADB_X_SPDADD:    &sadbXSPDAddMsg{},
	pfkey.SADB_X_SPDUPDATE: &sadbXSPDUpdateMsg{},
	pfkey.SADB_X_SPDGET:    &sadbXSPDGetMsg{},
	pfkey.SADB_X_SPDDELETE: &sadbXSPDDeleteMsg{},
}

// NewMsgMux returns pfkey.MsgMux for pfkey server.
func NewMsgMux() pfkey.MsgMux {
	return msgMuxDefault
}

// RecieverMsgMux Msg.
type RecieverMsgMux struct {
	pfkey.MsgMux
}

// NewMsgMuxForVRF returns pfkey.MsgMux for earch VRF pfkey servers.
func NewMsgMuxForVRF(i vswitch.VRFIndex) RecieverMsgMux {
	log.Logger.Info("NewMsgMuxForVRF: vrf %d", i)
	msgMux := RecieverMsgMux{
		pfkey.MsgMux{
			pfkey.SADB_GETSPI:      &sadbGetSPIMsg{},
			pfkey.SADB_UPDATE:      &sadbUpdateMsg{},
			pfkey.SADB_ADD:         &sadbAddMsg{},
			pfkey.SADB_DELETE:      &sadbDeleteMsg{},
			pfkey.SADB_GET:         &sadbGetMsg{},
			pfkey.SADB_REGISTER:    &sadbRegisterMsg{},
			pfkey.SADB_DUMP:        &sadbDumpMsg{},
			pfkey.SADB_X_SPDADD:    &sadbXSPDAddMsg{},
			pfkey.SADB_X_SPDUPDATE: &sadbXSPDUpdateMsg{},
			pfkey.SADB_X_SPDGET:    &sadbXSPDGetMsg{},
			pfkey.SADB_X_SPDDELETE: &sadbXSPDDeleteMsg{},
		},
	}
	for _, p := range msgMux.MsgMux {
		vrfs.store(p, i)
	}
	return msgMux
}

// Free delete map entry in vrfMap."
func (m *RecieverMsgMux) Free() {
	for _, p := range m.MsgMux {
		vrfs.delete(p)
	}
}
