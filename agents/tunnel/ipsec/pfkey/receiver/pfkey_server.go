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
	"io"
	"log"
	"math/rand"
	"sync"
	"syscall"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/pfkey"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/sad"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/spd"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
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
	log.Printf("SadbAddMsg: handle spi %d\n", s.Sa.SadbSaSpi)
	var i vswitch.VRFIndex
	var ok bool

	if i, ok = vrfMap[s]; !ok {
		panic("No vrf index found.")
	}
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
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_LIFETIME_HARD},
				s.HardLifetime,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_LIFETIME_SOFT},
				s.SoftLifetime,
			},
		},
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
	var i vswitch.VRFIndex
	var ok bool

	if i, ok = vrfMap[s]; !ok {
		panic("No vrf index found.")
	}
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
		log.Printf("SadbUpdateMsg Handle err: %v\n", err.(syscall.Errno))
		return nil
	}
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
	err = smsg.Serialize(w)
	return err
}

type sadbGetSPIMsg struct {
	pfkey.SadbBaseMsg
}

func (s *sadbGetSPIMsg) Parse(r io.Reader) error {
	err := s.ParseSadbMsg(r)
	if err != nil {
		log.Println("parse err")
		return err
	}
	/* checking necessary options */
	if (s.SrcAddress == nil && s.DstAddress == nil) ||
		s.SadbSPIRange == nil {
		log.Println("option err")
		return syscall.EINVAL
	}
	return err
}

func (s *sadbGetSPIMsg) Handle(w io.Writer, sadbMsg *pfkey.SadbMsg) error {
	var i vswitch.VRFIndex
	var ok bool

	if i, ok = vrfMap[s]; !ok {
		panic("No vrf index found.")
	}
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
		log.Printf("SadbGetSPIMsg Handle err: spi range: %d-%d, spi = %d, retry = %d\n",
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
		log.Println("parse err")
		return err
	}
	/* checking necessary options */
	if s.Sa == nil ||
		(s.SrcAddress == nil && s.DstAddress == nil) {
		log.Println("option err")
		return syscall.EINVAL
	}
	return err
}

func (s *sadbGetMsg) Handle(w io.Writer, sadbMsg *pfkey.SadbMsg) error {
	var i vswitch.VRFIndex
	var ok bool

	if i, ok = vrfMap[s]; !ok {
		panic("No vrf index found.")
	}
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
		log.Printf("SadbGetMsg Handle err: %v spi %d\n", syscall.ESRCH, s.Sa.SadbSaSpi)
		return nil
	}
	reply, ok := s.toSadbGetMsgReply(sav, s.Sa.SadbSaSpi)
	if !ok {
		sadbMsg.SadbMsgErrno = uint8(syscall.EINVAL)
		smsg := pfkey.SadbMsgTransport{
			SadbMsg: sadbMsg,
		}
		_ = smsg.Serialize(w)
		log.Printf("SadbGetMsg Handle err: %v spi %d\n", syscall.EINVAL, s.Sa.SadbSaSpi)
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
	log.Printf("SadbDeleteMsg: handle spi %d\n", s.Sa.SadbSaSpi)
	var i vswitch.VRFIndex
	var ok bool

	if i, ok = vrfMap[s]; !ok {
		panic("No vrf index found.")
	}
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
		log.Println("parse err")
		return err
	}
	/* checking necessary options */
	if s.Policy == nil ||
		(s.SrcAddress == nil && s.DstAddress == nil) {
		log.Println("option err")
		return syscall.EINVAL
	}
	return err
}

func (s *sadbXSPDAddMsg) Handle(w io.Writer, sadbMsg *pfkey.SadbMsg) error {
	var spi uint32
	var err error
	var i vswitch.VRFIndex
	var ok bool

	if i, ok = vrfMap[s]; !ok {
		panic("No vrf index found.")
	}
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
			log.Printf("SadbXSPDAddMsg Handle err: %v\n", syscall.ESRCH)
			return nil
		}
		selector.SPI = sad.SPI(spi)
		if ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir) == ipsec.DirectionTypeIn {
			log.Printf("enable spi:%d inbound\n", spi)
			enableSA(selector, ipsec.DirectionTypeIn)
		} else if ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir) == ipsec.DirectionTypeOut {
			log.Printf("enable spi:%d outbound\n", spi)
			enableSA(selector, ipsec.DirectionTypeOut)
		} else {
			log.Printf("no direction spi:%d\n", spi)
		}
	}
	sps, spv := s.toSadbSPSSPV(i)
	if spi != 0 {
		spv.State = spd.Completed
	}
	spv.SPI = spi
	spdi, err := addSP(ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir), sps, spv)
	log.Printf("SadbXSPDAddMsg: add spdi %d, spi %d\n", spdi, spi)
	if err != nil {
		sadbMsg.SadbMsgErrno = uint8(syscall.EEXIST)
		smsg := pfkey.SadbMsgTransport{
			SadbMsg: sadbMsg,
		}
		_ = smsg.Serialize(w)
		log.Printf("SadbXSPDAddMsg Handle err: %v\n", syscall.EEXIST)
		return nil
	}
	if spi != 0 {
		log.Printf("SadbXSPDAddMsg: completed spdi %d, spi %d\n", spdi, spi)
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
	var i vswitch.VRFIndex
	var ok bool

	if i, ok = vrfMap[s]; !ok {
		panic("No vrf index found.")
	}
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
			log.Printf("SadbXSPDUpdateMsg Handle err: %v\n", syscall.EINVAL)
			return nil
		}
		selector.SPI = sad.SPI(spi)
		if ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir) == ipsec.DirectionTypeIn {
			log.Printf("enable spi:%d inbound\n", spi)
			enableSA(selector, ipsec.DirectionTypeIn)
		} else if ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir) == ipsec.DirectionTypeOut {
			log.Printf("enable spi:%d outbound\n", spi)
			enableSA(selector, ipsec.DirectionTypeOut)
		}
	}
	log.Printf("get spi:%d\n", spi)
	log.Printf("receive policy_id :%d\n", s.Policy.Policy.SadbXPolicyID)
	sps, spvNew := s.toSadbSPSSPV(i)
	spvOld, ok := findSP(ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir), sps)
	if !ok {
		sadbMsg.SadbMsgErrno = uint8(syscall.EINVAL)
		smsg := pfkey.SadbMsgTransport{
			SadbMsg: sadbMsg,
		}
		_ = smsg.Serialize(w)
		log.Printf("SadbXSPDUpdateMsg Handle err: %v\n", syscall.EINVAL)
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
		log.Printf("set spi:%d\n", spi)
		spvOld.SPI = spi
		spvOld.State = spd.Completed
		err = updateSP(ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir), sps, spvOld)
		if err != nil {
			sadbMsg.SadbMsgErrno = uint8(syscall.EINVAL)
			smsg := pfkey.SadbMsgTransport{
				SadbMsg: sadbMsg,
			}
			_ = smsg.Serialize(w)
			log.Printf("SadbXSPDUpdateMsg Handle err: %v\n", syscall.EINVAL)
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
		log.Println("parse err")
		return err
	}
	if s.Policy == nil {
		log.Println("option err")
		return syscall.EINVAL
	}
	return nil
}

type sadbXSPDGetMsgReply struct {
	sadbXSPDAddMsg
}

func (s *sadbXSPDGetMsg) Handle(w io.Writer, sadbMsg *pfkey.SadbMsg) error {
	var i vswitch.VRFIndex
	var ok bool

	if i, ok = vrfMap[s]; !ok {
		panic("No vrf index found.")
	}
	selector := &spd.SPSelector{
		CSPSelector: ipsec.CSPSelector{
			VRFIndex: i,
		},
	}
	log.Printf("SadbXSPDGetMsg: spdi %d, priority %d\n",
		s.Policy.Policy.SadbXPolicyID, s.Policy.Policy.SadbXpolicyPriority)
	spv, ok := findSPByEntryID(selector, s.Policy.Policy.SadbXPolicyID)
	if !ok {
		sadbMsg.SadbMsgErrno = uint8(syscall.ESRCH)
		smsg := pfkey.SadbMsgTransport{
			SadbMsg: sadbMsg,
		}
		_ = smsg.Serialize(w)
		log.Printf("SadbXSPDGetMsg Handle err: %v\n", syscall.ESRCH)
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
		log.Println("parse err")
		return err
	}
	/* checking necessary options */
	if s.Policy == nil ||
		(s.SrcAddress == nil && s.DstAddress == nil) {
		log.Println("option err")
		return syscall.EINVAL
	}
	return err
}

func (s *sadbXSPDDeleteMsg) Handle(w io.Writer, sadbMsg *pfkey.SadbMsg) error {
	var i vswitch.VRFIndex
	var ok bool

	if i, ok = vrfMap[s]; !ok {
		panic("No vrf index found.")
	}
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
	var i vswitch.VRFIndex
	var ok bool

	if i, ok = vrfMap[s]; !ok {
		panic("No vrf index found.")
	}
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

var vrfMap = make(map[pfkey.ParseHandler]vswitch.VRFIndex)
var lock sync.Mutex

type RecieverMsgMux struct {
	pfkey.MsgMux
}

// NewMsgMuxForVRF returns pfkey.MsgMux for earch VRF pfkey servers.
func NewMsgMuxForVRF(i vswitch.VRFIndex) RecieverMsgMux {
	lock.Lock()
	defer lock.Unlock()
	log.Printf("NewMsgMuxForVRF: vrf %d\n", i)
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
		vrfMap[p] = i
	}
	return msgMux
}

// Free delete map entry in vrfMap."
func (m *RecieverMsgMux) Free() {
	for _, p := range m.MsgMux {
		delete(vrfMap, p)
	}
}
