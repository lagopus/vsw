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
	"bytes"
	"io"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/connections"
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

func sendError(w io.Writer, sadbMsg *pfkey.SadbMsg, errno uint8) {
	sadbMsg.SadbMsgErrno = errno
	smsg := pfkey.SadbMsgTransport{
		SadbMsg: sadbMsg,
	}
	_ = smsg.Serialize(w)
}

func (s *sadbAddMsg) addSA(selector *sad.SASelector) error {
	sav, ok := s.toSadbSaSAV()
	if !ok {
		return syscall.EINVAL
	}
	log.Logger.Info("SadbAddMsg: add sa spi %d", s.Sa.SadbSaSpi)
	selector.SPI = sad.SPI(s.Sa.SadbSaSpi)
	if err := addSA(selector, sav); err != nil {
		return syscall.EEXIST
	}
	return nil
}

func (s *sadbAddMsg) validCipherAlgo(algo ipsec.CipherAlgo,
	sav *sad.SAValue) bool {

	if algoInfo, ok := ipsec.SupportedCipherAlgo[algo]; ok {
		var key []byte
		var keyLen uint16
		if s.EncKey != nil && s.EncKey.Key != nil {
			keyLen = s.EncKey.SadbKey.SadbKeyBits / 8
			if keyLen <= uint16(len(*s.EncKey.Key)) {
				key = (*s.EncKey.Key)[:keyLen]
			}
		}
		if value, ok := algoInfo.Algos[keyLen]; ok {
			sav.CipherAlgoType = value.Type

			if key != nil {
				sav.CipherKey = append(sav.CipherKey, key...)
			}
			return true
		}
	}

	log.Logger.Err("no encAlgo(Cipher): %v, KeyBits: %v",
		s.Sa.SadbSaEncrypt, s.EncKey.SadbKey.SadbKeyBits)
	return false
}

func (s *sadbAddMsg) validAuthAlgo(algo ipsec.AuthAlgo,
	sav *sad.SAValue) bool {

	if algoInfo, ok := ipsec.SupportedAuthAlgo[algo]; ok {
		var key []byte
		var keyLen uint16
		if s.AuthKey != nil && s.AuthKey.Key != nil {
			keyLen = s.AuthKey.SadbKey.SadbKeyBits / 8
			if keyLen <= uint16(len(*s.AuthKey.Key)) {
				key = (*s.AuthKey.Key)[:keyLen]
			}
		}
		if value, ok := algoInfo.Algos[keyLen]; ok {
			sav.AuthAlgoType = value.Type

			if key != nil {
				sav.AuthKey = append(sav.AuthKey, key...)
			}
			return true
		}
	}

	log.Logger.Err("no authAlgo: %v, KeyBits: %v",
		s.Sa.SadbSaAuth, s.AuthKey.SadbKey.SadbKeyBits)
	return false
}

func (s *sadbAddMsg) validAeadAlgo(algo ipsec.AeadAlgo,
	sav *sad.SAValue) bool {

	if algoInfo, ok := ipsec.SupportedAeadAlgo[algo]; ok {
		var key []byte
		var keyLen uint16
		if s.EncKey != nil && s.EncKey.Key != nil {
			keyLen = s.EncKey.SadbKey.SadbKeyBits / 8
			if keyLen <= uint16(len(*s.EncKey.Key)) {
				key = (*s.EncKey.Key)[:keyLen]
			}
		}
		if value, ok := algoInfo.Algos[keyLen]; ok {
			sav.AeadAlgoType = value.Type

			if key != nil {
				sav.AeadKey = append(sav.AeadKey, key...)
			}
			return true
		}
	}

	log.Logger.Err("no encAlgo(AEAD): %v, KeyBits: %v",
		s.Sa.SadbSaEncrypt, s.EncKey.SadbKey.SadbKeyBits)
	return false
}

func (s *sadbAddMsg) toSadbSaSAV() (*sad.SAValue, bool) {
	if s.Sa == nil {
		log.Logger.Err("invalid sa: %v", s.Sa)
		return nil, false
	}
	sav := sad.SAValue{
		CSAValue: ipsec.CSAValue{
			Flags: ipsec.IP4Tunnel,
		},
	}

	if algo, ok := encTbl[s.Sa.SadbSaEncrypt]; ok {
		// Cipher/Auth algo.
		//// Cipher algo.
		if ok := s.validCipherAlgo(algo, &sav); !ok {
			log.Logger.Err("no encAlgo(Cipher): %v", s.Sa.SadbSaEncrypt)
			return nil, ok
		}

		//// Auth algo.
		if algo, ok := authTbl[s.Sa.SadbSaAuth]; ok {
			if ok := s.validAuthAlgo(algo, &sav); !ok {
				log.Logger.Err("no authAlgo: %v", s.Sa.SadbSaAuth)
				return nil, ok
			}
		} else {
			log.Logger.Err("no authAlgo: %v", s.Sa.SadbSaAuth)
			return nil, ok
		}
	} else if algo, ok := aeadTbl[s.Sa.SadbSaEncrypt]; ok {
		// AEAD algo.
		if ok := s.validAeadAlgo(algo, &sav); !ok {
			log.Logger.Err("no encAlgo(AEAD): %v", s.Sa.SadbSaEncrypt)
			return nil, ok
		}
	} else {
		log.Logger.Err("no encAlgo: %v", s.Sa.SadbSaEncrypt)
		return nil, ok
	}

	sav.State = sad.SAState(s.Sa.SadbSaState)
	sav.LocalEPIP = s.SrcAddress.ToIPNet().IP
	sav.RemoteEPIP = s.DstAddress.ToIPNet().IP
	// XXX: NOT support lifetime allocations
	now := time.Now()
	if s.HardLifetime != nil {
		log.Logger.Info("SadbAddMsg: spi %d, hard addtime %d", s.Sa.SadbSaSpi,
			s.HardLifetime.SadbLifetimeAddtime)
		if s.HardLifetime.SadbLifetimeAddtime != 0 {
			sav.LifeTimeHard = now.Add(time.Duration(
				s.HardLifetime.SadbLifetimeAddtime) * time.Second)
		} else {
			sav.LifeTimeHard = time.Time{}
		}
		sav.LifeTimeByteHard = s.HardLifetime.SadbLifetimeBytes

	}
	if s.SoftLifetime != nil {
		log.Logger.Info("SadbAddMsg: spi %d, soft addtime %d", s.Sa.SadbSaSpi,
			s.SoftLifetime.SadbLifetimeAddtime)
		if s.SoftLifetime.SadbLifetimeAddtime != 0 {
			sav.LifeTimeSoft = now.Add(time.Duration(
				s.SoftLifetime.SadbLifetimeAddtime) * time.Second)
		} else {
			sav.LifeTimeSoft = time.Time{}
		}

		sav.LifeTimeByteSoft = s.SoftLifetime.SadbLifetimeBytes
	}
	sav.LifeTimeCurrent = now
	sav.Protocol = ipsec.SecurityProtocolTypeESP //Only ESP supported.
	if s.NatTType != nil {
		if s.NatTType.SadbXNatTTypeType != uint8(ipsec.UDPEncapESPinUDP) ||
			s.NatTSrcPort == nil || s.NatTDstPort == nil {
			log.Logger.Err("natt invalid params: type %v, sport %v, dport %v", s.NatTType.SadbXNatTTypeType, s.NatTSrcPort, s.NatTDstPort)
			return nil, false
		}
		sav.EncapType = ipsec.UDPEncapESPinUDP //Only UDP Encap supported.
		sav.EncapProtocol = ipsec.EncapProtoUDP
		sav.EncapSrcPort = s.NatTSrcPort.SadbXNatTPortPort
		sav.EncapDstPort = s.NatTDstPort.SadbXNatTPortPort
	}
	return &sav, true
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
		sendError(w, sadbMsg, uint8(err.(syscall.Errno)))
		log.Logger.Err("SadbAddMsg Handle err: %v", err.(syscall.Errno))
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

func (s *sadbUpdateMsg) updateSA(selector *sad.SASelector) error {
	sav, ok := s.toSadbSaSAV()
	if !ok {
		return syscall.EINVAL
	}
	sav2, err := findSAByIP(selector, sav.LocalEPIP, sav.RemoteEPIP)
	if err != nil {
		return syscall.ENOENT
	}
	log.Logger.Info("SadbUpdateMsg: update sa spi %d", s.Sa.SadbSaSpi)
	sav2.CipherAlgoType = sav.CipherAlgoType
	sav2.CipherKey = sav.CipherKey
	sav2.AuthAlgoType = sav.AuthAlgoType
	sav2.AuthKey = sav.AuthKey
	sav2.AeadAlgoType = sav.AeadAlgoType
	sav2.AeadKey = sav.AeadKey
	sav2.Protocol = sav.Protocol
	sav2.Flags = sav.Flags
	sav2.State = sav.State
	if s.CurrentLifetime != nil {
		sav2.LifeTimeCurrent = sav.LifeTimeCurrent
		sav2.LifeTimeByteCurrent = sav.LifeTimeByteCurrent
	}
	if s.HardLifetime != nil {
		sav2.LifeTimeHard = sav.LifeTimeHard
		sav2.LifeTimeByteHard = sav.LifeTimeByteHard
	}
	if s.SoftLifetime != nil {
		sav2.LifeTimeSoft = sav.LifeTimeSoft
		sav2.LifeTimeByteSoft = sav.LifeTimeByteSoft
	}
	if s.SoftLifetime != nil {
		sav2.LifeTimeSoft = sav.LifeTimeSoft
		sav2.LifeTimeByteSoft = sav.LifeTimeByteSoft
	}
	if s.NatTType != nil {
		sav2.EncapType = sav.EncapType
		sav2.EncapProtocol = sav.EncapProtocol
		sav2.EncapSrcPort = sav.EncapSrcPort
		sav2.EncapDstPort = sav.EncapDstPort
	}
	return nil
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
		sendError(w, sadbMsg, uint8(err.(syscall.Errno)))
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

func (s *sadbGetMsg) toSadbGetMsgReply(sav *sad.SAValue, spi uint32) (*sadbGetMsgReply, bool) {
	sa := pfkey.SadbSa{
		SadbSaSpi:   spi,
		SadbSaState: uint8(sav.State),
	}

	var aKey *pfkey.KeyPair
	var eKey *pfkey.KeyPair
	if enc, ok := encRTbl[sav.CipherAlgoType]; ok {
		if auth, ok := authRTbl[sav.AuthAlgoType]; ok {
			sa.SadbSaEncrypt = enc
			sa.SadbSaAuth = auth
			aKey = pfkey.ToKeyPair(&sav.AuthKey)
			eKey = pfkey.ToKeyPair(&sav.CipherKey)
		} else {
			return nil, false
		}
	} else if enc, ok := aeadRTbl[sav.AeadAlgoType]; ok {
		sa.SadbSaEncrypt = enc
		eKey = pfkey.ToKeyPair(&sav.AeadKey)
	} else {
		return nil, false
	}

	sAddr := pfkey.AddrPair{
		Addr:     pfkey.SadbAddress{}, // XXX: to set proto, prefixlen?
		SockAddr: pfkey.ToSockaddr(&net.IPNet{IP: sav.LocalEPIP}),
	}
	dAddr := pfkey.AddrPair{
		Addr:     pfkey.SadbAddress{}, // XXX: to set proto, prefixlen?
		SockAddr: pfkey.ToSockaddr(&net.IPNet{IP: sav.RemoteEPIP}),
	}
	cTime := pfkey.SadbLifetime{
		SadbLifetimeBytes:   sav.LifeTimeByteCurrent,
		SadbLifetimeAddtime: uint64(sav.LifeTimeCurrent.Unix()),
		SadbLifetimeUsetime: 0, //XXX
	}
	hTime := pfkey.SadbLifetime{
		SadbLifetimeBytes:   sav.LifeTimeByteHard,
		SadbLifetimeAddtime: uint64(sav.LifeTimeHard.Sub(sav.LifeTimeCurrent).Seconds()),
		SadbLifetimeUsetime: 0, //XXX
	}
	sTime := pfkey.SadbLifetime{
		SadbLifetimeBytes:   sav.LifeTimeByteSoft,
		SadbLifetimeAddtime: uint64(sav.LifeTimeSoft.Sub(sav.LifeTimeCurrent).Seconds()),
		SadbLifetimeUsetime: 0, //XXX
	}

	return &sadbGetMsgReply{
		sa:              &sa,
		currentLifetime: &cTime,
		hardLifetime:    &hTime,
		softLifetime:    &sTime,
		srcAddress:      &sAddr,
		dstAddress:      &dAddr,
		authKey:         aKey,
		encKey:          eKey,
	}, true
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
		sendError(w, sadbMsg, uint8(syscall.EEXIST))
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
		sendError(w, sadbMsg, uint8(syscall.ENOENT))
		log.Logger.Err("SadbGetMsg Handle err: %v spi %d", syscall.ENOENT, s.Sa.SadbSaSpi)
		return nil
	}
	reply, ok := s.toSadbGetMsgReply(sav, s.Sa.SadbSaSpi)
	if !ok {
		sendError(w, sadbMsg, uint8(syscall.EINVAL))
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

func (s *sadbXSPDAddMsg) buildSPSelector(i vswitch.VRFIndex) *spd.SPSelector {
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
		sps.RemotePortRangeEnd = uint16(s.DstAddress.SockAddr.Port())
	} else {
		sps.RemotePortRangeStart = 0
		sps.RemotePortRangeEnd = 65535
	}
	return &sps
}

func (s *sadbXSPDAddMsg) toSadbSPSSPV(i vswitch.VRFIndex) (*spd.SPSelector, *spd.SPValue, error) {
	// parameter check, but this block will move to ipsec/spd?
	if s.Policy.IpsecRequest.SadbXIpsecrequestProto != uint16(vswitch.IPP_ESP) ||
		s.Policy.IpsecRequest.SadbXIpsecrequestMode != uint8(ipsec.ModeTypeTunnel) {
		return nil, nil, syscall.EINVAL
	}
	sps := s.buildSPSelector(i)
	spv := spd.SPValue{
		CSPValue: ipsec.CSPValue{
			Policy:   ipsec.PolicyType(s.Policy.Policy.SadbXPolicyType),
			Priority: int32(s.Policy.Policy.SadbXpolicyPriority),
		},
		Protocol:  ipsec.SecurityProtocolType(ipsec.SecurityProtocolTypeESP), // only support ESP.
		Mode:      ipsec.ModeType(ipsec.ModeTypeTunnel),                      // only support tunnel.
		Level:     ipsec.LevelType(s.Policy.IpsecRequest.SadbXIpsecrequestLevel),
		RequestID: s.Policy.IpsecRequest.SadbXIpsecrequestReqid,
	}
	if s.Policy.TunnelSrcAddr != nil {
		spv.LocalEPIP = *s.Policy.TunnelSrcAddr.ToIPNet(0)
	}
	if s.Policy.TunnelDstAddr != nil {
		spv.RemoteEPIP = *s.Policy.TunnelDstAddr.ToIPNet(0)
	}
	return sps, &spv, nil
}

func (s *sadbXSPDAddMsg) Parse(r io.Reader) error {
	err := s.ParseSadbMsg(r)
	if err != nil {
		log.Logger.Err("parse err %v", err)
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
			sendError(w, sadbMsg, uint8(syscall.ENOENT))
			log.Logger.Err("SadbXSPDAddMsg Handle err: %v", syscall.ENOENT)
			return nil
		}
		selector.SPI = sad.SPI(spi)

		switch ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir) {
		case ipsec.DirectionTypeIn:
			log.Logger.Info("enable spi:%d inbound", spi)
			enableSA(selector, ipsec.DirectionTypeIn)
		case ipsec.DirectionTypeOut:
			log.Logger.Info("enable spi:%d outbound", spi)
			enableSA(selector, ipsec.DirectionTypeOut)
		case ipsec.DirectionTypeFwd:
			// ignore.
		default:
			log.Logger.Err("no direction spi:%d", spi)
			return nil
		}
	}
	sps, spv, err := s.toSadbSPSSPV(i)
	if err != nil {
		sendError(w, sadbMsg, uint8(syscall.EINVAL))
		log.Logger.Err("SadbXSPDAddMsg Handle err: %v", syscall.EINVAL)
		return nil
	}
	if spi != 0 {
		spv.State = spd.Completed
	}
	spv.SPI = spi
	spdi, err := addSP(ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir), sps, spv)
	log.Logger.Info("SadbXSPDAddMsg: add spdi %d, spi %d", spdi, spi)
	if err != nil {
		sendError(w, sadbMsg, uint8(syscall.EEXIST))
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
			sendError(w, sadbMsg, uint8(syscall.EINVAL))
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
	sps, spvNew, err := s.toSadbSPSSPV(i)
	if err != nil {
		sendError(w, sadbMsg, uint8(syscall.EINVAL))
		log.Logger.Err("SadbXSPDUpdateMsg Handle err: %v", syscall.EINVAL)
		return nil
	}
	spvOld, ok := findSP(ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir), sps)
	if !ok {
		sendError(w, sadbMsg, uint8(syscall.EINVAL))
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
			sendError(w, sadbMsg, uint8(syscall.EINVAL))
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
		sendError(w, sadbMsg, uint8(syscall.ENOENT))
		log.Logger.Err("SadbXSPDGetMsg Handle err: %v", syscall.ENOENT)
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
	sadbXSPDAddMsg
}

func (s *sadbXSPDDeleteMsg) toSadbSPS(i vswitch.VRFIndex) *spd.SPSelector {
	sps := s.buildSPSelector(i)
	return sps
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
	err := deleteSP(ipsec.DirectionType(s.Policy.Policy.SadbXPolicyDir), sps)
	if err != nil {
		sendError(w, sadbMsg, uint8(syscall.ENOENT))
		log.Logger.Err("SadbXSPDeleteMsg Handle err: %v", syscall.ENOENT)
		return nil
	}
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
	return smsg.Serialize(w)
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

func (s *sadbExpireMsg) expireMsg(sav *sad.SAValue, spi uint32, isSoft bool) {
	s.sa = &pfkey.SadbSa{
		SadbSaSpi:   spi,
		SadbSaState: uint8(sav.State),
	}
	var ok bool
	if s.sa.SadbSaEncrypt, ok = encRTbl[sav.CipherAlgoType]; ok {
		s.sa.SadbSaAuth, _ = authRTbl[sav.AuthAlgoType]
	} else {
		s.sa.SadbSaEncrypt, _ = aeadRTbl[sav.AeadAlgoType]
	}

	s.srcAddress = &pfkey.AddrPair{
		Addr:     pfkey.SadbAddress{}, // XXX: to set proto, prefixlen?
		SockAddr: pfkey.ToSockaddr(&net.IPNet{IP: sav.LocalEPIP}),
	}
	s.dstAddress = &pfkey.AddrPair{
		Addr:     pfkey.SadbAddress{}, // XXX: to set proto, prefixlen?
		SockAddr: pfkey.ToSockaddr(&net.IPNet{IP: sav.RemoteEPIP}),
	}
	s.currentLifetime = &pfkey.SadbLifetime{
		SadbLifetimeBytes:   sav.LifeTimeByteCurrent,
		SadbLifetimeAddtime: uint64(sav.LifeTimeCurrent.Unix()),
		SadbLifetimeUsetime: 0, //XXX
	}
	if isSoft {
		s.softLifetime = &pfkey.SadbLifetime{
			SadbLifetimeBytes:   sav.LifeTimeByteSoft,
			SadbLifetimeAddtime: uint64(sav.LifeTimeSoft.Sub(sav.LifeTimeCurrent).Seconds()),
			SadbLifetimeUsetime: 0, //XXX
		}
	} else {
		s.hardLifetime = &pfkey.SadbLifetime{
			SadbLifetimeBytes:   sav.LifeTimeByteHard,
			SadbLifetimeAddtime: uint64(sav.LifeTimeHard.Sub(sav.LifeTimeCurrent).Seconds()),
			SadbLifetimeUsetime: 0, //XXX
		}
	}
}

type sadbAcquireMsg struct {
	sa         *pfkey.SadbSa
	srcAddress *pfkey.AddrPair
	dstAddress *pfkey.AddrPair
	Policy     *pfkey.Policy
}

func (s *sadbAcquireMsg) acquireMsg(src *net.IPNet, dst *net.IPNet) {
	s.srcAddress = &pfkey.AddrPair{
		Addr:     pfkey.SadbAddress{}, // XXX: to set proto, prefixlen?
		SockAddr: pfkey.ToSockaddr(src),
	}
	s.dstAddress = &pfkey.AddrPair{
		Addr:     pfkey.SadbAddress{}, // XXX: to set proto, prefixlen?
		SockAddr: pfkey.ToSockaddr(dst),
	}
}

func toIPProto(spt ipsec.SecurityProtocolType) vswitch.IPProto {
	switch spt {
	case ipsec.SecurityProtocolTypeAH:
		return vswitch.IPP_AH
	case ipsec.SecurityProtocolTypeESP:
		return vswitch.IPP_ESP
	default:
		return vswitch.IPP_ESP // only support ESP.
	}

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
			SadbXIpsecrequestProto: uint16(toIPProto(spv.Protocol)),
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

func getSupportedAuth() *[]pfkey.SadbAlg {
	s := []pfkey.SadbAlg{}
	// Auth algo.
	for auth, algo := range authTbl {
		algoInfo := ipsec.SupportedAuthAlgo[algo]
		minKeyLen := algoInfo.MinKeyLen
		maxKeyLen := algoInfo.MaxKeyLen
		a := pfkey.SadbAlg{
			SadbAlgID:      auth,
			SadbAlgMinbits: minKeyLen,
			SadbAlgMaxbits: maxKeyLen,
		}
		s = append(s, a)
	}

	return &s
}

func getSupportedEnc() *[]pfkey.SadbAlg {
	s := []pfkey.SadbAlg{}
	// Cipher algo.
	for enc, algo := range encTbl {
		algoInfo := ipsec.SupportedCipherAlgo[algo]
		minKeyLen := algoInfo.MinKeyLen
		maxKeyLen := algoInfo.MaxKeyLen
		// Prerequisites: same length of IV.
		ivLen := uint8(algoInfo.Algos[minKeyLen].IvLen)
		a := pfkey.SadbAlg{
			SadbAlgID:      enc,
			SadbAlgIvlen:   ivLen,
			SadbAlgMinbits: minKeyLen * 8,
			SadbAlgMaxbits: maxKeyLen * 8,
		}
		s = append(s, a)
	}
	// AEAD algo.
	for aead, algo := range aeadTbl {
		algoInfo := ipsec.SupportedAeadAlgo[algo]
		minKeyLen := algoInfo.MinKeyLen
		maxKeyLen := algoInfo.MaxKeyLen
		// Prerequisites: same length of IV.
		ivLen := uint8(algoInfo.Algos[minKeyLen].IvLen)
		a := pfkey.SadbAlg{
			SadbAlgID:      aead,
			SadbAlgIvlen:   ivLen,
			SadbAlgMinbits: minKeyLen * 8,
			SadbAlgMaxbits: maxKeyLen * 8,
		}
		s = append(s, a)
	}

	return &s
}

func sadbExpire(vrfIndex vswitch.VRFIndex, dir ipsec.DirectionType, spi sad.SPI, sav *sad.SAValue, kind sad.SadbExpireType) bool {
	// TODO: set VRF Index.
	sadbMsg := pfkey.NewSadbMsg(pfkey.SADB_EXPIRE, pfkey.SADB_SATYPE_ESP, 0, 0)
	s := &sadbExpireMsg{}

	if kind == sad.SoftLifetimeExpired {
		s.expireMsg(sav, uint32(spi), true)
		log.Logger.Info("send soft expire message: spi %d", uint32(spi))
	} else {
		s.expireMsg(sav, uint32(spi), false)
		log.Logger.Info("send hard expire message: spi %d", uint32(spi))
	}
	smsg := pfkey.SadbMsgTransport{
		sadbMsg,
		[]pfkey.Serializer{
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_SA},
				s.sa,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_SRC},
				s.srcAddress,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_DST},
				s.dstAddress,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_LIFETIME_CURRENT},
				s.currentLifetime,
			},
		},
	}
	var st *pfkey.SadbExtTransport
	if kind == sad.SoftLifetimeExpired {
		st = &pfkey.SadbExtTransport{&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_LIFETIME_SOFT}, s.softLifetime}
	} else {
		st = &pfkey.SadbExtTransport{&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_LIFETIME_HARD}, s.hardLifetime}
	}
	smsg.Serializer = append(smsg.Serializer, st)
	buf := bytes.Buffer{}
	err := smsg.Serialize(&buf)
	if err != nil {
		log.Logger.Err("SadbExpire: error: %v", err)
		return false
	}
	con := &connections.Connections{}
	con.Write(buf.Bytes())
	return true
}

func sadbAcquire(vrfIndex vswitch.VRFIndex, spEntryID uint32, src *net.IPNet, dst *net.IPNet) bool {
	// TODO: set VRF Index.
	// XXX: use spEntryID
	sadbMsg := pfkey.NewSadbMsg(pfkey.SADB_ACQUIRE, pfkey.SADB_SATYPE_ESP, 0, 0)
	s := &sadbAcquireMsg{}
	s.acquireMsg(src, dst)
	smsg := pfkey.SadbMsgTransport{
		sadbMsg,
		[]pfkey.Serializer{
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_SRC},
				s.srcAddress,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_EXT_ADDRESS_DST},
				s.dstAddress,
			},
			&pfkey.SadbExtTransport{
				&pfkey.SadbExt{SadbExtType: pfkey.SADB_X_EXT_POLICY},
				&pfkey.Policy{}, // XXX: workaround for no charon down.
			},
		},
	}
	buf := bytes.Buffer{}
	err := smsg.Serialize(&buf)
	if err != nil {
		log.Logger.Err("SadbAcquire: error: %v", err)
		return false
	}
	con := &connections.Connections{}
	con.Write(buf.Bytes())
	return true
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
