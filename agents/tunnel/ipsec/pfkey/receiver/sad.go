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
	"net"
	"syscall"
	"time"

	"github.com/lagopus/vsw/agents/tunnel/ipsec/connections"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/pfkey" // XXX
	"github.com/lagopus/vsw/agents/tunnel/ipsec/sad"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/vswitch"

	"github.com/lagopus/vsw/modules/tunnel/log"
)

var mgrs [2]*sad.Mgr

func init() {
	sad.RegisterSadbExpire(sadbExpire)
	sad.RegisterSadbAcquire(sadbAcquire)
	mgrs[0] = sad.GetMgr(ipsec.DirectionTypeIn)
	mgrs[1] = sad.GetMgr(ipsec.DirectionTypeOut)
}

func reserveSA(selector *sad.SASelector, spi uint32) error {
	err := mgrs[0].ReserveSA(selector)
	if err != nil {
		return err
	}
	err = mgrs[1].ReserveSA(selector)
	if err != nil {
		mgrs[0].DeleteSA(selector)
		return err
	}

	return nil
}

func addSA(selector *sad.SASelector, sa *sad.SAValue) error {
	err := mgrs[0].AddSA(selector, sa)
	if err != nil {
		return err
	}
	err = mgrs[1].AddSA(selector, sa)
	if err != nil {
		mgrs[0].DeleteSA(selector)
		return err
	}

	return nil
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

func (s *sadbUpdateMsg) updateSA(selector *sad.SASelector) error {
	sav, ok := s.toSadbSaSAV()
	if !ok {
		return syscall.EINVAL
	}
	sav2, err := findSAByIP(selector, sav.LocalEPIP, sav.RemoteEPIP)
	if err != nil {
		return syscall.EEXIST
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

func findSA(selector *sad.SASelector) (*sad.SAValue, error) {
	// find mgrs[0] only.
	sav, err := mgrs[0].FindSA(selector)
	if err != nil {
		return nil, err
	}
	return sav, nil
}

func cloneSA(selector *sad.SASelector) sad.SAD {
	return mgrs[0].CloneSAD(selector)
}

func enableSA(selector *sad.SASelector, dir ipsec.DirectionType) error {
	// find mgrs[0] only.
	mgr := sad.GetMgr(dir)
	return mgr.EnableSA(selector) // ready to push for C
}

func findSAByIP(selector *sad.SASelector, local net.IP, remote net.IP) (*sad.SAValue, error) {
	// find mgrs[0] only.
	_, sav, err := mgrs[0].FindSAbyIP(selector, local, remote)
	if err != nil {
		return nil, err
	}
	return sav, nil
}

func findSPIbyIP(selector *sad.SASelector, local net.IP, remote net.IP) (uint32, error) {
	// find mgrs[0] only.
	spi, _, err := mgrs[0].FindSAbyIP(selector, local, remote)
	if err != nil {
		// RFC4303 2.1.  Security Parameters Index (SPI)
		// The SPI value of zero (0)
		// is reserved for local, implementation-specific use and MUST NOT be
		// sent on the wire.  (For example, a key management implementation
		// might use the zero SPI value to mean "No Security Association Exists"
		return 0, err
	}
	return uint32(spi), nil
}

func deleteSA(selector *sad.SASelector) {
	mgrs[0].DeleteSA(selector)
	mgrs[1].DeleteSA(selector)
}

var encTbl = map[uint8]ipsec.CipherAlgo{
	pfkey.SADB_EALG_NONE:     ipsec.CipherAlgoNull,
	pfkey.SADB_X_EALG_AESCBC: ipsec.CipherAlgoAesCbc,
	pfkey.SADB_X_EALG_AESCTR: ipsec.CipherAlgoAesCtr,
	pfkey.SADB_EALG_3DESCBC:  ipsec.CipherAlgo3desCbc,
}

var aeadTbl = map[uint8]ipsec.AeadAlgo{
	pfkey.SADB_X_EALG_AES_GCM_ICV16: ipsec.AeadAlgoGcm,
}

var authTbl = map[uint8]ipsec.AuthAlgo{
	pfkey.SADB_AALG_NONE:     ipsec.AuthAlgoNull,
	pfkey.SADB_AALG_SHA1HMAC: ipsec.AuthAlgoSha1Hmac,
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

func (s *sadbAddMsg) validCipherAlgo(algo ipsec.CipherAlgo,
	sav *sad.SAValue) bool {

	if algoInfo, ok := ipsec.SupportedCipherAlgo[algo]; ok {
		keyLen := s.EncKey.SadbKey.SadbKeyBits / 8
		if value, ok := algoInfo.Algos[keyLen]; ok {
			sav.CipherAlgoType = value.Type
			sav.CipherKey = append(sav.CipherKey,
				(*s.EncKey.Key)[:value.KeyLen]...)
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
		keyLen := s.AuthKey.SadbKey.SadbKeyBits / 8
		if value, ok := algoInfo.Algos[keyLen]; ok {
			sav.AuthAlgoType = value.Type
			sav.AuthKey = append(sav.AuthKey,
				(*s.AuthKey.Key)[:value.KeyLen]...)
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
		keyLen := s.EncKey.SadbKey.SadbKeyBits / 8
		if value, ok := algoInfo.Algos[keyLen]; ok {
			sav.AeadAlgoType = value.Type
			sav.AeadKey = append(sav.AeadKey,
				(*s.EncKey.Key)[:value.KeyLen]...)
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

var encRTbl = map[ipsec.CipherAlgoType]uint8{
	ipsec.CipherAlgoTypeNull:      pfkey.SADB_EALG_NONE,
	ipsec.CipherAlgoTypeAes128Cbc: pfkey.SADB_X_EALG_AESCBC,
	ipsec.CipherAlgoTypeAes256Cbc: pfkey.SADB_X_EALG_AESCBC,
	ipsec.CipherAlgoTypeAes128Ctr: pfkey.SADB_X_EALG_AESCTR,
	ipsec.CipherAlgoType3desCbc:   pfkey.SADB_EALG_3DESCBC,
}

var authRTbl = map[ipsec.AuthAlgoType]uint8{
	ipsec.AuthAlgoTypeNull:     pfkey.SADB_AALG_NONE,
	ipsec.AuthAlgoTypeSha1Hmac: pfkey.SADB_AALG_SHA1HMAC,
}

var aeadRTbl = map[ipsec.AeadAlgoType]uint8{
	ipsec.AeadAlgoTypeAes128Gcm: pfkey.SADB_X_EALG_AES_GCM_ICV16,
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
