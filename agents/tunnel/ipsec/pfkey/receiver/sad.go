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
	"log"
	"net"
	"syscall"
	"time"

	"github.com/lagopus/vsw/agents/tunnel/ipsec/connections"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/pfkey" // XXX
	"github.com/lagopus/vsw/agents/tunnel/ipsec/sad"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/vswitch"
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
	log.Printf("SadbAddMsg: add sa spi %d\n", s.Sa.SadbSaSpi)
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
	sav2, err := findSAByIP(selector, sav.LocalEPIP.IP, sav.RemoteEPIP.IP)
	if err != nil {
		return syscall.EEXIST
	}
	log.Printf("SadbUpdateMsg: update sa spi %d\n", s.Sa.SadbSaSpi)
	sav2.CipherAlgo = sav.CipherAlgo
	sav2.CipherKey = sav.CipherKey
	sav2.AuthAlgo = sav.AuthAlgo
	sav2.AuthKey = sav.AuthKey
	sav2.AeadAlgo = sav.AeadAlgo
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

func getSupportedAuth() *[]pfkey.SadbAlg {
	s := []pfkey.SadbAlg{
		{
			SadbAlgID:      pfkey.SADB_AALG_NONE,
			SadbAlgMinbits: ipsec.SupportedAuthAlgo[ipsec.AuthAlgoTypeNull].KeyLen,
			SadbAlgMaxbits: ipsec.SupportedAuthAlgo[ipsec.AuthAlgoTypeNull].KeyLen,
		},
		{
			SadbAlgID:      pfkey.SADB_AALG_SHA1HMAC,
			SadbAlgMinbits: ipsec.SupportedAuthAlgo[ipsec.AuthAlgoTypeSha1Hmac].KeyLen,
			SadbAlgMaxbits: ipsec.SupportedAuthAlgo[ipsec.AuthAlgoTypeSha1Hmac].KeyLen,
		},
	}

	return &s
}

func getSupportedEnc() *[]pfkey.SadbAlg {
	s := []pfkey.SadbAlg{
		{
			SadbAlgID:      pfkey.SADB_EALG_NONE,
			SadbAlgIvlen:   uint8(ipsec.SupportedCipherAlgo[ipsec.CipherAlgoTypeNull].IvLen),
			SadbAlgMinbits: ipsec.SupportedCipherAlgo[ipsec.CipherAlgoTypeNull].KeyLen * 8,
			SadbAlgMaxbits: ipsec.SupportedCipherAlgo[ipsec.CipherAlgoTypeNull].KeyLen * 8,
		},
		{
			SadbAlgID:      pfkey.SADB_X_EALG_AESCBC,
			SadbAlgIvlen:   uint8(ipsec.SupportedCipherAlgo[ipsec.CipherAlgoTypeAesCbc].IvLen),
			SadbAlgMinbits: ipsec.SupportedCipherAlgo[ipsec.CipherAlgoTypeAesCbc].KeyLen * 8,
			SadbAlgMaxbits: ipsec.SupportedCipherAlgo[ipsec.CipherAlgoTypeAesCbc].KeyLen * 8,
		},
		{
			SadbAlgID:      pfkey.SADB_X_EALG_AES_GCM_ICV16,
			SadbAlgIvlen:   uint8(ipsec.SupportedAeadAlgo[ipsec.AeadAlgoTypeGcm].IvLen),
			SadbAlgMinbits: ipsec.SupportedAeadAlgo[ipsec.AeadAlgoTypeGcm].KeyLen * 8,
			SadbAlgMaxbits: ipsec.SupportedAeadAlgo[ipsec.AeadAlgoTypeGcm].KeyLen * 8,
		},
		{
			SadbAlgID:      pfkey.SADB_X_EALG_AESCTR,
			SadbAlgIvlen:   uint8(ipsec.SupportedCipherAlgo[ipsec.CipherAlgoTypeAesCtr].IvLen),
			SadbAlgMinbits: ipsec.SupportedCipherAlgo[ipsec.CipherAlgoTypeAesCtr].KeyLen * 8,
			SadbAlgMaxbits: ipsec.SupportedCipherAlgo[ipsec.CipherAlgoTypeAesCtr].KeyLen * 8,
		},
	}

	return &s
}

var encTbl = map[uint8]ipsec.CipherAlgoType{
	pfkey.SADB_EALG_NONE:     ipsec.CipherAlgoTypeNull,
	pfkey.SADB_X_EALG_AESCBC: ipsec.CipherAlgoTypeAesCbc,
	pfkey.SADB_X_EALG_AESCTR: ipsec.CipherAlgoTypeAesCtr,
}

var authTbl = map[uint8]ipsec.AuthAlgoType{
	pfkey.SADB_AALG_NONE:     ipsec.AuthAlgoTypeNull,
	pfkey.SADB_AALG_SHA1HMAC: ipsec.AuthAlgoTypeSha1Hmac,
}
var aeadTbl = map[uint8]ipsec.AeadAlgoType{
	pfkey.SADB_X_EALG_AES_GCM_ICV16: ipsec.AeadAlgoTypeGcm,
}

func (s *sadbAddMsg) toSadbSaSAV() (*sad.SAValue, bool) {
	if s.Sa == nil {
		log.Printf("invalid sa: %v", s.Sa)
		return nil, false
	}
	var ok bool
	sav := sad.SAValue{
		CSAValue: ipsec.CSAValue{
			Flags: ipsec.IP4Tunnel,
		},
	}

	if sav.CipherAlgo, ok = encTbl[s.Sa.SadbSaEncrypt]; ok {
		// Cipher/Auth algo.
		sav.CipherKey = append(sav.CipherKey,
			(*s.EncKey.Key)[:s.EncKey.SadbKey.SadbKeyBits/8]...)
		if sav.AuthAlgo, ok = authTbl[s.Sa.SadbSaAuth]; !ok {
			log.Printf("no authAlgo: %v", s.Sa.SadbSaAuth)
			return nil, ok
		}
		sav.AuthKey = append(sav.AuthKey,
			(*s.AuthKey.Key)[:s.AuthKey.SadbKey.SadbKeyBits/8]...)
	} else if sav.AeadAlgo, ok = aeadTbl[s.Sa.SadbSaEncrypt]; ok {
		// AEAD algo.
		sav.AeadKey = append(sav.AeadKey,
			(*s.EncKey.Key)[:s.EncKey.SadbKey.SadbKeyBits/8]...)
	} else {
		log.Printf("no encAlgo: %v", s.Sa.SadbSaEncrypt)
		return nil, ok
	}

	sav.State = sad.SAState(s.Sa.SadbSaState)
	sav.LocalEPIP = *s.SrcAddress.ToIPNet()
	sav.RemoteEPIP = *s.DstAddress.ToIPNet()
	// XXX: NOT support lifetime allocations
	now := time.Now()
	if s.HardLifetime != nil {
		log.Printf("SadbAddMsg: spi %d, hard addtime %d\n", s.Sa.SadbSaSpi,
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
		log.Printf("SadbAddMsg: spi %d, soft addtime %d\n", s.Sa.SadbSaSpi,
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
	sav.Protocol = ipsec.SecurityProtocolTypeESP //XXX
	return &sav, true
}

var encRTbl = map[ipsec.CipherAlgoType]uint8{
	ipsec.CipherAlgoTypeNull:   pfkey.SADB_EALG_NONE,
	ipsec.CipherAlgoTypeAesCbc: pfkey.SADB_X_EALG_AESCBC,
	ipsec.CipherAlgoTypeAesCtr: pfkey.SADB_X_EALG_AESCTR,
}

var authRTbl = map[ipsec.AuthAlgoType]uint8{
	ipsec.AuthAlgoTypeNull:     pfkey.SADB_AALG_NONE,
	ipsec.AuthAlgoTypeSha1Hmac: pfkey.SADB_AALG_SHA1HMAC,
}

var aeadRTbl = map[ipsec.AeadAlgoType]uint8{
	ipsec.AeadAlgoTypeGcm: pfkey.SADB_X_EALG_AES_GCM_ICV16,
}

func (s *sadbGetMsg) toSadbGetMsgReply(sav *sad.SAValue, spi uint32) (*sadbGetMsgReply, bool) {
	sa := pfkey.SadbSa{
		SadbSaSpi:   spi,
		SadbSaState: uint8(sav.State),
	}

	var aKey *pfkey.KeyPair
	var eKey *pfkey.KeyPair
	if enc, ok := encRTbl[sav.CipherAlgo]; ok {
		if auth, ok := authRTbl[sav.AuthAlgo]; ok {
			sa.SadbSaEncrypt = enc
			sa.SadbSaAuth = auth
			aKey = pfkey.ToKeyPair(&sav.AuthKey)
			eKey = pfkey.ToKeyPair(&sav.CipherKey)
		} else {
			return nil, false
		}
	} else if enc, ok := aeadRTbl[sav.AeadAlgo]; ok {
		sa.SadbSaEncrypt = enc
		eKey = pfkey.ToKeyPair(&sav.AeadKey)
	} else {
		return nil, false
	}

	sAddr := pfkey.AddrPair{
		Addr:     pfkey.SadbAddress{}, // XXX: to set proto, prefixlen?
		SockAddr: pfkey.ToSockaddr(&sav.LocalEPIP),
	}
	dAddr := pfkey.AddrPair{
		Addr:     pfkey.SadbAddress{}, // XXX: to set proto, prefixlen?
		SockAddr: pfkey.ToSockaddr(&sav.RemoteEPIP),
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
		log.Printf("send soft expire message: spi %d\n", uint32(spi))
	} else {
		s.expireMsg(sav, uint32(spi), false)
		log.Printf("send hard expire message: spi %d\n", uint32(spi))
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
		log.Printf("SadbExpire: error: %v\n", err)
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
	if s.sa.SadbSaEncrypt, ok = encRTbl[sav.CipherAlgo]; ok {
		s.sa.SadbSaAuth, _ = authRTbl[sav.AuthAlgo]
	} else {
		s.sa.SadbSaEncrypt, _ = aeadRTbl[sav.AeadAlgo]
	}

	s.srcAddress = &pfkey.AddrPair{
		Addr:     pfkey.SadbAddress{}, // XXX: to set proto, prefixlen?
		SockAddr: pfkey.ToSockaddr(&sav.LocalEPIP),
	}
	s.dstAddress = &pfkey.AddrPair{
		Addr:     pfkey.SadbAddress{}, // XXX: to set proto, prefixlen?
		SockAddr: pfkey.ToSockaddr(&sav.RemoteEPIP),
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
		log.Printf("SadbAcquire: error: %v\n", err)
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
