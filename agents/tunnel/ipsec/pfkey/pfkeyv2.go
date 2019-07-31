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

package pfkey

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"syscall"
	"unsafe"

	"github.com/lagopus/vsw/modules/tunnel/log"
)

// Serializer is the interface that wraps the Serialize method.
type Serializer interface {
	Serialize(w io.Writer) error
}

// PfkeyBufferLen represents buffer length for one pfkey message.
const PfkeyBufferLen = 4096

// SadbMsg is base message header for pfkey messages.
type SadbMsg struct {
	SadbMsgVersion  uint8
	SadbMsgType     uint8
	SadbMsgErrno    uint8
	SadbMsgSatype   uint8
	SadbMsgLen      uint16
	SadbMsgReserved uint16
	SadbMsgSeq      uint32
	SadbMsgPid      uint32
}

// SadbMsgLen is the length of SadbMsg.
const SadbMsgLen = 16

// HostByteOrder is the byte order on host.
var HostByteOrder = binary.LittleEndian

// NewSadbMsg returns a new SadbMsg.
func NewSadbMsg(mtype, satype uint8, seq, pid uint32) *SadbMsg {
	return &SadbMsg{
		SadbMsgVersion: PF_KEY_V2,
		SadbMsgType:    mtype,
		SadbMsgSatype:  satype,
		SadbMsgSeq:     seq,
		SadbMsgPid:     pid,
	}
}

// Deserialize deserializes SadbMsg.
func (s *SadbMsg) Deserialize(r io.Reader) error {
	err := binary.Read(r, HostByteOrder, s)
	return err
}

// Serialize serializes SadbMsg.
func (s *SadbMsg) Serialize(w io.Writer) error {
	err := binary.Write(w, HostByteOrder, s)
	return err
}

// SadbMsgTransport is message frame for pfkey message of replying.
type SadbMsgTransport struct {
	SadbMsg    *SadbMsg
	Serializer []Serializer
}

// Serialize serializes SadbMsgTransport.
func (s *SadbMsgTransport) Serialize(w io.Writer) error {
	buf := bytes.Buffer{}
	for _, v := range s.Serializer {
		err := v.Serialize(&buf)
		if err != nil {
			return err
		}
	}
	mLen := SadbMsgLen + len(buf.Bytes())
	s.SadbMsg.SadbMsgLen = toPFKeyLen(mLen)
	mBuf := bytes.Buffer{}
	err := s.SadbMsg.Serialize(&mBuf)
	if err != nil {
		return err
	}
	mBuf.Write(buf.Bytes())
	n, err := w.Write(mBuf.Bytes())
	log.Logger.Info("sadbMsgReply: %d bytes write", n)
	return err
}

// SadbExt is extension header for pfkey messages.
type SadbExt struct {
	SadbExtLen  uint16
	SadbExtType uint16
}

// SadbExtMsgLen is the length of extension header.
const SadbExtMsgLen = 4

// Deserialize deserializes SadbExt.
func (s *SadbExt) Deserialize(r io.Reader) error {
	err := binary.Read(r, HostByteOrder, s)
	return err
}

// Serialize serializes SadbExt.
func (s *SadbExt) Serialize(w io.Writer) error {
	err := binary.Write(w, HostByteOrder, s)
	return err
}

// SadbExtTransport represents a pair of extension header and body data.
type SadbExtTransport struct {
	SadbExt    *SadbExt
	Serializer Serializer
}

// Serialize serializes SadbExtTransport.
func (s *SadbExtTransport) Serialize(w io.Writer) error {
	if s.Serializer == nil {
		return nil
	}
	buf := bytes.Buffer{}
	err := s.Serializer.Serialize(&buf)
	if err != nil {
		return err
	}
	s.SadbExt.SadbExtLen = uint16((len(buf.Bytes()) + 4) / 8)
	err = s.SadbExt.Serialize(w)
	if err != nil {
		return err
	}
	_, err = w.Write(buf.Bytes())
	return err
}

// SadbSa represents association extension.
type SadbSa struct {
	SadbSaSpi     uint32 //big endian
	SadbSaReplay  uint8
	SadbSaState   uint8
	SadbSaAuth    uint8
	SadbSaEncrypt uint8
	SadbSaFlags   uint32
}

// SadbSaMsgLen is the length of SadbSa.
const SadbSaMsgLen = 16

// Deserialize deserializes SadbSa.
func (s *SadbSa) Deserialize(r io.Reader) error {
	err := binary.Read(r, HostByteOrder, s)
	if err != nil {
		return err
	}
	b := make([]byte, binary.MaxVarintLen32)
	binary.BigEndian.PutUint32(b, s.SadbSaSpi)
	s.SadbSaSpi = HostByteOrder.Uint32(b)
	return nil
}

func toPFKeyLen(i int) uint16 {
	return uint16(i / 8)
}

func toByteLen(i uint16) int {
	return int(i * 8)
}

// Serialize serializes SadbSa.
func (s *SadbSa) Serialize(w io.Writer) error {
	b := make([]byte, binary.MaxVarintLen32)
	binary.BigEndian.PutUint32(b, s.SadbSaSpi)
	s.SadbSaSpi = HostByteOrder.Uint32(b)
	err := binary.Write(w, HostByteOrder, s)
	if err != nil {
		return err
	}
	return err
}

// SadbLifetime represents lifetime extension.
type SadbLifetime struct {
	SadbLifetimeAllocations uint32
	SadbLifetimeBytes       uint64
	SadbLifetimeAddtime     uint64
	SadbLifetimeUsetime     uint64
}

// SadbLifetimeMsgLen is the length of SadbLifetime.
const SadbLifetimeMsgLen = 32

// Deserialize deserializes SadbLifetime.
func (s *SadbLifetime) Deserialize(r io.Reader) error {
	err := binary.Read(r, HostByteOrder, s)
	return err
}

// Serialize serializes SadbLifetime.
func (s *SadbLifetime) Serialize(w io.Writer) error {
	err := binary.Write(w, HostByteOrder, s)
	return err
}

// SadbAddress represents address extension.
type SadbAddress struct {
	SadbAddressProto     uint8
	SadbAddressPrefixlen uint8
	SadbAddressReserved  uint16
}

// Deserialize deserializes SadbAddress.
func (s *SadbAddress) Deserialize(r io.Reader) error {
	err := binary.Read(r, HostByteOrder, s)
	return err
}

// Serialize serializes SadbAddress.
func (s *SadbAddress) Serialize(w io.Writer) error {
	err := binary.Write(w, HostByteOrder, s)
	return err
}

// Sockaddr represents both sockaddrInet4 and sockaddrInet6.
type Sockaddr interface {
	Deserialize(r io.Reader) error
	Serialize(w io.Writer) error
	ToIPNet(plen int) *net.IPNet
	Port() int
}

type sockaddrInet4 struct {
	syscall.SockaddrInet4
}

type sockaddrInet6 struct {
	syscall.SockaddrInet6
}

// Deserialize deserializes sockaddrInet4.
func (sa *sockaddrInet4) Deserialize(r io.Reader) error {
	raw := &syscall.RawSockaddrInet4{}
	err := binary.Read(r, HostByteOrder, raw)
	if err != nil {
		return err
	} else if raw.Family != syscall.AF_INET {
		return syscall.EINVAL
	}
	p := (*[2]byte)(unsafe.Pointer(&raw.Port))
	sa.SockaddrInet4.Port = int(p[0])<<8 + int(p[1])
	for i := 0; i < len(sa.Addr); i++ {
		sa.Addr[i] = raw.Addr[i]
	}
	return err
}

// Serialize serializes sockaddrInet4.
func (sa *sockaddrInet4) Serialize(w io.Writer) error {
	raw := &syscall.RawSockaddrInet4{}
	raw.Family = syscall.AF_INET
	b := make([]byte, binary.MaxVarintLen16)
	binary.BigEndian.PutUint16(b, uint16(sa.SockaddrInet4.Port))
	p := (*[2]byte)(unsafe.Pointer(&raw.Port))
	p[0] = b[0]
	p[1] = b[1]
	for i := 0; i < len(sa.Addr); i++ {
		raw.Addr[i] = sa.Addr[i]
	}
	err := binary.Write(w, HostByteOrder, raw)
	return err
}

// ToIPNet returns net.IPNet.
func (sa *sockaddrInet4) ToIPNet(plen int) *net.IPNet {
	return &net.IPNet{
		IP:   net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]),
		Mask: net.CIDRMask(plen, net.IPv4len*8),
	}
}

// ToSockaddr converts net.IPNet to Sockaddr.
func ToSockaddr(ipnet *net.IPNet) Sockaddr {
	ip := ipnet.IP.To4()
	if ip != nil {
		sa := sockaddrInet4{}
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = ip[i]
		}
		return &sa
	}
	ip = ipnet.IP.To16()
	if ip != nil {
		sa := sockaddrInet6{}
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = ip[i]
		}
		return &sa
	}

	return nil
}

// Port returns port number.
func (sa *sockaddrInet4) Port() int {
	return sa.SockaddrInet4.Port
}

// Deserialize deserializes sockaddrInet6.
func (sa *sockaddrInet6) Deserialize(r io.Reader) error {
	raw := &syscall.RawSockaddrInet6{}
	err := binary.Read(r, HostByteOrder, raw)
	if err != nil {
		return err
	} else if raw.Family != syscall.AF_INET6 {
		return syscall.EINVAL
	}
	p := (*[2]byte)(unsafe.Pointer(&raw.Port))
	sa.SockaddrInet6.Port = int(p[0])<<8 + int(p[1])
	sa.ZoneId = raw.Scope_id
	for i := 0; i < len(sa.Addr); i++ {
		sa.Addr[i] = raw.Addr[i]
	}
	return err
}

// ToIPNet returns net.IPNet.
func (sa *sockaddrInet6) ToIPNet(plen int) *net.IPNet {
	return &net.IPNet{
		IP: []byte{
			sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3],
			sa.Addr[4], sa.Addr[5], sa.Addr[6], sa.Addr[7],
			sa.Addr[8], sa.Addr[9], sa.Addr[10], sa.Addr[11],
			sa.Addr[12], sa.Addr[13], sa.Addr[14], sa.Addr[15]},
		Mask: net.CIDRMask(plen, net.IPv6len*8),
	}
}

// Serialize serializes sockaddrInet6.
func (sa *sockaddrInet6) Serialize(w io.Writer) error {
	raw := &syscall.RawSockaddrInet6{}
	raw.Family = syscall.AF_INET6
	b := make([]byte, binary.MaxVarintLen16)
	binary.BigEndian.PutUint16(b, uint16(sa.SockaddrInet6.Port))
	p := (*[2]byte)(unsafe.Pointer(&raw.Port))
	p[0] = b[0]
	p[1] = b[1]
	sa.ZoneId = raw.Scope_id
	for i := 0; i < len(sa.Addr); i++ {
		raw.Addr[i] = sa.Addr[i]
	}
	err := binary.Write(w, HostByteOrder, raw)
	return err
}

// Port returns port number.
func (sa *sockaddrInet6) Port() int {
	return sa.SockaddrInet6.Port
}

// AddrPair represents a pair of SadbAddress and SockAddr in pfkey messages.
type AddrPair struct {
	Addr        SadbAddress
	SockAddr    Sockaddr
	SadbAddrLen uint16
}

// ToIPNet returns net.IPNet.
func (s *AddrPair) ToIPNet() *net.IPNet {
	ipnet := s.SockAddr.ToIPNet(int(s.Addr.SadbAddressPrefixlen))
	return ipnet
}

// Deserialize deserializes AddrPair.
func (s *AddrPair) Deserialize(r io.Reader) error {
	err := s.Addr.Deserialize(r)
	if err != nil {
		return err
	}
	l := (s.SadbAddrLen - 1) * 8 // Sockaddr length.
	switch {
	case l <= syscall.SizeofSockaddrInet4:
		s.SockAddr = &sockaddrInet4{}
		err = s.SockAddr.Deserialize(r)
		if err != nil {
			return err
		}
		return err
	case l <= syscall.SizeofSockaddrInet6:
		s.SockAddr = &sockaddrInet6{}
		err = s.SockAddr.Deserialize(r)
		if err != nil {
			return err
		}
		return err
	default:
		return syscall.EINVAL
	}
}

// Serialize serializes AddrPair.
func (s *AddrPair) Serialize(w io.Writer) error {
	err := s.Addr.Serialize(w)
	if err != nil {
		return err
	}
	err = s.SockAddr.Serialize(w)
	return err
}

// KeyPair represents a pair of SadbKey and Key in pfkey messages.
type KeyPair struct {
	SadbKey    SadbKey
	Key        *[]byte
	SadbKeyLen uint16 // use in deserialize only.
}

// ToKeyPair returns KeyPair.
func ToKeyPair(key *[]byte) *KeyPair {
	lenBits := len(*key) * 8
	bufLen := len(*key) / 8 * 8
	if bufLen < len(*key) {
		bufLen += 8 // 64bit alignment
	}
	buf := make([]byte, bufLen)
	copy(buf, *key)
	return &KeyPair{
		SadbKey: SadbKey{SadbKeyBits: uint16(lenBits)},
		Key:     &buf,
	}
}

// SadbKey represents key extension.
type SadbKey struct {
	SadbKeyBits     uint16
	SadbKeyReserved uint16
}

// Deserialize deserializes SadbKey.
func (s *SadbKey) Deserialize(r io.Reader) error {
	err := binary.Read(r, HostByteOrder, s)
	return err
}

// Serialize serializes SadbKey.
func (s *SadbKey) Serialize(w io.Writer) error {
	err := binary.Write(w, HostByteOrder, s)
	return err
}

// Deserialize deserializes KeyPair.
func (s *KeyPair) Deserialize(r io.Reader) error {
	err := s.SadbKey.Deserialize(r)
	if err != nil {
		return err
	}
	blen := (s.SadbKeyLen - 1) * 8 // Key length.
	key := make([]byte, blen)
	err = binary.Read(r, HostByteOrder, key)
	if err != nil {
		return err
	}
	s.Key = &key
	return err
}

// Serialize serializes KeyPair.
func (s *KeyPair) Serialize(w io.Writer) error {
	err := s.SadbKey.Serialize(w)
	if err != nil {
		return err
	}
	err = binary.Write(w, HostByteOrder, s.Key)
	return err
}

// SadbIdent represents identity extension.
type SadbIdent struct {
	SadbIdentLen      uint16
	SadbIdentExttype  uint16
	SadbIdentType     uint16
	SadbIdentReserved uint16
	SadbIdentID       uint64
}

// SadbSens represents sensitivity extension.
type SadbSens struct {
	SadbSensLen        uint16
	SadbSensExttype    uint16
	SadbSensDpd        uint32
	SadbSensSensLevel  uint8
	SadbSensSensLen    uint8
	SadbSensIntegLevel uint8
	SadbSensIntegLen   uint8
	SadbSensReserved   uint32
}

// SadbProp represents proposal extension.
type SadbProp struct {
	SadbPropLen      uint16
	SadbPropExttype  uint16
	SadbPropReplay   uint8
	SadbPropReserved [3]uint8
}

// SadbComb represents combination extension.
type SadbComb struct {
	SadbCombAuth            uint8
	SadbCombEncrypt         uint8
	SadbCombFlags           uint16
	SadbCombAuthMinbits     uint16
	SadbCombAuthMaxbits     uint16
	SadbCombEncryptMinbits  uint16
	SadbCombEncryptMaxbits  uint16
	SadbCombReserved        uint32
	SadbCombSoftAllocations uint32
	SadbCombHardAllocations uint32
	SadbCombSoftBytes       uint64
	SadbCombHardBytes       uint64
	SadbCombSoftAddtime     uint64
	SadbCombHardAddtime     uint64
	SadbCombSoftUsetime     uint64
	SadbCombHardUsetime     uint64
}

// SadbSupported represents supported algorithms extension.
type SadbSupported struct {
	SadbSupportedReserved uint32
}

// Serialize serializes SadbSupported.
func (s *SadbSupported) Serialize(w io.Writer) error {
	err := binary.Write(w, HostByteOrder, s)
	return err
}

// SadbAlg represents algorithm description.
type SadbAlg struct {
	SadbAlgID       uint8
	SadbAlgIvlen    uint8
	SadbAlgMinbits  uint16
	SadbAlgMaxbits  uint16
	SadbAlgReserved uint16
}

// Serialize serializes SadbAlg.
func (s *SadbAlg) Serialize(w io.Writer) error {
	err := binary.Write(w, HostByteOrder, s)
	return err
}

// SupportedAlgPair represents a pair of SadbSupported and SadbAlgs.
type SupportedAlgPair struct {
	Sup SadbSupported
	Alg []SadbAlg
}

// Serialize serializes SupportedAlgPair.
func (s *SupportedAlgPair) Serialize(w io.Writer) error {
	err := s.Sup.Serialize(w)
	if err != nil {
		return err
	}
	for _, v := range s.Alg {
		err = v.Serialize(w)
		if err != nil {
			return err
		}
	}
	return err
}

// SadbSPIRange represents spi range extension.
type SadbSPIRange struct {
	SadbSpirangeMin      uint32
	SadbSpirangeMax      uint32
	SadbSpirangeReserved uint32
}

// Deserialize deserializes SadbSPIRange.
func (s *SadbSPIRange) Deserialize(r io.Reader) error {
	err := binary.Read(r, HostByteOrder, s)
	return err
}

// SadbXSa2 represents sa extension.
type SadbXSa2 struct {
	SadbXSa2Mode      uint8
	SadbXSa2Reserved1 uint8
	SadbXSa2Reserved2 uint16
	SadbXSa2Sequence  uint32
	SadbXSa2Reqid     uint32
}

// Deserialize deserializes SadbXSa2.
func (s *SadbXSa2) Deserialize(r io.Reader) error {
	err := binary.Read(r, HostByteOrder, s)
	return err
}

// Serialize serializes SadbXSa2.
func (s *SadbXSa2) Serialize(w io.Writer) error {
	err := binary.Write(w, HostByteOrder, s)
	return err
}

// SadbXPolicy represents policy extension.
type SadbXPolicy struct {
	SadbXPolicyType     uint16
	SadbXPolicyDir      uint8
	SadbXPolicyReserved uint8
	SadbXPolicyID       uint32
	SadbXpolicyPriority uint32
}

// Deserialize deserializes SadbXPolicy.
func (s *SadbXPolicy) Deserialize(r io.Reader) error {
	err := binary.Read(r, HostByteOrder, s)
	return err
}

// Serialize serializes SadbXPolicy.
func (s *SadbXPolicy) Serialize(w io.Writer) error {
	err := binary.Write(w, HostByteOrder, s)
	return err
}

// Policy represents spd add/update messages.
type Policy struct {
	Policy         SadbXPolicy
	IpsecRequest   SadbXIpsecrequest
	TunnelSrcAddr  Sockaddr /* optional */
	TunnelDstAddr  Sockaddr /* optional */
	SadbXPolicyLen uint16
}

// Deserialize deserializes Policy.
func (s *Policy) Deserialize(r io.Reader) error {
	err := s.Policy.Deserialize(r)
	l := (s.SadbXPolicyLen - 2) * 8
	if l > 16 {
		err := s.IpsecRequest.Deserialize(r)
		if err != nil {
			return err
		} else if s.IpsecRequest.SadbXIpsecrequestMode == IPSEC_MODE_TUNNEL {
			switch {
			case s.IpsecRequest.SadbXIpsecrequestLen-16 <= syscall.SizeofSockaddrInet4*2:
				src := sockaddrInet4{}
				err = src.Deserialize(r)
				if err != nil {
					return err
				}
				dst := sockaddrInet4{}
				err = dst.Deserialize(r)
				if err != nil {
					return err
				}
				s.TunnelSrcAddr = &src
				s.TunnelDstAddr = &dst
			case s.IpsecRequest.SadbXIpsecrequestLen-16 <= syscall.SizeofSockaddrInet6*2:
				src := sockaddrInet6{}
				err = src.Deserialize(r)
				if err != nil {
					return err
				}
				dst := sockaddrInet6{}
				err := dst.Deserialize(r)
				if err != nil {
					return err
				}
				s.TunnelSrcAddr = &src
				s.TunnelDstAddr = &dst
			default:
				return syscall.EINVAL
			}
		} else {
			return syscall.EINVAL
		}
	} else if l != 0 {
		err = syscall.EINVAL
	}
	return err
}

// Serialize serializes Policy.
func (s *Policy) Serialize(w io.Writer) error {
	s.Policy.Serialize(w)
	buf := bytes.Buffer{}
	if s.TunnelSrcAddr != nil {
		err := s.TunnelSrcAddr.Serialize(&buf)
		if err != nil {
			return err
		}
	}
	if s.TunnelDstAddr != nil {
		err := s.TunnelDstAddr.Serialize(&buf)
		if err != nil {
			return err
		}
	}
	s.IpsecRequest.SadbXIpsecrequestLen =
		uint16(16 + len(buf.Bytes())) // len is bytes number
	s.IpsecRequest.Serialize(w)
	_, err := w.Write(buf.Bytes())
	return err
}

// SadbXIpsecrequest represents ipsec request message for spd entry.
type SadbXIpsecrequest struct {
	SadbXIpsecrequestLen       uint16
	SadbXIpsecrequestProto     uint16
	SadbXIpsecrequestMode      uint8
	SadbXIpsecrequestLevel     uint8
	SadbXIpsecrequestReserved1 uint16
	SadbXIpsecrequestReqid     uint32
	SadbXIpsecrequestReserved2 uint32
}

// Deserialize deserializes SadbXIpsecrequest.
func (s *SadbXIpsecrequest) Deserialize(r io.Reader) error {
	err := binary.Read(r, HostByteOrder, s)
	return err
}

// Serialize serializes SadbXIpsecrequest.
func (s *SadbXIpsecrequest) Serialize(w io.Writer) error {
	err := binary.Write(w, HostByteOrder, s)
	return err
}

// SadbXNatTType represents the type of nat traversal.
type SadbXNatTType struct {
	SadbXNatTTypeType     uint8
	SadbXNatTTypeReserved [3]uint8
}

// Deserialize deserializes SadbXNatTType.
func (s *SadbXNatTType) Deserialize(r io.Reader) error {
	err := binary.Read(r, HostByteOrder, s)
	return err
}

// Serialize serializes SadbXNatTType.
func (s *SadbXNatTType) Serialize(w io.Writer) error {
	err := binary.Write(w, HostByteOrder, s)
	return err
}

// SadbXNatTPort represents the port of nat traversal.
type SadbXNatTPort struct {
	SadbXNatTPortPort     uint16 //big endian
	SadbXNatTPortReserved uint16
}

// Deserialize deserializes SadbXNatTPort.
func (s *SadbXNatTPort) Deserialize(r io.Reader) error {
	err := binary.Read(r, HostByteOrder, s)
	if err != nil {
		return err
	}
	b := make([]byte, binary.MaxVarintLen16)
	binary.BigEndian.PutUint16(b, s.SadbXNatTPortPort)
	s.SadbXNatTPortPort = HostByteOrder.Uint16(b)
	return nil
}

// Serialize serializes SadbXNatTPort.
func (s *SadbXNatTPort) Serialize(w io.Writer) error {
	b := make([]byte, binary.MaxVarintLen16)
	binary.BigEndian.PutUint16(b, s.SadbXNatTPortPort)
	s.SadbXNatTPortPort = HostByteOrder.Uint16(b)
	err := binary.Write(w, HostByteOrder, s)
	return err
}
