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

package vswitch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type IPv4Addr uint32

func (a IPv4Addr) String() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(a>>24)&0xff, (a>>16)&0xff, (a>>8)&0xff, a&0xff)
}

func NewIPv4Addr(a, b, c, d int) IPv4Addr {
	return IPv4Addr((a&0xff)<<24 | (b&0xff)<<16 | (c&0xff)<<8 | (d & 0xff))
}

func ToIPv4Addr(b []byte) IPv4Addr {
	return IPv4Addr(b[0])<<24 | IPv4Addr(b[1])<<16 | IPv4Addr(b[2])<<8 | IPv4Addr(b[3])
}

type EtherAddr [int(EthernetAddrLen)]byte

func NewEtherAddr(hwAddr net.HardwareAddr) EtherAddr {
	var etherAddr EtherAddr
	copy(etherAddr[:], hwAddr)
	return etherAddr
}

func (e EtherAddr) String() string {
	const hexDigits = "0123456789abcdef"

	buf := make([]byte, 0, 17)
	for i, b := range e {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigits[b>>4])
		buf = append(buf, hexDigits[b&0xf])
	}
	return string(buf)
}

func (e EtherAddr) Equal(x EtherAddr) bool {
	for i := 0; i < int(EthernetAddrLen); i++ {
		if e[i] != x[i] {
			return false
		}
	}
	return true
}

type Ethertype uint16

const (
	EthertypeIPv4 = Ethertype(0x0800)
	EthertypeARP  = Ethertype(0x0806)
)

func (e Ethertype) String() string {
	switch e {
	case EthertypeIPv4:
		return "IPv4"
	case EthertypeARP:
		return "ARP"
	}
	return "Unknown"
}

type ARPHrd uint16

const ARPHrdEthernet = ARPHrd(1)

func (a ARPHrd) String() string {
	switch a {
	case ARPHrdEthernet:
		return "Ethernet"
	}
	return "Unknown"
}

type ARPOp uint16

const (
	ARPOpRequest = ARPOp(1)
	ARPOpReply   = ARPOp(2)
)

func (o ARPOp) String() string {
	switch o {
	case ARPOpRequest:
		return "Request"
	case ARPOpReply:
		return "Reply"
	}
	return "Unknown"
}

const (
	EthernetAddrLen = uint8(6)
	IPv4AddrLen     = uint8(4)
)

const ARPPacketLength = 42

type ARPPacket struct {
	Dst             EtherAddr //  0: 6byte
	Src             EtherAddr //  6: 6byte
	Proto           Ethertype // 12: 2byte
	HWAddrSpc       ARPHrd    // 14: 2byte
	ProtoAddrSpc    Ethertype // 16: 2byte
	HWAddrLen       uint8     // 18: 1byte
	ProtoAddrLen    uint8     // 19: 1byte
	Op              ARPOp     // 20: 2byte
	SenderHWAddr    EtherAddr // 22: 6byte
	SenderProtoAddr IPv4Addr  // 28: 4byte
	TargetHWAddr    EtherAddr // 32: 6byte
	TargetProtoAddr IPv4Addr  // 38: 4byte
}

func NewARPRequest(targetIP, senderIP IPv4Addr, senderHW EtherAddr) *ARPPacket {
	return &ARPPacket{
		Dst:             EtherAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Src:             senderHW,
		Proto:           EthertypeARP,
		HWAddrSpc:       ARPHrdEthernet,
		ProtoAddrSpc:    EthertypeIPv4,
		HWAddrLen:       EthernetAddrLen,
		ProtoAddrLen:    IPv4AddrLen,
		Op:              ARPOpRequest,
		SenderProtoAddr: senderIP,
		SenderHWAddr:    senderHW,
		TargetProtoAddr: targetIP,
	}
}

func ARPParse(b []byte) (*ARPPacket, error) {
	arp := new(ARPPacket)
	buf := bytes.NewReader(b)
	if err := binary.Read(buf, binary.BigEndian, arp); err != nil {
		return nil, err
	}
	return arp, nil
}

func (a *ARPPacket) Encode() []byte {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, a); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func (a *ARPPacket) Decode(b []byte) error {
	buf := bytes.NewReader(b)
	if err := binary.Read(buf, binary.BigEndian, a); err != nil {
		return err
	}
	// verify legitimacy of ARP packet
	if a.Proto != EthertypeARP ||
		a.HWAddrSpc != ARPHrdEthernet || a.ProtoAddrSpc != EthertypeIPv4 ||
		a.HWAddrLen != 6 || a.ProtoAddrLen != 4 ||
		(a.Op != ARPOpRequest && a.Op != ARPOpReply) {
		return errors.New("Bad ARP packet")
	}
	return nil
}

// ConvertRequestToReply does the followings from RFC 826:
//
// Swap hardware and protocol fields, putting the local
// hardware and protocol addresses in the sender fields.
// Set the ar$op field to ares_op$REPLY
func (a *ARPPacket) ConvertRequestToReply(hwAddr EtherAddr) {
	a.Dst = a.Src
	a.Src = hwAddr

	a.TargetHWAddr = a.SenderHWAddr
	a.SenderHWAddr = hwAddr

	pAddr := a.SenderProtoAddr
	a.SenderProtoAddr = a.TargetProtoAddr
	a.TargetProtoAddr = pAddr

	a.Op = ARPOpReply
}

func (a *ARPPacket) String() string {
	s := fmt.Sprintf("Dst: %v, Src: %v, Proto: %v, ", a.Dst, a.Src, a.Proto)
	s += fmt.Sprintf("HWAddrSpc: %v, ProtoAddrSpc: %v, HWAddrLen: %v, ProtoAddrLen: %v, ",
		a.HWAddrSpc, a.ProtoAddrSpc, a.HWAddrLen, a.ProtoAddrLen)
	s += fmt.Sprintf("Op: %v, ", a.Op)
	s += fmt.Sprintf("Sender: %v (%v), Target: %v (%v)",
		a.SenderProtoAddr, a.SenderHWAddr,
		a.TargetProtoAddr, a.TargetHWAddr)
	return s
}
