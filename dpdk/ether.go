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

package dpdk

/*
#include <rte_ether.h>
*/
import "C"

import (
	"fmt"
	"net"
)

type EtherType uint16

const (
	ETHER_TYPE_IPv4 EtherType = C.ETHER_TYPE_IPv4
	ETHER_TYPE_IPv6           = C.ETHER_TYPE_IPv6
	ETHER_TYPE_ARP            = C.ETHER_TYPE_ARP
	ETHER_TYPE_RARP           = C.ETHER_TYPE_RARP
	ETHER_TYPE_VLAN           = C.ETHER_TYPE_VLAN
	ETHER_TYPE_QINQ           = C.ETHER_TYPE_QINQ
	ETHER_TYPE_1588           = C.ETHER_TYPE_1588
	ETHER_TYPE_SLOW           = C.ETHER_TYPE_SLOW
	ETHER_TYPE_TEB            = C.ETHER_TYPE_TEB
)

var etherTypeStrings = map[EtherType]string{
	ETHER_TYPE_IPv4: "IPv4 Protocol",
	ETHER_TYPE_IPv6: "IPv6 Protocol",
	ETHER_TYPE_ARP:  "ARP Protocol",
	ETHER_TYPE_RARP: "Reverse ARP Protocol",
	ETHER_TYPE_VLAN: "IEEE 802.1Q VLAN Tagging",
	ETHER_TYPE_QINQ: "IEEE 802.1ad QinQ Tagging",
	ETHER_TYPE_1588: "IEEE 802.1AS 1588 Precise Time Protocol",
	ETHER_TYPE_SLOW: "Slow Protoocls (LACP and Marker)",
	ETHER_TYPE_TEB:  "Tranparent Ether Bridging",
}

func (et EtherType) String() string { return etherTypeStrings[et] }

type EtherHdr []byte

func (eh EtherHdr) DstAddr() net.HardwareAddr {
	return net.HardwareAddr(eh[:6])
}

func (eh EtherHdr) SetDstAddr(addr net.HardwareAddr) {
	copy(eh[:6], addr[:6])
}

func (eh EtherHdr) SrcAddr() net.HardwareAddr {
	return net.HardwareAddr(eh[6:12])
}

func (eh EtherHdr) SetSrcAddr(addr net.HardwareAddr) {
	copy(eh[6:], addr[:6])
}

func (eh EtherHdr) EtherType() EtherType {
	return EtherType(uint16(eh[12])<<8 | uint16(eh[13]))
}

func (eh EtherHdr) SetEtherType(et EtherType) {
	eh[12] = byte((et >> 8) & 0xff)
	eh[13] = byte(et & 0xff)
}

func (eh EtherHdr) String() string {
	return fmt.Sprintf("DST=%v, SRC=%v, TYPE=%s (%#v)", eh.DstAddr(), eh.SrcAddr(), eh.EtherType(), eh.EtherType())
}
