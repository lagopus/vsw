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

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
)

func TestEtherHdr(t *testing.T) {
	hdr := EtherHdr{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // Destination
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Source
		0x08, 0x00, // IPv4
	}

	t.Logf("EtherHdr=%v\n", hdr)
	t.Logf("%s\n", hex.Dump([]byte(hdr)))

	// Check
	addr, _ := net.ParseMAC("11:22:33:44:55:66")
	if bytes.Compare(hdr.DstAddr(), addr) != 0 {
		t.Errorf("Expected %v. Got %v.\n", addr, hdr.DstAddr())
	} else {
		t.Logf("Dst Addr OK")
	}
	addr, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if bytes.Compare(hdr.SrcAddr(), addr) != 0 {
		t.Errorf("Expected %v. Got %v.\n", addr, hdr.SrcAddr())
	} else {
		t.Logf("Src Addr OK")
	}
	if hdr.EtherType() != ETHER_TYPE_IPv4 {
		t.Errorf("Expected %04x. Got %04x.\n", ETHER_TYPE_IPv4, hdr.EtherType())
	} else {
		t.Logf("Ether type OK")
	}

	// Rewrite
	dst, _ := net.ParseMAC("fe:dc:ba:98:76:54")
	src, _ := net.ParseMAC("01:23:45:67:89:ab")
	hdr.SetDstAddr(dst)
	hdr.SetSrcAddr(src)
	hdr.SetEtherType(ETHER_TYPE_ARP)

	t.Logf("EtherHdr=%v\n", hdr)
	t.Logf("%s\n", hex.Dump([]byte(hdr)))

	hdr2 := []byte{
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, // Destination
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, // Source
		0x08, 0x06, // ARP
	}

	if bytes.Compare(hdr, hdr2) != 0 {
		t.Errorf("Expected\n %v\nGot\n %v\n", EtherHdr(hdr2), hdr)
	} else {
		t.Logf("Header matched. OK")
	}

	for i := range etherTypeStrings {
		t.Logf("%#v: %s\n", uint16(i), i)
	}
}
