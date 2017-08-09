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
	"testing"
)

func TestMbufEtherHdr(t *testing.T) {
	pool := PktMbufPoolCreate("mbuf-test", 128, 0, 0, RTE_PKTMBUF_HEADROOM+2048, SOCKET_ID_ANY)
	if pool == nil {
		t.Fatal("Can't create mempool")
	}

	mbuf := pool.AllocMbuf()

	if len := mbuf.DataLen(); len != 0 {
		t.Errorf("DataLen() is not 0 bytes (%d bytes)", len)
	} else {
		t.Logf("Mbuf is not initialized yet. As expected.")
	}

	eh := mbuf.EtherHdr()
	dt := mbuf.Data()

	if bytes.Compare(eh, dt) != 0 {
		t.Errorf("EtherHdr() and Data() aren't same: %v != %v", eh, dt)
	}

	if len(eh) != 14 {
		t.Errorf("EtherHdr() is not 14 bytes (%d bytes)", len(eh))
	}

	if len := mbuf.DataLen(); len != 14 {
		t.Errorf("DataLen() is not 14 bytes (%d bytes)", len)
	} else {
		t.Logf("EtherHdr() returned 14 bytes slice.")
	}

	mbuf.Free()
	pool.Free()
}

func TestMbuf(t *testing.T) {
	pool := PktMbufPoolCreate("mbuf-test", 128, 0, 0, RTE_PKTMBUF_HEADROOM+2048, SOCKET_ID_ANY)
	if pool == nil {
		t.Fatal("Can't create mempool")
	}

	mbuf := pool.AllocMbuf()

	testeh := EtherHdr{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // Destination
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Source
		0x08, 0x00, // IPv4
	}

	testeh2 := EtherHdr{
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, // Destination
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, // Source
		0x08, 0x00, // IPv4
	}

	t.Logf("Setting to %v", testeh)
	mbuf.SetEtherHdr(testeh)

	eh := mbuf.EtherHdr()

	t.Logf("Set to %v", eh)
	t.Logf("DataCap:%v, DataLen:%v", mbuf.DataCap(), mbuf.DataLen())

	eh2 := mbuf.EtherHdr()
	eh2.SetEtherType(ETHER_TYPE_IPv6)

	eh = mbuf.EtherHdr()
	t.Logf("Set to %v", eh)

	t.Logf("Setting to %v", testeh2)
	mbuf.SetEtherHdr(testeh2)

	eh = mbuf.EtherHdr()
	t.Logf("Set to %v", eh)

	t.Log("mbuf.SetEtherHdr(mbuf.EtherHdr())")
	mbuf.SetEtherHdr(mbuf.EtherHdr())
	t.Logf("Set to %v", eh)
	t.Logf("Data:\n%s", hex.Dump(mbuf.Data()))

	data := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}

	t.Logf("DataLen: %v", mbuf.DataLen())
	if n := mbuf.SetData(data); n != len(data) {
		t.Errorf("Couldn't set all data. Set only %d/%d", n, len(data))
	}

	t.Logf("Data:\n%s", hex.Dump(mbuf.Data()))
	t.Logf("DataLen: %v", mbuf.DataLen())

	// tear down
	mbuf.Free()
	pool.Free()
}
