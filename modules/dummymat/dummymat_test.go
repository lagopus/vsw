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

package dummymat

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/lagopus/vsw/dpdk"
	_ "github.com/lagopus/vsw/modules/bridge"
	"github.com/lagopus/vsw/modules/testvif"
	"github.com/lagopus/vsw/vswitch"
)

type bridge struct {
	br    *vswitch.TestInstance
	iface *vswitch.Interface
	vif   *vswitch.VIF
	rxCh  chan *dpdk.Mbuf
	txCh  chan *dpdk.Mbuf
	mac   net.HardwareAddr
}

var vids = []vswitch.VID{100, 200}
var bridges = make(map[vswitch.VID]*bridge)
var pool *dpdk.MemPool

func TestNormalFlow(t *testing.T) {
	timer := time.NewTimer(time.Second)
	mbuf := pool.AllocMbuf()
	eh := mbuf.EtherHdr()

	sa, _ := net.ParseMAC("11:22:33:44:55:66")

	eh.SetDstAddr(bridges[100].mac)
	eh.SetSrcAddr(sa)

	bridges[100].rxCh <- mbuf
	t.Logf("Sending %v", mbuf)

	select {
	case <-bridges[100].txCh:
		t.Fatalf("Got from VID 100. Unexpected.")
	case <-bridges[200].txCh:
		t.Logf("Got from VID 200. Ok")
	case <-timer.C:
		t.Fatalf("Timed out")
	}

	t.Logf("Got %v", mbuf)
}

func TestMain(m *testing.M) {
	// Initialize DPDK
	vswitch.Init("../../vsw.conf")
	pool = vswitch.GetDpdkResource().Mempool

	//
	// Setup Vswitch
	//

	// Create Instances
	mat, _ := vswitch.NewTestModule("mat", "mat0", nil)

	for id, vid := range vids {
		br, err := vswitch.NewTestModule("bridge", fmt.Sprintf("br%d", id), nil)
		if err != nil {
			fmt.Printf("Creating bridge failed: %v", err)
		}
		bi, _ := br.Instance().(vswitch.BridgeInstance)
		bi.SetMAT(mat.Input())
		mat.Connect(br.Input(), vswitch.MatchVID, vid)

		br.Enable()

		iface, _ := vswitch.NewInterface("testvif", fmt.Sprintf("tv%d", id), nil)
		iface.AddVID(vid)
		iface.Enable()

		vif, _ := iface.NewVIF(0)
		vif.SetVID(vid)
		vif.Enable()

		testif, _ := iface.Instance().(*testvif.TestIF)

		bridges[vid] = &bridge{
			br:    br,
			iface: iface,
			vif:   vif,
			rxCh:  testif.RxChan(),
			txCh:  testif.TxChan(),
			mac:   vif.MACAddress(),
		}

		br.AddVIF(vif)
		bi.AddVIF(vif, 1500)
	}

	mat.Enable()

	rc := m.Run()

	// Teardown
	mat.Disable()
	for _, b := range bridges {
		b.vif.Disable()
		b.iface.Disable()
		b.br.Disable()
	}

	// Done
	os.Exit(rc)
}
