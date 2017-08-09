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

package hostif

import (
	"bytes"
	"flag"
	"github.com/lagopus/vsw/dpdk"
	_ "github.com/lagopus/vsw/modules/testvif"
	_ "github.com/lagopus/vsw/modules/hostif"
	"github.com/lagopus/vsw/vswitch"
	"google.golang.org/grpc"
	pb "github.com/lagopus/vsw/modules/hostif/packets_io"
	"net"
	"os"
	context "golang.org/x/net/context"
	"log"
	"testing"
)

var tx_chan chan *dpdk.Mbuf
var rx_chan chan *dpdk.Mbuf
var vif_mac net.HardwareAddr
var pool *dpdk.MemPool

func rpcclient() {
	conn, err := grpc.Dial(":30020", grpc.WithInsecure())
	if err != nil {
		log.Fatalf(":30020 connection failed: %v", err)
	}
	io := pb.NewPacketsIoClient(conn)
	var pkts *pb.BulkPackets
	// 2 times.
	for i := 0; i < 2; i++ {
		for {
			pkts, _ = io.RecvBulk(context.Background(), new(pb.Null))
			if pkts.N > 0 {
				break
			}
		}
		for _, pkt := range pkts.Packets {
			pkt.Subifname = "tv0"
		}
		io.SendBulk(context.Background(), pkts)
	}
	defer conn.Close()
}

func send(t *testing.T, mbuf *dpdk.Mbuf, self bool) bool {
	eh := mbuf.EtherHdr()
	src_ha := eh.SrcAddr()
	dst_ha := eh.DstAddr()

	//
	t.Logf("Sending: %s -> %s\n", src_ha, dst_ha)

	// send
	tx_chan <- mbuf

	// recv
	rmbuf := <-rx_chan
	reh := rmbuf.EtherHdr()
	md := (*vswitch.Metadata)(rmbuf.Metadata())

	t.Logf("Rcv'd: src=%s, dst=%s, vif=%d, self=%v\n", reh.SrcAddr(), reh.DstAddr(), md.InVIF(), md.Self())

	return 	bytes.Compare(reh.SrcAddr(), src_ha) == 0 &&
		bytes.Compare(reh.DstAddr(), dst_ha) == 0
}

func TestNormalFlow(t *testing.T) {
	t.Logf("testvif mac address: %s\n", vif_mac)

	src_ha, _ := net.ParseMAC("11:22:33:44:55:66")
	dst_ha, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	mbuf := pool.AllocMbuf()
	eh :=make(dpdk.EtherHdr, 14)
	eh.SetSrcAddr(src_ha)
	eh.SetDstAddr(dst_ha)
	mbuf.SetEtherHdr(eh)

	if !send(t, mbuf, false) {
		t.Errorf("Unexpected packet metadata recv'd")
	}

	// send to testvif
	eh.SetDstAddr(vif_mac)

	if !send(t, mbuf, true) {
		t.Errorf("Unexpected packet metadata recv'd")
	}
}

func initDpdk() {
	dc := &vswitch.DpdkConfig{
		CoreMask:      0xff,
		MemoryChannel: 2,
		PmdPath:       "/usr/local/lib/dpdk-pmd",
	}

	dc.Vdevs = flag.Args()

	if !vswitch.InitDpdk(dc) {
		log.Fatalf("DPDK initialization failed.\n")
	}
}

func TestMain(m *testing.M) {
	// Initialize DPDK
	initDpdk()

	pool = vswitch.GetDpdkResource().Mempool

	//
	// Setup Vswitch
	//
	vrf := vswitch.NewVRF("vrf0", 0)

	// Create Instances
	testvif := vrf.NewModule("testvif", "tv0")
	hostif := vrf.NewModule("hostif", "hostif0")

	// Connect Instances
	testvif.Connect(hostif, vswitch.MATCH_ANY)
	hostif.Connect(testvif, vswitch.MATCH_OUT_VIF)

	// Get Channels
	tx_chan, _ = testvif.Control("GET_TX_CHAN", nil).(chan *dpdk.Mbuf)
	rx_chan, _ = testvif.Control("GET_RX_CHAN", nil).(chan *dpdk.Mbuf)
	vif_mac, _ = testvif.Control("GET_MAC_ADDRESS", nil).(net.HardwareAddr)

	// Link up
	for _, idx := range vswitch.AllVifs() {
		vi := vswitch.GetVifInfo(idx)
		vi.SetLink(vswitch.LinkUp)
	}

	// Start
	go rpcclient()
	vswitch.Start()

	// Execute test
	flag.Parse()
	rc := m.Run()

	// Teardown
	vswitch.Stop()
	vswitch.Wait()

	// Done
	os.Exit(rc)
}
