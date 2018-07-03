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
	"net"
	"os"
	"testing"

	"github.com/lagopus/vsw/dpdk"
	pb "github.com/lagopus/vsw/modules/hostif/packets_io"
	"github.com/lagopus/vsw/modules/testvif"
	"github.com/lagopus/vsw/vswitch"

	context "golang.org/x/net/context"
	"google.golang.org/grpc"
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
			if pkts != nil && pkts.N > 0 {
				break
			}
		}
		for _, pkt := range pkts.Packets {
			pkt.Subifname = "tv0-0"
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
	rx_chan <- mbuf

	// recv
	rmbuf := <-tx_chan
	reh := rmbuf.EtherHdr()
	md := (*vswitch.Metadata)(rmbuf.Metadata())

	t.Logf("Rcv'd: src=%s, dst=%s, vif=%d, self=%v\n", reh.SrcAddr(), reh.DstAddr(), md.InVIF(), md.Self())

	return bytes.Compare(reh.SrcAddr(), src_ha) == 0 &&
		bytes.Compare(reh.DstAddr(), dst_ha) == 0
}

func TestNormalFlow(t *testing.T) {
	t.Logf("testvif mac address: %s\n", vif_mac)

	src_ha, _ := net.ParseMAC("11:22:33:44:55:66")
	dst_ha, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	mbuf := pool.AllocMbuf()
	eh := make(dpdk.EtherHdr, 14)
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

func TestMain(m *testing.M) {
	// Initialize vswitch core
	vswitch.Init("../../vsw.conf")
	vswitch.EnableLog(true)
	pool = vswitch.GetDpdkResource().Mempool

	//
	// Setup Vswitch
	//

	// Create Instances
	tv0, _ := vswitch.NewInterface("testvif", "tv0", nil)
	tv0_0, _ := tv0.NewVIF(0)
	hostif, _ := vswitch.NewTestModule("hostif", "hostif0", nil)

	testif, _ := tv0.Instance().(*testvif.TestIF)

	// Connect Instances
	hostif.AddVIF(tv0_0)

	// Get Channels
	tx_chan = testif.TxChan()
	rx_chan = testif.RxChan()
	vif_mac = tv0.MACAddress()

	// Enable Modules
	go rpcclient()
	tv0.Enable()
	tv0_0.Enable()
	hostif.Enable()

	// Execute test
	flag.Parse()
	rc := m.Run()

	// Teardown
	hostif.Disable()
	tv0_0.Disable()
	tv0.Disable()

	// Done
	os.Exit(rc)
}
