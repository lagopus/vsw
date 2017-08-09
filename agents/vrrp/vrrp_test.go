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

package vrrp

import (
	"flag"
	"github.com/lagopus/vsw/agents/vrrp/rpc"
	"github.com/lagopus/vsw/dpdk"
	_ "github.com/lagopus/vsw/modules/dumb"
	_ "github.com/lagopus/vsw/modules/testvif"
	"github.com/lagopus/vsw/vswitch"
	"google.golang.org/grpc"
	"golang.org/x/net/context"
	"net"
	"os"
	"testing"
)

var tx_chan chan *dpdk.Mbuf
var rx_chan chan *dpdk.Mbuf
var vif_mac net.HardwareAddr
var pool *dpdk.MemPool

// exist
func TestFindVifInfo1(t *testing.T) {
	var info *vswitch.VifInfo
	var err error
	info, err = findVifInfo("tv0")
	if info == nil && err != nil {
		log.Fatal("findVifInfo1 failed.")
	}
}

// not exist
func TestFindVifInfo2(t *testing.T) {
	var info *vswitch.VifInfo
	var err error
	info, err = findVifInfo("invalid_name")
	if info != nil && err == nil {
		log.Fatal("findVifInfo2 failed.")
	}
}

func TestSplitAddrPrefix1(t *testing.T) {
	expectedIp := net.ParseIP("192.168.0.1")
	expectedMask := net.CIDRMask(24, 32)

	str := "192.168.0.1/24"
	ip, mask, err := splitAddrPrefix(str)

	if !ip.Equal(expectedIp) || mask.String() != expectedMask.String() || err != nil {
		log.Fatal("splitAddrPrefix1 failed.")
	}
}

func TestSplitAddrPrefix2(t *testing.T) {
	ip, mask, err := splitAddrPrefix("invalid_addr")
	if ip != nil && mask != nil && err == nil {
		log.Fatal("splitAddrPrefix2 failed.")
	}
}

func TestSplitAddrPrefix3(t *testing.T) {
	ip, mask, err := splitAddrPrefix("")
	if ip != nil && mask != nil && err == nil {
		log.Fatal("splitAddrPrefix3 failed.")
	}
}

func TestGetVifInfo1(t *testing.T) {
	entry := &rpc.VifEntry {
		Name: "tv0",
		Addr: "",
	}
	info := &rpc.VifInfo {
		N: 1,
		Entries: []*rpc.VifEntry{entry},
	}

	vrrp := &vrrp{}
	actualInfo, err := vrrp.GetVifInfo(nil, info)

	if err != nil {
		log.Fatalf("GetVifInfo1 failed: %+v", err)
	} else if actualInfo.Entries[0].Name != "tv0" ||
		actualInfo.Entries[0].Addr != "12:34:56:78:00:01" {
		log.Fatalf("GetVifInfo1 failed: %+v\n", actualInfo.Entries[0])
	}
}

func TestGetVifInfo2(t *testing.T) {
	entry1 := &rpc.VifEntry {
		Name: "tv0",
		Addr: "",
	}
	entry2 := &rpc.VifEntry {
		Name: "invalid_name",
		Addr: "",
	}
	info := &rpc.VifInfo {
		N: 2,
		Entries: []*rpc.VifEntry{entry1, entry2},
	}

	vrrp := &vrrp{}
	actualInfo, err := vrrp.GetVifInfo(nil, info)

	if actualInfo != nil && err == nil {
		log.Fatal("GetVifInfo2 failed.")
	}
}

func TestGetVifInfo3(t *testing.T) {
	vrrp := &vrrp{}
	_, err := vrrp.GetVifInfo(nil, nil)

	if err == nil {
		log.Fatal("GetVifInfo3 failed")
	}
}

func TestToMaster1(t *testing.T) {
	entry1 := &rpc.VifEntry {
		Name: "tv0",
		Addr: "192.168.0.1/24",
	}
	entry2 := &rpc.VifEntry {
		Name: "tv0",
		Addr: "192.168.1.1/24",
	}
	info := &rpc.VifInfo {
		N: 2,
		Entries: []*rpc.VifEntry{entry1, entry2},
	}

	vrrp := &vrrp{}

	rep, err := vrrp.ToMaster(nil, info)

	if err != nil {
		log.Fatalf("ToMaster1 failed: %+v", err)
	} else if rep.Code != rpc.ResultCode_SUCCESS {
		log.Fatalf("ToMaster1 failed: %+v\n", rep)
	}

	actualInfo, err := findVifInfo("tv0")
	for _, addr := range actualInfo.IPAddrs.ListIPAddrs() {
		if addr.String() != "192.168.0.1/24" &&
			addr.String() != "192.168.1.1/24" {
			log.Fatal("ToMaster1 failed: %+v", addr)
		}
	}
}

func TestToMaster2(t *testing.T) {
	vrrp := &vrrp{}
	_, err := vrrp.ToMaster(nil, nil)

	if err == nil {
		log.Fatal("ToMaster2 failed")
	}
}

// Depends on TestToMaster1
func TestToBackup1(t *testing.T) {
	entry1 := &rpc.VifEntry {
		Name: "tv0",
		Addr: "192.168.0.1/24",
	}
	entry2 := &rpc.VifEntry {
		Name: "tv0",
		Addr: "192.168.1.1/24",
	}
	info := &rpc.VifInfo {
		N: 2,
		Entries: []*rpc.VifEntry{entry1, entry2},
	}

	vrrp := &vrrp{}

	rep, err := vrrp.ToBackup(nil, info)

	if err != nil {
		log.Fatalf("ToBackup1 failed: %+v", err)
	} else if rep.Code != rpc.ResultCode_SUCCESS {
		log.Fatalf("ToBackup1 failed: %+v\n", rep)
	}

	actualInfo, err := findVifInfo("tv0")
	if len(actualInfo.IPAddrs.ListIPAddrs()) != 0 {
		log.Fatalf("ToBackup1 failed: %+v\n", actualInfo.IPAddrs.ListIPAddrs())
	}
}

func TestToBackup2(t *testing.T) {
	vrrp := &vrrp{}
	_, err := vrrp.ToBackup(nil, nil)

	if err == nil {
		log.Fatal("ToBackup2 failed")
	}
}

func TestRpcClientGetVifInfo(t *testing.T) {
	conn, err := grpc.Dial(":30010", grpc.WithInsecure())
	if err != nil {
		log.Fatalf(":30010 connection failed: %v", err)
	}
	defer conn.Close()

	entry := &rpc.VifEntry {
		Name: "tv0",
		Addr: "",
	}
	info := &rpc.VifInfo {
		N: 1,
		Entries: []*rpc.VifEntry{entry},
	}

	io := rpc.NewVrrpClient(conn)
	ctx, _ := context.WithCancel(context.Background())
	actualInfo, err := io.GetVifInfo(ctx, info)

	if err != nil {
		log.Fatalf("RpcClient failed: %+v", err)
	} else if actualInfo.Entries[0].Name != "tv0" ||
		actualInfo.Entries[0].Addr != "12:34:56:78:00:01" {
		log.Fatalf("RpcClient failed: %+v\n", actualInfo.Entries[0])
	}
}

func TestRpcClientToMaster(t *testing.T) {
	conn, err := grpc.Dial(":30010", grpc.WithInsecure())
	if err != nil {
		log.Fatalf(":30010 connection failed: %v", err)
	}
	defer conn.Close()

	entry1 := &rpc.VifEntry {
		Name: "tv0",
		Addr: "192.168.0.1/24",
	}
	entry2 := &rpc.VifEntry {
		Name: "tv0",
		Addr: "192.168.1.1/24",
	}
	info := &rpc.VifInfo {
		N: 2,
		Entries: []*rpc.VifEntry{entry1, entry2},
	}

	io := rpc.NewVrrpClient(conn)
	ctx, _ := context.WithCancel(context.Background())
	rep, err := io.ToMaster(ctx, info)

	if err != nil {
		log.Fatalf("ToMaster1 failed: %+v", err)
	} else if rep.Code != rpc.ResultCode_SUCCESS {
		log.Fatalf("ToMaster1 failed: %+v\n", rep)
	}

	actualInfo, err := findVifInfo("tv0")
	for _, addr := range actualInfo.IPAddrs.ListIPAddrs() {
		if addr.String() != "192.168.0.1/24" &&
			addr.String() != "192.168.1.1/24" {
			log.Fatal("ToMaster1 failed: %+v", addr)
		}
	}
}

func TestRpcClientToBackup(t *testing.T) {
	conn, err := grpc.Dial(":30010", grpc.WithInsecure())
	if err != nil {
		log.Fatalf(":30010 connection failed: %v", err)
	}
	defer conn.Close()

	entry1 := &rpc.VifEntry {
		Name: "tv0",
		Addr: "192.168.0.1/24",
	}
	entry2 := &rpc.VifEntry {
		Name: "tv0",
		Addr: "192.168.1.1/24",
	}
	info := &rpc.VifInfo {
		N: 2,
		Entries: []*rpc.VifEntry{entry1, entry2},
	}

	io := rpc.NewVrrpClient(conn)
	ctx, _ := context.WithCancel(context.Background())
	rep, err := io.ToBackup(ctx, info)

	if err != nil {
		log.Fatalf("ToBackup1 failed: %+v", err)
	} else if rep.Code != rpc.ResultCode_SUCCESS {
		log.Fatalf("ToBackup1 failed: %+v\n", rep)
	}

	actualInfo, err := findVifInfo("tv0")
	if len(actualInfo.IPAddrs.ListIPAddrs()) != 0 {
		log.Fatalf("ToBackup1 failed: %+v\n", actualInfo.IPAddrs.ListIPAddrs())
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

	// Create Instances
	vrf := vswitch.NewVRF("testvrf", 0)
	testvif := vrf.NewModule("testvif", "tv0")
	dumb := vrf.NewModule("dumb", "dumb0")

	// Connect Instances
	testvif.Connect(dumb, vswitch.MATCH_ANY)
	dumb.Connect(testvif, vswitch.MATCH_ANY)

	// Get Channels
	tx_chan, _ = testvif.Control("GET_TX_CHAN", nil).(chan *dpdk.Mbuf)
	rx_chan, _ = testvif.Control("GET_RX_CHAN", nil).(chan *dpdk.Mbuf)
	vif_mac, _ = testvif.Control("GET_MAC_ADDRESS", nil).(net.HardwareAddr)

	// Start agent
	vswitch.StartNamedAgents("vrrp")

	// Start
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
