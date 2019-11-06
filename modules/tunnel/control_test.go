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

package tunnel

import (
	"net"
	"testing"

	"github.com/lagopus/vsw/vswitch"
)

//
// L3
//

func TestToL3CParam(t *testing.T) {
	addressType := vswitch.AF_IPv4
	localAddr := net.ParseIP("172.16.0.2")
	remoteAddr := net.ParseIP("172.16.0.1")
	hopLimit := uint8(defaultHopLimit)
	tos := int8(defaultTos)

	from := createL3SetEnableCmdParam(addressType, localAddr, remoteAddr, hopLimit, tos, nil, nil)

	if from == nil {
		t.Fatalf("from nil\n")
	}

	to := toL3CParam(from);
	if to == nil {
		t.Fatalf("to nil\n")
	}

	if to.cmd != from.cmd {
		t.Fatalf("cmd failed\n")
	}

	if to.address_type != from.address_type {
		t.Fatalf("address_type failed\n")
	}

	if to.local_addr.ip[0] != from.local_addr.ip[0] {
		t.Fatalf("local_addr[0] failed\n")
	}

	if to.local_addr.ip[1] != from.local_addr.ip[1] {
		t.Fatalf("local_addr[1] failed\n")
	}

	if to.local_addr.ip[2] != from.local_addr.ip[2] {
		t.Fatalf("local_addr[2] failed\n")
	}

	if to.local_addr.ip[3] != from.local_addr.ip[3] {
		t.Fatalf("local_addr[3] failed\n")
	}

	if to.remote_addr.ip[0] != from.remote_addr.ip[0] {
		t.Fatalf("remote_addr[0] failed\n")
	}

	if to.remote_addr.ip[1] != from.remote_addr.ip[1] {
		t.Fatalf("remote_addr[1] failed\n")
	}

	if to.remote_addr.ip[2] != from.remote_addr.ip[2] {
		t.Fatalf("remote_addr[2] failed\n")
	}

	if to.remote_addr.ip[3] != from.remote_addr.ip[3] {
		t.Fatalf("remote_addr[3] failed\n")
	}

	if to.hop_limit != from.hop_limit {
		t.Fatalf("hop_limit failed\n")
	}

	if to.tos != from.tos {
		t.Fatalf("tos failed\n")
	}

	freeL3CParam(to)
}

func TestCreateL3SetAddressTypeCmdParam(t *testing.T) {
	addressType := vswitch.AF_IPv4

	param := createL3SetAddressTypeCmdParam(addressType)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestCreateL3SetLocalAddressCmdParam(t *testing.T) {
	remoteAddr := net.ParseIP("172.16.0.1")

	param := createL3SetLocalAddressCmdParam(remoteAddr)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestCreateL3SetRemoteAddressCmdParam(t *testing.T) {
	localAddr := net.ParseIP("172.16.0.2")

	param := createL3SetRemoteAddressCmdParam(localAddr)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestL3TunnelVIFCreateL2SetRemoteAddressesCmdParam(t *testing.T) {
	remoteAddrs := []net.IP{net.ParseIP("172.16.0.1"), net.ParseIP("172.16.0.1")}

	param := createL2SetRemoteAddressesCmdParam(remoteAddrs)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestCreateL3SetHopLimitCmdParam(t *testing.T) {
	hopLimit := uint8(defaultHopLimit)

	param := createL3SetHopLimitCmdParam(hopLimit)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestCreateL3SetTOSCmdParam(t *testing.T) {
	tos := int8(defaultTos)

	param := createL3SetTOSCmdParam(tos)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestCreateL3SetEnableCmdParam(t *testing.T) {
	addressType := vswitch.AF_IPv4
	localAddr := net.ParseIP("172.16.0.2")
	remoteAddr := net.ParseIP("172.16.0.1")
	hopLimit := uint8(defaultHopLimit)
	tos := int8(defaultTos)

	param := createL3SetEnableCmdParam(addressType, localAddr, remoteAddr, hopLimit, tos, nil, nil)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestCreateL3SetDisableCmdParam(t *testing.T) {
	param := createL3SetDisableCmdParam()

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

//
// L2
//

func TestToL2CParam(t *testing.T) {
	index := vswitch.VIFIndex(200)
	addressType := vswitch.AF_IPv4
	localAddr := net.ParseIP("172.16.0.2")
	remoteAddrs := []net.IP{net.ParseIP("172.16.0.1"), net.ParseIP("172.16.0.1")}
	hopLimit := uint8(defaultHopLimit)
	tos := uint8(10)
	vid := vswitch.VID(111)
	mode := vswitch.TrunkMode
	vni := uint32(100)

	from := createL2SetEnableCmdParam(index, addressType, localAddr, remoteAddrs,
		hopLimit, tos, nil, nil, vid, mode, vni, nil, nil)

	if from == nil {
		t.Fatalf("from nil\n")
	}

	to := toL2CParam(from);
	if to == nil {
		t.Fatalf("to nil\n")
	}

	if to.cmd != from.cmd {
		t.Fatalf("cmd failed\n")
	}

	if to.index != from.index {
		t.Fatalf("index failed\n")
	}

	if to.address_type != from.address_type {
		t.Fatalf("address_type failed\n")
	}

	if to.local_addr.ip[0] != from.local_addr.ip[0] {
		t.Fatalf("local_addr[0] failed\n")
	}

	if to.local_addr.ip[1] != from.local_addr.ip[1] {
		t.Fatalf("local_addr[1] failed\n")
	}

	if to.local_addr.ip[2] != from.local_addr.ip[2] {
		t.Fatalf("local_addr[2] failed\n")
	}

	if to.local_addr.ip[3] != from.local_addr.ip[3] {
		t.Fatalf("local_addr[3] failed\n")
	}

	if to.remote_addrs.addrs[0].ip[0] != from.remote_addrs.addrs[0].ip[0] {
		t.Fatalf("remote_addrs[0] [0] failed\n")
	}

	if to.remote_addrs.addrs[0].ip[1] != from.remote_addrs.addrs[0].ip[1] {
		t.Fatalf("remote_addrs[0] [1] failed\n")
	}

	if to.remote_addrs.addrs[0].ip[2] != from.remote_addrs.addrs[0].ip[2] {
		t.Fatalf("remote_addrs[0] [2] failed\n")
	}

	if to.remote_addrs.addrs[0].ip[3] != from.remote_addrs.addrs[0].ip[3] {
		t.Fatalf("remote_addrs[0] [3] failed\n")
	}

	if to.remote_addrs.addrs[1].ip[0] != from.remote_addrs.addrs[1].ip[0] {
		t.Fatalf("remote_addrs[1] [0] failed\n")
	}

	if to.remote_addrs.addrs[1].ip[1] != from.remote_addrs.addrs[1].ip[1] {
		t.Fatalf("remote_addrs[1] [1] failed\n")
	}

	if to.remote_addrs.addrs[1].ip[2] != from.remote_addrs.addrs[1].ip[2] {
		t.Fatalf("remote_addrs[1] [2] failed\n")
	}

	if to.remote_addrs.addrs[1].ip[3] != from.remote_addrs.addrs[1].ip[3] {
		t.Fatalf("remote_addrs[1] [3] failed\n")
	}

	if to.hop_limit != from.hop_limit {
		t.Fatalf("hop_limit failed\n")
	}

	if to.tos != from.tos {
		t.Fatalf("tos failed\n")
	}

	if to.vid != from.vid {
		t.Fatalf("vid failed\n")
	}

	if to.trunk != from.trunk {
		t.Fatalf("mode failed\n")
	}

	if to.vni != from.vni {
		t.Fatalf("vni failed\n")
	}

	freeL2CParam(to)
}

func TestCreateL2SetAddressTypeCmdParam(t *testing.T) {
	addressType := vswitch.AF_IPv4

	param := createL2SetAddressTypeCmdParam(addressType)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestCreateL2SetLocalAddressCmdParam(t *testing.T) {
	localAddr := net.ParseIP("172.16.0.2")

	param := createL2SetLocalAddressCmdParam(localAddr)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestCreateL2SetRemoteAddressesCmdParam(t *testing.T) {
	remoteAddrs := []net.IP{net.ParseIP("172.16.0.1"), net.ParseIP("172.16.0.2")}

	param := createL2SetRemoteAddressesCmdParam(remoteAddrs)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestCreateL2SetHopLimitCmdParam(t *testing.T) {
	hopLimit := uint8(defaultHopLimit)

	param := createL2SetHopLimitCmdParam(hopLimit)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestCreateL2SetTOSCmdParam(t *testing.T) {
	tos := uint8(10)

	param := createL2SetTOSCmdParam(tos)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestCreateL2SetVLANModeCmdParam(t *testing.T) {
	mode := vswitch.TrunkMode

	param := createL2SetVLANModeCmdParam(mode)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestCreateL2SetVNICmdParam(t *testing.T) {
	vni := uint32(100)

	param := createL2SetVNICmdParam(vni)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestCreateL2SetEnableCmdParam(t *testing.T) {
	index := vswitch.VIFIndex(200)
	addressType := vswitch.AF_IPv4
	localAddr := net.ParseIP("172.16.0.2")
	remoteAddrs := []net.IP{net.ParseIP("172.16.0.1"), net.ParseIP("172.16.0.1")}
	hopLimit := uint8(defaultHopLimit)
	tos := uint8(10)
	vid := vswitch.VID(111)
	mode := vswitch.TrunkMode
	vni := uint32(100)

	param := createL2SetEnableCmdParam(index, addressType, localAddr, remoteAddrs,
		hopLimit, tos, nil, nil, vid, mode, vni, nil, nil)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestCreateL2SetDisableCmdParam(t *testing.T) {
	index := vswitch.VIFIndex(200)
	vid := vswitch.VID(111)

	param := createL2SetDisableCmdParam(index, vid)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}
