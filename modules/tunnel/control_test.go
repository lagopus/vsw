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
