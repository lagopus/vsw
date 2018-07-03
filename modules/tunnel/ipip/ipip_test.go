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

package ipip

import (
	"net"
	"testing"

	"github.com/lagopus/vsw/vswitch"
)

//
// TunnelIF
//

func TestNewTunnelIF(t *testing.T) {
	index := uint16(0)
	name := "tunnelIf"
	iface := newTunnelIF(index, name, nil, nil)
	if iface == nil {
		t.Fatalf("TunnelIF nil\n")
	}

	if iface.index != index {
		t.Fatalf("invalid index: %d\n", iface.index)
	}

	if iface.name != name {
		t.Fatalf("invalid name: %s\n", iface.name)
	}

	if iface.inboundCiface == nil {
		t.Fatalf("inboundCiface nil\n")
	}

	if iface.outboundCiface == nil {
		t.Fatalf("outboundCiface nil\n")
	}

	if iface.cname == nil {
		t.Fatalf("cname nil\n")
	}

	if iface.inboundRti != nil {
		t.Fatalf("inbound runtime instance not nil\n")
	}

	if iface.outboundRti != nil {
		t.Fatalf("outbound runtime instance not nil\n")
	}

	if iface.vif != nil {
		t.Fatalf("TunnelVIF not nil\n")
	}

	if iface.enable {
		t.Fatalf("enable true\n")
	}
}

func TestTunnelIFFree(t *testing.T) {
	iface := newTunnelIF(uint16(0), "tunnelIf", nil, nil)

	iface.Free()
}

func TestTunnelIFEnable(t *testing.T) {
	iface := newTunnelIF(uint16(0), "tunnelIf", nil, nil)

	if err := iface.Enable(); err == nil {
		t.Fatalf("enable failed: %v\n", err)
	}

	if iface.enable {
		t.Fatalf("enable true\n")
	}
}

func TestTunnelIFDisable(t *testing.T) {
	iface := newTunnelIF(uint16(0), "tunnelIf", nil, nil)

	iface.Disable()

	if iface.enable {
		t.Fatalf("enable true\n")
	}
}

func TestTunnelIFNewVIF(t *testing.T) {
	iface := newTunnelIF(uint16(0), "tunnelIf", nil, nil)
	vif, err := iface.NewVIF(&vswitch.VIF{})

	if vif == nil || err != nil {
		t.Fatalf("NewVIF error: %v\n", err)
	}
}

//
// TunnelVIF
//

func TestNewTunnelVIF(t *testing.T) {
	iface := newTunnelIF(uint16(0), "tunnelIf", nil, nil)
	vif := newTunnelVIF(iface, &vswitch.VIF{})

	if vif == nil {
		t.Fatalf("TunnelVIF nil\n")
	}

	if vif.enable {
		t.Fatalf("enable true\n")
	}

	if newTunnelVIF(nil, &vswitch.VIF{}) != nil {
		t.Fatalf("TunnelVIF not nil\n")
	}

	if newTunnelVIF(iface, nil) != nil {
		t.Fatalf("TunnelVIF not nil\n")
	}
}

func TestTunnelVIFFree(t *testing.T) {
	iface := newTunnelIF(uint16(0), "tunnelIf", nil, nil)
	vif := newTunnelVIF(iface, &vswitch.VIF{})

	vif.Free()
}

func TestTunnelVIFEnable(t *testing.T) {
	iface := newTunnelIF(uint16(0), "tunnelIf", nil, nil)
	vif := newTunnelVIF(iface, &vswitch.VIF{})

	if err := vif.Enable(); err == nil {
		t.Fatalf("enable failed: %v\n", err)
	}

	if vif.enable {
		t.Fatalf("enable true\n")
	}
}

func TestTunnelVIFDisable(t *testing.T) {
	iface := newTunnelIF(uint16(0), "tunnelIf", nil, nil)
	vif := newTunnelVIF(iface, &vswitch.VIF{})

	vif.Disable()

	if vif.enable {
		t.Fatalf("enable true\n")
	}
}

func TestTunnelVIFNewAddressTypeCmdParam(t *testing.T) {
	iface := newTunnelIF(uint16(0), "tunnelIf", nil, nil)
	vif := newTunnelVIF(iface, &vswitch.VIF{})

	addressType := vswitch.AF_IPv4

	param := vif.newAddressTypeCmdParam(addressType)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestTunnelVIFNewLocalAddressCmdParam(t *testing.T) {
	iface := newTunnelIF(uint16(0), "tunnelIf", nil, nil)
	vif := newTunnelVIF(iface, &vswitch.VIF{})

	localAddr := net.ParseIP("172.16.0.2")

	param := vif.newLocalAddressCmdParam(localAddr)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestTunnelVIFNewRemoteAddressCmdParam(t *testing.T) {
	iface := newTunnelIF(uint16(0), "tunnelIf", nil, nil)
	vif := newTunnelVIF(iface, &vswitch.VIF{})

	remoteAddr := net.ParseIP("172.16.0.1")

	param := vif.newRemoteAddressCmdParam(remoteAddr)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestTunnelVIFNewHopLimitCmdParam(t *testing.T) {
	iface := newTunnelIF(uint16(0), "tunnelIf", nil, nil)
	vif := newTunnelVIF(iface, &vswitch.VIF{})

	hopLimit := uint8(defaultHopLimit)

	param := vif.newHopLimitCmdParam(hopLimit)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestTunnelVIFNewTOSParam(t *testing.T) {
	iface := newTunnelIF(uint16(0), "tunnelIf", nil, nil)
	vif := newTunnelVIF(iface, &vswitch.VIF{})

	tos := int8(defaultTos)

	param := vif.newTOSCmdParam(tos)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestTunnelVIFNewEnableCmdParam(t *testing.T) {
	iface := newTunnelIF(uint16(0), "tunnelIf", nil, nil)
	vif := newTunnelVIF(iface, &vswitch.VIF{})

	enable := true

	param := vif.newEnableCmdParam(enable)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}

func TestTunnelVIFNewAllCmdParam(t *testing.T) {
	iface := newTunnelIF(uint16(0), "tunnelIf", nil, nil)
	vif := newTunnelVIF(iface, &vswitch.VIF{})

	addressType := vswitch.AF_IPv4
	localAddr := net.ParseIP("172.16.0.2")
	remoteAddr := net.ParseIP("172.16.0.1")
	hopLimit := uint8(defaultHopLimit)
	tos := int8(defaultTos)
	enable := true

	param := vif.newAllCmdParam(addressType, localAddr, remoteAddr,
		hopLimit, tos, enable, nil)

	if param == nil {
		t.Fatalf("param nil\n")
	}
}
