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
	"testing"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/vswitch"
)

type l3IfParam struct {
	proto  ProtocolType
	ifName string
}

func newL3IfParam(protocol ProtocolType, ifName string) *l3IfParam {
	return &l3IfParam{
		proto:  protocol,
		ifName: ifName,
	}
}

func (l *l3IfParam) protocol() ProtocolType {
	return l.proto
}

func (l *l3IfParam) name() string {
	return l.ifName
}

func (l *l3IfParam) outbound() *dpdk.Ring {
	return nil
}

func (l *l3IfParam) inbound() *dpdk.Ring {
	return nil
}

func (l *l3IfParam) rules() *vswitch.Rules {
	return nil
}

func (l *l3IfParam) interfaceMode() vswitch.VLANMode {
	return vswitch.TrunkMode
}

func (l *l3IfParam) moduleConfig() *ModuleConfig {
	return nil
}

func (l *l3IfParam) l2tunnelConfig() *vswitch.L2Tunnel {
	return nil
}

func (l *l3IfParam) counter() *vswitch.Counter {
	return nil
}

//
// L3TunnelIF
//

func TestNewL3TunnelIF(t *testing.T) {
	accessor := newL3IfParam(IPIP, "l3tunnelIf")

	iface := newL3TunnelIF(accessor)
	if iface == nil {
		t.Fatalf("TunnelIF nil\n")
	}

	if iface.name != accessor.name() {
		t.Fatalf("invalid name: %s\n", iface.name)
	}

	if iface.inboundCIface == nil {
		t.Fatalf("inboundCiface nil\n")
	}

	if iface.outboundCIface == nil {
		t.Fatalf("outboundCiface nil\n")
	}

	if iface.inboundCname == nil {
		t.Fatalf("inboundCname nil\n")
	}

	if iface.outboundCname == nil {
		t.Fatalf("outboundCname nil\n")
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

	if iface.enabled {
		t.Fatalf("enabled true\n")
	}
}

func TestL3TunnelIFFree(t *testing.T) {
	accessor := newL3IfParam(IPIP, "l3tunnelIf")
	iface := newL3TunnelIF(accessor)
	iface.Free()
}

func TestL3TunnelIFEnable(t *testing.T) {
	accessor := newL3IfParam(IPIP, "l3tunnelIf")
	iface := newL3TunnelIF(accessor)

	if err := iface.Enable(); err == nil {
		t.Fatalf("enable failed: %v\n", err)
	}

	if iface.enabled {
		t.Fatalf("enable true\n")
	}
}

func TestL3TunnelIFDisable(t *testing.T) {
	accessor := newL3IfParam(IPIP, "l3tunnelIf")
	iface := newL3TunnelIF(accessor)

	iface.Disable()

	if iface.enabled {
		t.Fatalf("enable true\n")
	}
}

func TestL3TunnelIFNewVIF(t *testing.T) {
	accessor := newL3IfParam(IPIP, "l3tunnelIf")
	iface := newL3TunnelIF(accessor)
	vif, err := iface.newVIF(&vswitch.VIF{})

	if vif == nil || err != nil {
		t.Fatalf("NewVIF error: %v\n", err)
	}
}

//
// L3TunnelVIF
//

func TestNewL3TunnelVIF(t *testing.T) {
	accessor := newL3IfParam(IPIP, "l3tunnelIf")
	iface := newL3TunnelIF(accessor)
	vif := newL3TunnelVIF(iface, &vswitch.VIF{})

	if vif == nil {
		t.Fatalf("TunnelVIF nil\n")
	}

	if vif.enabled {
		t.Fatalf("enable true\n")
	}

	if newL3TunnelVIF(nil, &vswitch.VIF{}) != nil {
		t.Fatalf("TunnelVIF not nil\n")
	}

	if newL3TunnelVIF(iface, nil) != nil {
		t.Fatalf("TunnelVIF not nil\n")
	}
}

func TestL3TunnelVIFFree(t *testing.T) {
	accessor := newL3IfParam(IPIP, "l3tunnelIf")
	iface := newL3TunnelIF(accessor)
	vif := newL3TunnelVIF(iface, &vswitch.VIF{})

	vif.Free()
}

func TestL3TunnelVIFEnable(t *testing.T) {
	accessor := newL3IfParam(IPIP, "l3tunnelIf")
	iface := newL3TunnelIF(accessor)
	vif := newL3TunnelVIF(iface, &vswitch.VIF{})

	if err := vif.Enable(); err == nil {
		t.Fatalf("enable failed: %v\n", err)
	}

	if vif.enabled {
		t.Fatalf("enable true\n")
	}
}

func TestL3TunnelVIFDisable(t *testing.T) {
	accessor := newL3IfParam(IPIP, "l3tunnelIf")
	iface := newL3TunnelIF(accessor)
	vif := newL3TunnelVIF(iface, &vswitch.VIF{})

	vif.Disable()

	if vif.enabled {
		t.Fatalf("enable true\n")
	}
}
