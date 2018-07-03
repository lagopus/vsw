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

package tunnel

import (
	"net"
	"reflect"
	"testing"

	"github.com/lagopus/vsw/vswitch"
)

func TestNewWrapperIF(t *testing.T) {
	iface := newWrapperIF(nil, nil)
	if iface == nil {
		t.Fatalf("TunnelIF nil\n")
	}

	if iface.iface != nil {
		t.Fatalf("ConcreteIF not nil\n")
	}
}

func TestWrapperIFFree(t *testing.T) {
	iface := newWrapperIF(nil, nil)

	iface.Free()
	if iface.state != freed {
		t.Fatalf("state not freed\n")
	}

	iface.Enable()
	if iface.state != freed {
		t.Fatalf("state not freed\n")
	}

	iface.Disable()
	if iface.state != freed {
		t.Fatalf("state not freed\n")
	}
}

func TestWrapperIFEnable(t *testing.T) {
	iface := newWrapperIF(nil, nil)

	iface.Enable()
	if iface.state != enabled {
		t.Fatalf("state not enabled\n")
	}
}

func TestWrapperIFDisable(t *testing.T) {
	iface := newWrapperIF(nil, nil)

	iface.Disable()
	if iface.state != disabled {
		t.Fatalf("state not disabled\n")
	}
}

func TestWrapperIFMACAddress(t *testing.T) {
	iface := newWrapperIF(nil, nil)

	if iface.MACAddress() != nil {
		t.Fatalf("MACAddress not nil\n")
	}
}

func TestWrapperIFSetMACAddress(t *testing.T) {
	iface := newWrapperIF(nil, nil)

	mac := net.HardwareAddr{0x10, 0x02, 0x03, 0x04, 0x05, 0x06}
	if iface.SetMACAddress(mac) != nil {
		t.Fatalf("SetMACAddress not nil\n")
	}

	if !reflect.DeepEqual(mac, iface.MACAddress()) {
		t.Fatalf("invalid MACAddress\n")
	}
}

func TestWrapperIFMTU(t *testing.T) {
	iface := newWrapperIF(nil, nil)

	if iface.MTU() != vswitch.DefaultMTU {
		t.Fatalf("invalid MTU: %d\n", iface.MTU())
	}
}

func TestWrapperIFSetMTU(t *testing.T) {
	iface := newWrapperIF(nil, nil)

	if iface.SetMTU(4096) != nil {
		t.Fatalf("SetMTU failed\n")
	}

	if iface.MTU() != 4096 {
		t.Fatalf("invalid MTU: %d\n", iface.MTU())
	}
}

func TestWrapperIFInterfaceMode(t *testing.T) {
	iface := newWrapperIF(nil, nil)

	if iface.InterfaceMode() != vswitch.AccessMode {
		t.Fatalf("invalid InterfaceMode: %d\n", iface.InterfaceMode())
	}
}

func TestWrapperIFSetInterfaceMode(t *testing.T) {
	iface := newWrapperIF(nil, nil)

	if iface.SetInterfaceMode(vswitch.AccessMode) == nil {
		t.Fatalf("SetInterfaceMode failed\n")
	}
}

func TestWrapperIFAddVID(t *testing.T) {
	iface := newWrapperIF(nil, nil)

	if iface.AddVID(200) == nil {
		t.Fatalf("AddVID failed\n")
	}
}

func TestWrapperIFDeleteVID(t *testing.T) {
	iface := newWrapperIF(nil, nil)

	if iface.DeleteVID(200) == nil {
		t.Fatalf("DeleteVID failed\n")
	}
}

func TestWrapperIFSetNativeVID(t *testing.T) {
	iface := newWrapperIF(nil, nil)

	if iface.SetNativeVID(200) == nil {
		t.Fatalf("SetNativeVID failed\n")
	}
}
