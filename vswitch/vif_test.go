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

package vswitch

import (
	"bytes"
	"net"
	"testing"
)

func listIP(t *testing.T, v *VifInfo, addrs []IPAddr, expect int) {
	count := 0
	for _, addr := range addrs {
		t.Logf("\t%s", addr)
		count++
	}
	if count != expect {
		t.Errorf("VIF: # of IP address != 2 (%d)", count)
	}
}

func testVi(t *testing.T, vi *VifInfo, mac net.HardwareAddr) {
	if bytes.Compare(vi.MacAddress(), mac) != 0 {
		t.Errorf("VIF: %s != %s", mac, vi.MacAddress())
	}
	t.Logf("VIF MAC: %s\n", vi.MacAddress())

	t.Logf("Setting IP Addresses\n")

	ipv4 := IPAddr{IP: net.ParseIP("192.168.1.1"), Mask: net.CIDRMask(24, 32)}
	ipv6 := IPAddr{IP: net.ParseIP("2001:db8::68"), Mask: net.CIDRMask(64, 128)}

	if !vi.AddIPAddr(ipv4) {
		t.Errorf("VIF: Can't set IPv4: %s\n", ipv4)
	}

	if !vi.AddIPAddr(ipv6) {
		t.Errorf("VIF: Can't set IPv6: %s\n", ipv6)
	}

	// List all IP
	t.Logf("VIF: List All IP Address:\n")
	listIP(t, vi, vi.ListIPAddrs(), 2)

	// Change Prefix
	t.Logf("VIF: Modify IPv4 Address Prefix:\n")
	ipv4.Mask = net.CIDRMask(32, 32)
	if !vi.AddIPAddr(ipv4) {
		t.Errorf("VIF: Can't change prefix of IPv4: %s\n", ipv4)
	}

	// List all IP
	t.Logf("VIF: List All IP Address:\n")
	listIP(t, vi, vi.ListIPAddrs(), 2)
}

type dummyVif struct{}

func (d *dummyVif) Link() LinkStatus          { return LinkUp }
func (d *dummyVif) SetLink(s LinkStatus) bool { return true }

var vm = &dummyVif{}
var ms0 = NewModuleService(&ModuleParam{name: "vif0", vrf: &VrfInfo{name: "testVrf"}})
var ms1 = NewModuleService(&ModuleParam{name: "vif1", vrf: &VrfInfo{name: "testVrf"}})

func checkVifIndex(t *testing.T, name string, idx VifIndex) {
	gidx := GetVifIndex(name)
	if gidx == idx {
		t.Logf("VifIndex for %s matched (idx=%d).", name, idx)
	} else {
		t.Errorf("VifIndex for %s doesn't match. (Expected %d, Got %d)", name, idx, gidx)
	}
}

func TestVifBasic(t *testing.T) {
	vif0 := newVif()
	vif0.config(vm, ms0)

	t.Logf("VIF created: Vif Index = %v\n", vif0.VifIndex())

	mac, _ := net.ParseMAC("01:23:45:67:89:ab")
	vif0.SetMacAddress(mac)

	vi := GetVifInfo(vif0.VifIndex())
	testVi(t, vi, mac)

	vif1 := newVif()
	vif1.config(vm, ms1)
	t.Logf("VIF created: Vif Index = %v\n", vif1.VifIndex())
	vif1.SetMacAddress(mac)
	testVi(t, vif1.VifInfo(), mac)

	// search VIF Index
	checkVifIndex(t, "vif0", vif0.VifIndex())
	checkVifIndex(t, "vif1", vif1.VifIndex())
}

func TestVifNotification(t *testing.T) {
	noti := GetNotifier()
	ch := noti.Listen()
	done := make(chan struct{})

	go func() {
		for n := range ch {
			t.Log(n)
		}
		close(done)
	}()

	vif := newVif()
	vif.config(vm, ms0)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	vif.SetMacAddress(mac)

	vi := GetVifInfo(vif.VifIndex())
	testVi(t, vi, mac)

	t.Logf("VRF=%v", vi.Vrf().Name())

	noti.Close(ch)

	<-done
}
