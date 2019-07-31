//
// Copyright 2018-2019 Nippon Telegraph and Telephone Corporation.
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
	"net"
	"testing"
	"time"
)

type tunnelMember int

const (
	tm_af tunnelMember = iota
	tm_em
	tm_hop
	tm_local
	tm_remote
	tm_remotes
	tm_s
	tm_tos
	tm_vrf
	tm_vni
)

func (tm tunnelMember) String() string {
	s := map[tunnelMember]string{
		tm_af:      "AddressType",
		tm_em:      "EncapsMethod",
		tm_hop:     "HopLimit",
		tm_local:   "LocalAddress",
		tm_remote:  "RemoteAddress",
		tm_remotes: "RemoteAddresses",
		tm_s:       "Security",
		tm_tos:     "TOS",
		tm_vrf:     "VRF",
		tm_vni:     "VNI",
	}
	return s[tm]
}

type tunnelObserver struct {
	t       *testing.T
	tu      *L3Tunnel
	l2      *L2Tunnel
	af      AddressFamily
	em      EncapsMethod
	hop     uint8
	local   net.IP
	remotes []net.IP
	s       Security
	tos     int
	vrf     *VRF
	vni     uint32
	rcvd    chan tunnelMember
}

func (o *tunnelObserver) AddressTypeUpdated(af AddressFamily) {
	if o.af != af {
		o.t.Fatalf("New Addresss Family doesn't match: %v != %v", o.af, af)
	}
	if o.tu != nil {
		if af == o.tu.AddressType() {
			o.t.Fatalf("New Addresss Family shouldn't match with old one: %v != %v", o.tu.AddressType(), af)
		}
	} else {
		if af == o.l2.AddressType() {
			o.t.Fatalf("New Addresss Family shouldn't match with old one: %v != %v", o.l2.AddressType(), af)
		}
	}
	o.t.Logf("AddressType as expected: %v", af)
	o.rcvd <- tm_af
}

func (o *tunnelObserver) EncapsMethodUpdated(em EncapsMethod) {
	if o.em != em {
		o.t.Fatalf("New EncapsMethod doesn't match: %v != %v", o.em, em)
	}
	if o.tu != nil {
		if em == o.tu.EncapsMethod() {
			o.t.Fatalf("New EncapsMethod shouldn't match with old one: %v != %v", o.tu.EncapsMethod(), em)
		}
	} else {
		if em == o.l2.EncapsMethod() {
			o.t.Fatalf("New EncapsMethod shouldn't match with old one: %v != %v", o.l2.EncapsMethod(), em)
		}
	}
	o.t.Logf("EncapsMethod as expected: %v", em)
	o.rcvd <- tm_em
}

func (o *tunnelObserver) HopLimitUpdated(hop uint8) {
	if o.hop != hop {
		o.t.Fatalf("New HopLimit doesn't match: %v != %v", o.hop, hop)
	}
	if o.tu != nil {
		if hop == o.tu.HopLimit() {
			o.t.Fatalf("New HopLimit shouldn't match with old one: %v != %v", o.tu.HopLimit(), hop)
		}
	} else {
		if hop == o.l2.HopLimit() {
			o.t.Fatalf("New HopLimit shouldn't match with old one: %v != %v", o.l2.HopLimit(), hop)
		}
	}
	o.t.Logf("HopLimit as expected: %v", hop)
	o.rcvd <- tm_hop
}

func (o *tunnelObserver) LocalAddressUpdated(ip net.IP) {
	if !o.local.Equal(ip) {
		o.t.Fatalf("New LocalAddress doesn't match: %v != %v", o.local, ip)
	}
	if o.tu != nil {
		if ip.Equal(o.tu.LocalAddress()) {
			o.t.Fatalf("New LocalAddress shouldn't match with old one: %v != %v", o.tu.LocalAddress(), ip)
		}
	} else {
		if ip.Equal(o.l2.LocalAddress()) {
			o.t.Fatalf("New LocalAddress shouldn't match with old one: %v != %v", o.l2.LocalAddress(), ip)
		}
	}
	o.t.Logf("LocalAddress as expected: %v", ip)
	o.rcvd <- tm_local
}

func (o *tunnelObserver) RemoteAddressesUpdated(ips []net.IP) {
	if !compareRemotes(o.remotes, ips) {
		o.t.Fatalf("New RemoteAddress doesn't match: %v != %v", o.remotes, ips)
	}
	if o.tu != nil {
		if compareRemotes(o.tu.RemoteAddresses(), ips) {
			o.t.Fatalf("New RemoteAddress shouldn't match with old one: %v != %v", o.tu.RemoteAddresses(), ips)
		}
	} else {
		if compareRemotes(o.l2.RemoteAddresses(), ips) {
			o.t.Fatalf("New RemoteAddress shouldn't match with old one: %v != %v", o.l2.RemoteAddresses(), ips)
		}
	}
	o.t.Logf("RemoteAddresses as expected: %v", ips)
	o.rcvd <- tm_remotes
}

func (o *tunnelObserver) SecurityUpdated(s Security) {
	if o.s != s {
		o.t.Fatalf("New Security doesn't match: %v != %v", o.s, s)
	}
	if s == o.tu.Security() {
		o.t.Fatalf("New Security shouldn't match with old one: %v != %v", o.tu.Security(), s)
	}
	o.t.Logf("Security as expected: %v", s)
	o.rcvd <- tm_s
}

func (o *tunnelObserver) L3TOSUpdated(tos int8) {
	if o.tos != int(tos) {
		o.t.Fatalf("New TOS doesn't match: %v != %v", o.tos, tos)
	}
	if tos == o.tu.TOS() {
		o.t.Fatalf("New TOS shouldn't match with old one: %v != %v", o.tu.TOS(), tos)
	}
	o.t.Logf("TOS as expected: %d", tos)
	o.rcvd <- tm_tos
}

func (o *tunnelObserver) L2TOSUpdated(tos uint8) {
	if o.tos != int(tos) {
		o.t.Fatalf("New TOS doesn't match: %v != %v", o.tos, tos)
	}
	if tos == o.l2.TOS() {
		o.t.Fatalf("New TOS shouldn't match with old one: %v != %v", o.l2.TOS(), tos)
	}
	o.t.Logf("TOS as expected: %d", tos)
	o.rcvd <- tm_tos
}

func (o *tunnelObserver) VRFUpdated(vrf *VRF) {
	if o.vrf != vrf {
		o.t.Fatalf("New VRF doesn't match: %v != %v", o.vrf, vrf)
	}
	if o.tu != nil {
		if vrf == o.tu.VRF() {
			o.t.Fatalf("New TOS shouldn't match with old one: %v != %v", o.tu.VRF(), vrf)
		}
	} else {
		if vrf == o.l2.VRF() {
			o.t.Fatalf("New TOS shouldn't match with old one: %v != %v", o.l2.VRF(), vrf)
		}
	}
	o.t.Logf("VRF as expected: %v", vrf)
	o.rcvd <- tm_vrf
}

func (o *tunnelObserver) VNIUpdated(vni uint32) {
	if o.vni != vni {
		o.t.Fatalf("New VNI doesn't match: %v != %v", o.vni, vni)
	}
	if o.l2.VNI() == vni {
		o.t.Fatalf("New VNI shouldn't match with old one: %v != %v", o.l2.VNI(), vni)
	}
	o.t.Logf("VNI as expected: %v", vni)
	o.rcvd <- tm_vni
}

func (o *tunnelObserver) wait(tm tunnelMember) bool {
	defer close(o.rcvd)
	select {
	case m := <-o.rcvd:
		if m == tm {
			o.t.Logf("Got expected update: %v", tm)
			return true
		}
		o.t.Fatalf("Didn't get expected update: expected %v, got %v", tm, m)
	case <-time.After(10 * time.Millisecond):
		o.t.Logf("Timed out")
	}
	return false
}

func (o *tunnelObserver) prepare() {
	o.rcvd = make(chan tunnelMember, 1)
}

func TestL3TunnelNew(t *testing.T) {
	t.Logf("Testing NewL3Tunnel()")
	tu, err := NewL3Tunnel(EncapsMethodDirect)

	if err != nil {
		t.Fatalf("NewL3Tunnel(EncapsMethodDirect) failed: %v", err)
	}

	const (
		defaultAT  = AF_IPv4
		defaultHL  = uint8(0)
		defaultTOS = int8(-1)
	)

	if v := tu.AddressType(); v != defaultAT {
		t.Errorf("Default AddressType not as expected: %v (should be %v)", v, defaultAT)
	}

	if v := tu.HopLimit(); v != defaultHL {
		t.Errorf("Default HopLimit not as expected: %v (should be %v)", v, defaultHL)
	}

	if v := tu.TOS(); v != defaultTOS {
		t.Errorf("Default TOS not as expected: %v (should be %v)", v, defaultHL)
	}

	t.Logf("All members are as expected")
}

func TestL3TunnelBasic(t *testing.T) {
	tu, err := NewL3Tunnel(EncapsMethodDirect)
	if err != nil {
		t.Fatalf("NewL3Tunnel(EncapsMethodDirect) failed: %v", err)
	}

	o := &tunnelObserver{t: t, tu: tu}
	tu.setNotify(o)

	t.Logf("Default L3Tunnel Setting:\n\t%v", tu)

	// AddressType
	o.prepare()
	o.af = tu.AddressType()
	tu.SetAddressType(tu.AddressType())
	if o.wait(tm_af) {
		t.Fatalf("UpdateAddressType shall not be called")
	}
	t.Logf("UpdateAddressType wasn't get called. ok")

	// Check EncapsMethod
	if tu.EncapsMethod() != EncapsMethodDirect {
		t.Fatalf("EncapsMethod doesn't match; expected %v, got %v",
			EncapsMethodDirect, tu.EncapsMethod())
	}
	t.Logf("EncapsMethod ok.")

	// HopLimit
	o.prepare()
	o.hop = tu.HopLimit()
	tu.SetHopLimit(tu.HopLimit())
	if o.wait(tm_hop) {
		t.Fatalf("UpdateHopLimit shall not be called")
	}
	t.Logf("UpdateHopLimit wasn't get called. ok")

	t.Logf("Setting to new HopLimit")
	hop := o.hop + 1
	o.hop = hop
	o.prepare()
	tu.SetHopLimit(hop)
	if !o.wait(tm_hop) {
		t.Fatalf("UpdateHopLimit shall be called")
	}
	if tu.HopLimit() != hop {
		t.Fatalf("EncapsMethod not as epxected: %v != %v", hop, tu.HopLimit())
	}
	t.Logf("HopLimit ok")

	// Local
	o.prepare()
	ip := net.ParseIP("1.1.1.1")
	o.local = ip
	tu.SetLocalAddress(ip)
	if !o.wait(tm_local) {
		t.Fatalf("UpdateLocalAddress shall be called")
	}
	t.Logf("UpdateLocalAddress was get called. ok")

	t.Logf("Setting to new local address")
	ip = net.ParseIP("2.2.2.2")
	o.local = ip
	o.prepare()
	tu.SetLocalAddress(ip)
	if !o.wait(tm_local) {
		t.Fatalf("UpdateLocalAddress shall be called")
	}
	if !ip.Equal(tu.LocalAddress()) {
		t.Fatalf("LocalAddress not as epxected: %v != %v", ip, tu.LocalAddress())
	}
	t.Logf("LocalAddress ok")

	// Remote
	o.prepare()
	ips := []net.IP{
		net.IPv4(1, 1, 1, 1),
		net.IPv4(2, 2, 2, 2),
	}
	o.remotes = ips
	tu.SetRemoteAddresses(ips)
	if !o.wait(tm_remotes) {
		t.Fatalf("UpdateRemoteAddresses shall be called")
	}
	t.Logf("UpdateRemoteAddresses was called. ok")

	t.Logf("Setting to new remote address")
	ips = []net.IP{
		net.IPv4(2, 2, 2, 2),
	}
	o.remotes = ips
	o.prepare()
	tu.SetRemoteAddresses(ips)
	if !o.wait(tm_remotes) {
		t.Fatalf("UpdateRemoteAddresses shall be called")
	}
	t.Logf("RemoteAddresses ok")

	// Security
	o.prepare()
	o.s = tu.Security()
	tu.SetSecurity(tu.Security())
	if o.wait(tm_s) {
		t.Fatalf("UpdateSecurity shall not be called")
	}
	t.Logf("UpdateSecurity wasn't get called. ok")

	// none -> ipsec
	t.Logf("Setting to SecurityNone")
	o.s = SecurityNone
	tu.SetSecurity(SecurityNone)
	o.prepare()
	t.Logf("Now Setting to SecurityIPSec")
	o.s = SecurityIPSec
	tu.SetSecurity(SecurityIPSec)
	if !o.wait(tm_s) {
		t.Fatalf("UpdateSecurity shall be called")
	}
	if tu.Security() != SecurityIPSec {
		t.Fatalf("Security not as epxected: %v != %v", SecurityIPSec, tu.Security())
	}
	t.Logf("Security ok")

	// TOS
	o.prepare()
	o.tos = int(tu.TOS())
	tu.SetTOS(tu.TOS())
	if o.wait(tm_tos) {
		t.Fatalf("UpdateTOS shall not be called")
	}
	t.Logf("UpdateTOS wasn't get called. ok")

	t.Logf("Setting to new TOS")
	o.tos = 0
	o.prepare()
	tu.SetTOS(int8(o.tos))
	if !o.wait(tm_tos) {
		t.Fatalf("UpdateTOS shall be called")
	}
	if tu.TOS() != int8(o.tos) {
		t.Fatalf("TOS not as epxected: %v != %v", o.tos, tu.TOS())
	}

	badTOSTest(t, o, -3)
	badTOSTest(t, o, 64)

	t.Logf("TOS ok")

	// VRF
	vrf, err := NewVRF("vrf1")
	if err != nil {
		t.Fatalf("NewVRF failed.")
	}
	o.prepare()
	o.vrf = vrf
	tu.SetVRF(vrf)
	if !o.wait(tm_vrf) {
		t.Fatalf("UpdateVRF shall be called")
	}
	t.Logf("UpdateVRF got called. ok")
	vrf.Free()

	t.Logf("VRF ok")
}

func badTOSTest(t *testing.T, o *tunnelObserver, tos int) {
	t.Logf("Setting TOS to %d", tos)
	o.tos = tos
	o.prepare()
	if o.tu != nil {
		if err := o.tu.SetTOS(int8(tos)); err == nil {
			t.Fatalf("SetTOS(%d) must fail", tos)
		}
	} else {
		if err := o.l2.SetTOS(uint8(tos)); err == nil {
			t.Fatalf("SetTOS(%d) must fail", tos)
		}
	}
	if o.wait(tm_tos) {
		t.Fatalf("SetTOS(%d) should not cause UpdateTOS to be called", tos)
	}
	t.Logf("SetTOS(%d) failed as expected", tos)
}

func TestL2TunnelBasic(t *testing.T) {
	if _, err := NewL2Tunnel(EncapsMethodDirect); err == nil {
		t.Fatalf("NewL2Tunnel(EncapsMethodDirect) succeeded; must fail.")
	} else {
		t.Logf("NewL2Tunnel(EncapsMethodDirect) failed ok; %v", err)
	}

	tu, err := NewL2Tunnel(EncapsMethodGRE)
	if err != nil {
		t.Logf("NewL2Tunnel(EncapsMethodGRE) failed: %v", err)
	}
	o := &tunnelObserver{t: t, l2: tu}
	tu.setNotify(o)

	t.Logf("Default L2Tunnel Setting:\n\t%v", tu)

	// AddressType
	o.prepare()
	o.af = tu.AddressType()
	tu.SetAddressType(tu.AddressType())
	if o.wait(tm_af) {
		t.Fatalf("UpdateAddressType shall not be called")
	}
	t.Logf("UpdateAddressType wasn't get called. ok")

	// Check EncapsMethod
	if tu.EncapsMethod() != EncapsMethodGRE {
		t.Fatalf("EncapsMethod doesn't match; expected %v, got %v",
			EncapsMethodGRE, tu.EncapsMethod())
	}
	t.Logf("EncapsMethod ok.")

	// HopLimit
	o.prepare()
	o.hop = tu.HopLimit()
	tu.SetHopLimit(tu.HopLimit())
	if o.wait(tm_hop) {
		t.Fatalf("UpdateHopLimit shall not be called")
	}
	t.Logf("UpdateHopLimit wasn't get called. ok")

	t.Logf("Setting to new HopLimit")
	hop := o.hop + 1
	o.hop = hop
	o.prepare()
	tu.SetHopLimit(hop)
	if !o.wait(tm_hop) {
		t.Fatalf("UpdateHopLimit shall be called")
	}
	if tu.HopLimit() != hop {
		t.Fatalf("EncapsMethod not as epxected: %v != %v", hop, tu.HopLimit())
	}
	t.Logf("HopLimit ok")

	// Local
	o.prepare()
	ip := net.ParseIP("1.1.1.1")
	o.local = ip
	tu.SetLocalAddress(ip)
	if !o.wait(tm_local) {
		t.Fatalf("UpdateLocalAddress shall be called")
	}
	t.Logf("UpdateLocalAddress was get called. ok")

	t.Logf("Setting to new local address")
	ip = net.ParseIP("2.2.2.2")
	o.local = ip
	o.prepare()
	tu.SetLocalAddress(ip)
	if !o.wait(tm_local) {
		t.Fatalf("UpdateLocalAddress shall be called")
	}
	if !ip.Equal(tu.LocalAddress()) {
		t.Fatalf("LocalAddress not as epxected: %v != %v", ip, tu.LocalAddress())
	}
	t.Logf("LocalAddress ok")

	// Remotes
	o.prepare()
	ips := []net.IP{
		net.IPv4(1, 1, 1, 1),
		net.IPv4(2, 2, 2, 2),
		net.IPv4(3, 3, 3, 3),
	}
	o.remotes = ips
	t.Logf("Setting to new remote addresses: %v", ips)
	tu.SetRemoteAddresses(ips)
	if !o.wait(tm_remotes) {
		t.Fatalf("UpdateRemoteAddresses shall be called")
	}
	t.Logf("UpdateRemoteAddresses was called. ok")

	ips = []net.IP{
		net.IPv4(2, 2, 2, 2),
		net.IPv4(3, 3, 3, 3),
		net.IPv4(1, 1, 1, 1),
	}
	t.Logf("Setting to same remote addresses in different orders: %v", ips)
	o.remotes = ips
	o.prepare()
	tu.SetRemoteAddresses(ips)
	if o.wait(tm_remotes) {
		t.Fatalf("UpdateRemoteAddress shall not be called")
	}
	t.Logf("UpdateRemoteAddresses wasn't called. ok")

	ips = []net.IP{
		net.IPv4(1, 1, 1, 1),
		net.IPv4(2, 2, 2, 2),
	}
	t.Logf("Setting to different remote addresses: %v", ips)
	o.remotes = ips
	o.prepare()
	tu.SetRemoteAddresses(ips)
	if !o.wait(tm_remotes) {
		t.Fatalf("UpdateRemoteAddress shall be called")
	}
	t.Logf("UpdateRemoteAddresses was called. ok")

	ips = []net.IP{
		net.IPv4(3, 3, 3, 3),
		net.IPv4(1, 1, 1, 1),
	}
	t.Logf("Setting to different remote addresses: %v", ips)
	o.remotes = ips
	o.prepare()
	tu.SetRemoteAddresses(ips)
	if !o.wait(tm_remotes) {
		t.Fatalf("UpdateRemoteAddress shall be called")
	}
	t.Logf("UpdateRemoteAddresses was called. ok")

	t.Logf("RemoteAddress ok")

	// TOS
	o.prepare()
	o.tos = int(tu.TOS())
	tu.SetTOS(tu.TOS())
	if o.wait(tm_tos) {
		t.Fatalf("UpdateTOS shall not be called")
	}
	t.Logf("UpdateTOS wasn't get called. ok")

	t.Logf("Setting to new TOS")
	o.tos = 10
	o.prepare()
	tu.SetTOS(uint8(o.tos))
	if !o.wait(tm_tos) {
		t.Fatalf("UpdateTOS shall be called")
	}
	if tu.TOS() != uint8(o.tos) {
		t.Fatalf("TOS not as epxected: %v != %v", o.tos, tu.TOS())
	}

	badTOSTest(t, o, 64)

	t.Logf("TOS ok")

	// VRF
	vrf, err := NewVRF("vrf1")
	if err != nil {
		t.Fatalf("NewVRF failed.")
	}
	o.prepare()
	o.vrf = vrf
	tu.SetVRF(vrf)
	if !o.wait(tm_vrf) {
		t.Fatalf("UpdateVRF shall be called")
	}
	t.Logf("UpdateVRF got called. ok")
	vrf.Free()

	t.Logf("VRF ok")

	// VNI
	o.prepare()
	o.vni = tu.VNI()
	t.Logf("Setting VNI with the current VNI value: %v", o.vni)
	tu.SetVNI(o.vni)
	if o.wait(tm_vni) {
		t.Fatalf("VNIUpdated shall not be called")
	}
	t.Logf("VNIUpdated didn't get called. ok")

	o.prepare()
	o.vni += 0x1234
	t.Logf("Calling SetVNI with different value: %v", o.vni)
	tu.SetVNI(o.vni)
	if !o.wait(tm_vni) {
		t.Fatalf("VNIUpdated shall be called")
	}
	t.Logf("VNIUpdated got called. ok")

	t.Logf("VNI ok")
}

func TestL2TunnelVxLAN(t *testing.T) {
	tu, err := NewL2Tunnel(EncapsMethodGRE)
	if err != nil {
		t.Logf("NewL2Tunnel(EncapsMethodGRE) failed: %v", err)
	}

	// Shall fail to set VxLAN Port
	if err := tu.SetVxLANPort(1234); err == nil {
		t.Errorf("SetVxLANPort succeeded. Setting VxLAN port on EncapsMethodGRE shall fail.")
	} else {
		t.Logf("SetVxLANPort failed. ok: %v", err)
	}

	tu, err = NewL2Tunnel(EncapsMethodVxLAN)
	if err != nil {
		t.Logf("NewL2Tunnel(EncapsMethodVxLAN) failed: %v", err)
	}

	// Shall succeed to set VxLAN Port
	p := uint16(1234)
	if err := tu.SetVxLANPort(p); err != nil {
		t.Errorf("SetVxLANPort failed: %v", err)
	}
	t.Logf("SetVxLANPort(%d) succeeded.", p)

	if port := tu.VxLANPort(); port != p {
		t.Errorf("VxLANPort doesn't match to the expected value: expected: %d, got: %v", p, port)
	} else {
		t.Logf("VxLANPort returned %d. ok", port)
	}

	t.Logf("Testing VxLANPort succeeded.")
}
