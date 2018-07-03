//
// Copyright 2018 Nippon Telegraph and Telephone Corporation.
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
	tm_s
	tm_tos
)

func (tm tunnelMember) String() string {
	s := map[tunnelMember]string{
		tm_af:     "AddressType",
		tm_em:     "EncapsMethod",
		tm_hop:    "HopLimit",
		tm_local:  "LocalAddress",
		tm_remote: "RemoteAddress",
		tm_s:      "Security",
		tm_tos:    "TOS",
	}
	return s[tm]
}

type tunnelObserver struct {
	t      *testing.T
	tu     *Tunnel
	af     AddressFamily
	em     EncapsMethod
	hop    uint8
	local  net.IP
	remote net.IP
	s      Security
	tos    int8
	rcvd   chan tunnelMember
}

func (o *tunnelObserver) AddressTypeUpdated(af AddressFamily) {
	if o.af != af {
		o.t.Fatalf("New Addresss Family doesn't match: %v != %v", o.af, af)
	}
	if af == o.tu.AddressType() {
		o.t.Fatalf("New Addresss Family shouldn't match with old one: %v != %v", o.tu.AddressType(), af)
	}
	o.t.Logf("AddressType as expected: %v", af)
	o.rcvd <- tm_af
}

func (o *tunnelObserver) EncapsMethodUpdated(em EncapsMethod) {
	if o.em != em {
		o.t.Fatalf("New EncapsMethod doesn't match: %v != %v", o.em, em)
	}
	if em == o.tu.EncapsMethod() {
		o.t.Fatalf("New EncapsMethod shouldn't match with old one: %v != %v", o.tu.EncapsMethod(), em)
	}
	o.t.Logf("EncapsMethod as expected: %v", em)
	o.rcvd <- tm_em
}

func (o *tunnelObserver) HopLimitUpdated(hop uint8) {
	if o.hop != hop {
		o.t.Fatalf("New HopLimit doesn't match: %v != %v", o.hop, hop)
	}
	if hop == o.tu.HopLimit() {
		o.t.Fatalf("New HopLimit shouldn't match with old one: %v != %v", o.tu.HopLimit(), hop)
	}
	o.t.Logf("HopLimit as expected: %v", hop)
	o.rcvd <- tm_hop
}

func (o *tunnelObserver) LocalAddressUpdated(ip net.IP) {
	if !o.local.Equal(ip) {
		o.t.Fatalf("New LocalAddress doesn't match: %v != %v", o.local, ip)
	}
	if ip.Equal(o.tu.LocalAddress()) {
		o.t.Fatalf("New LocalAddress shouldn't match with old one: %v != %v", o.tu.LocalAddress(), ip)
	}
	o.t.Logf("LocalAddress as expected: %v", ip)
	o.rcvd <- tm_local
}

func (o *tunnelObserver) RemoteAddressUpdated(ip net.IP) {
	if !o.remote.Equal(ip) {
		o.t.Fatalf("New RemoteAddress doesn't match: %v != %v", o.remote, ip)
	}
	if ip.Equal(o.tu.RemoteAddress()) {
		o.t.Fatalf("New RemoteAddress shouldn't match with old one: %v != %v", o.tu.RemoteAddress(), ip)
	}
	o.t.Logf("RemoteAddress as expected: %v", ip)
	o.rcvd <- tm_remote
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

func (o *tunnelObserver) TOSUpdated(tos int8) {
	if o.tos != tos {
		o.t.Fatalf("New TOS doesn't match: %v != %v", o.tos, tos)
	}
	if tos == o.tu.TOS() {
		o.t.Fatalf("New TOS shouldn't match with old one: %v != %v", o.tu.TOS(), tos)
	}
	o.t.Logf("TOS as expected: %d", tos)
	o.rcvd <- tm_tos
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

func TestTunnelNew(t *testing.T) {
	t.Logf("Testing NewTunnel()")
	tu := NewTunnel()

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

func TestTunnelBasic(t *testing.T) {
	tu := NewTunnel()
	o := &tunnelObserver{t: t, tu: tu}
	tu.setNotify(o)

	t.Logf("Default Tunnel Setting:\n\t%v", tu)

	// AddressType
	o.prepare()
	o.af = tu.AddressType()
	tu.SetAddressType(tu.AddressType())
	if o.wait(tm_af) {
		t.Fatalf("UpdateAddressType shall not be called")
	}
	t.Logf("UpdateAddressType wasn't get called. ok")

	// EncapsMethod
	o.prepare()
	o.em = tu.EncapsMethod()
	tu.SetEncapsMethod(tu.EncapsMethod())
	if o.wait(tm_em) {
		t.Fatalf("UpdateEncapsMethod shall not be called")
	}
	t.Logf("UpdateEncapsMethod wasn't get called. ok")

	// Direct -> GRE
	t.Logf("Setting to EncapsMethodDirect")
	o.em = EncapsMethodDirect
	tu.SetEncapsMethod(EncapsMethodDirect)
	o.prepare()
	t.Logf("Now Setting to EncapsMethodGRE")
	o.em = EncapsMethodGRE
	tu.SetEncapsMethod(EncapsMethodGRE)
	if !o.wait(tm_em) {
		t.Fatalf("UpdateEncapsMethod shall be called")
	}
	if tu.EncapsMethod() != EncapsMethodGRE {
		t.Fatalf("EncapsMethod not as epxected: %v != %v", EncapsMethodGRE, tu.EncapsMethod())
	}
	t.Logf("EncapsMethod ok")

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
	ip = net.ParseIP("1.1.1.1")
	o.remote = ip
	tu.SetRemoteAddress(ip)
	if !o.wait(tm_remote) {
		t.Fatalf("UpdateRemoteAddress shall be called")
	}
	t.Logf("UpdateRemoteAddress was get called. ok")

	t.Logf("Setting to new remote address")
	ip = net.ParseIP("2.2.2.2")
	o.remote = ip
	o.prepare()
	tu.SetRemoteAddress(ip)
	if !o.wait(tm_remote) {
		t.Fatalf("UpdateRemoteAddress shall be called")
	}
	if !ip.Equal(tu.RemoteAddress()) {
		t.Fatalf("RemoteAddress not as epxected: %v != %v", ip, tu.RemoteAddress())
	}
	t.Logf("RemoteAddress ok")

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
	o.tos = tu.TOS()
	tu.SetTOS(tu.TOS())
	if o.wait(tm_tos) {
		t.Fatalf("UpdateTOS shall not be called")
	}
	t.Logf("UpdateTOS wasn't get called. ok")

	t.Logf("Setting to new TOS")
	o.tos = 0
	o.prepare()
	tu.SetTOS(0)
	if !o.wait(tm_tos) {
		t.Fatalf("UpdateTOS shall be called")
	}
	if tu.TOS() != 0 {
		t.Fatalf("TOS not as epxected: %v != %v", 0, tu.TOS())
	}

	badTOSTest(t, o, -3)
	badTOSTest(t, o, 64)

	t.Logf("TOS ok")
}

func badTOSTest(t *testing.T, o *tunnelObserver, tos int8) {
	t.Logf("Setting TOS to %d", tos)
	o.tos = tos
	o.prepare()
	if err := o.tu.SetTOS(tos); err == nil {
		t.Fatalf("SetTOS(%d) must fail", tos)
	}
	if o.wait(tm_tos) {
		t.Fatalf("SetTOS(%d) should not cause UpdateTOS to be called", tos)
	}
	t.Logf("SetTOS(%d) failed as expected", tos)
}
