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

package vswitch

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
)

type TunnelNotify interface {
	AddressTypeUpdated(AddressFamily)
	HopLimitUpdated(uint8)
	LocalAddressUpdated(net.IP)
	RemoteAddressesUpdated([]net.IP)
	VRFUpdated(*VRF)
}

// L3TunnelNotify shall be implemented if the entity wants to receive
// notification upon changes in the L3 tunnel settings.
// Methods are called with the new value.
// Old values are still visible via gtter when these methods are called.
type L3TunnelNotify interface {
	TunnelNotify
	SecurityUpdated(Security)
	L3TOSUpdated(int8)
}

// L2TunnelNotify shall be implemented if the entity wants to receive
// notification upon changes in the L2 tunnel settings.
// Methods are called with the new value.
// Old values are still visible via gtter when these methods are called.
type L2TunnelNotify interface {
	TunnelNotify
	VNIUpdated(uint32)
	L2TOSUpdated(uint8)
}

type tunnel struct {
	encapsMethod EncapsMethod
	hopLimit     uint8
	local        net.IP
	remotes      []net.IP
	addressType  AddressFamily
	vrf          *VRF
	notify       TunnelNotify
}

type L3Tunnel struct {
	*tunnel
	security Security
	tos      int8
	l3notify L3TunnelNotify
}

type L2Tunnel struct {
	*tunnel
	vni       uint32
	vxlanPort uint16 // UDP Port used for VxLAN
	tos       uint8
	l2notify  L2TunnelNotify
}

type EncapsMethod int

const (
	EncapsMethodDirect EncapsMethod = iota
	EncapsMethodGRE
	EncapsMethodVxLAN
)

func (e EncapsMethod) String() string {
	s := map[EncapsMethod]string{
		EncapsMethodDirect: "direct",
		EncapsMethodGRE:    "gre",
		EncapsMethodVxLAN:  "vxlan",
	}
	return s[e]
}

func (e EncapsMethod) MarshalJSON() ([]byte, error) {
	return []byte(`"` + e.String() + `"`), nil
}

type Security int

const (
	SecurityNone Security = iota
	SecurityIPSec
)

func (e Security) String() string {
	s := map[Security]string{
		SecurityNone:  "none",
		SecurityIPSec: "ipsec",
	}
	return s[e]
}

func (e Security) MarshalJSON() ([]byte, error) {
	if e == SecurityNone {
		return []byte(`"none"`), nil
	}
	return []byte(`"ipsec"`), nil
}

func newTunnel(em EncapsMethod) *tunnel {
	return &tunnel{
		hopLimit:     0,
		addressType:  AF_IPv4,
		encapsMethod: em,
	}
}

func (t *tunnel) AddressType() AddressFamily {
	return t.addressType
}

func (t *tunnel) SetAddressType(af AddressFamily) {
	if t.addressType != af {
		if t.notify != nil {
			t.notify.AddressTypeUpdated(af)
		}
		t.addressType = af
	}
}

func (t *tunnel) EncapsMethod() EncapsMethod {
	return t.encapsMethod
}

func (t *tunnel) HopLimit() uint8 {
	return t.hopLimit
}

func (t *tunnel) SetHopLimit(h uint8) {
	if t.hopLimit != h {
		if t.notify != nil {
			t.notify.HopLimitUpdated(h)
		}
		t.hopLimit = h
	}
}

func (t *tunnel) LocalAddress() net.IP {
	return t.local
}

func (t *tunnel) SetLocalAddress(ip net.IP) {
	if !t.local.Equal(ip) {
		if t.notify != nil {
			t.notify.LocalAddressUpdated(ip)
		}
		t.local = ip
	}
}

func (t *tunnel) RemoteAddresses() []net.IP {
	return t.remotes
}

func compareRemotes(old, new []net.IP) bool {
	if len(old) != len(new) {
		return false
	}

	for _, ip1 := range new {
		matched := false
		for _, ip2 := range old {
			if ip1.Equal(ip2) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (t *tunnel) SetRemoteAddresses(ips []net.IP) {
	if !compareRemotes(t.remotes, ips) {
		if t.notify != nil {
			t.notify.RemoteAddressesUpdated(ips)
		}
		t.remotes = ips
	}
}

func (t *tunnel) VRF() *VRF {
	return t.vrf
}

func (t *tunnel) SetVRF(vrf *VRF) {
	if t.vrf != vrf {
		if t.notify != nil {
			t.notify.VRFUpdated(vrf)
		}
		t.vrf = vrf
	}
}

func (t *tunnel) String() string {
	return fmt.Sprintf("AddressType=%v EncapsMethod=%v HopLimit=%d LocalAddress=%v RemoteAddress=%v",
		t.addressType, t.encapsMethod, t.hopLimit, t.local, t.remotes)
}

func (t *tunnel) mapJSON() map[string]interface{} {
	m := map[string]interface{}{
		"encaps-method":  t.encapsMethod,
		"hop-limit":      t.hopLimit,
		"local-address":  t.local,
		"remote-address": t.remotes,
		"address-type":   t.addressType,
	}
	if t.vrf != nil {
		m["vrf"] = t.vrf
	}
	return m
}

// NewL3Tunnel creates new L3Tunnel param with default setting.
// L3Tunnel is epected to be instantiated with NewL3Tunnel.
//
// Encaps is an encapsulation method. Only EcanpsMethodGRE, or
// EncapsMethodDirect are permitted.
//
// Returns nil on the error.
func NewL3Tunnel(encaps EncapsMethod) (*L3Tunnel, error) {
	if encaps != EncapsMethodGRE && encaps != EncapsMethodDirect {
		return nil, fmt.Errorf("Invalid encaps method: %v", encaps)
	}

	return &L3Tunnel{
		tunnel: newTunnel(encaps),
		tos:    -1,
	}, nil
}

func (t *L3Tunnel) setNotify(n L3TunnelNotify) {
	t.l3notify = n
	t.tunnel.notify = n.(TunnelNotify)
}

func (t *L3Tunnel) Security() Security {
	return t.security
}

func (t *L3Tunnel) SetSecurity(s Security) {
	if t.security != s {
		if t.l3notify != nil {
			t.l3notify.SecurityUpdated(s)
		}
		t.security = s
	}
}

// IPProto returns supported IPProto value with the given configuration.
func (t *L3Tunnel) IPProto() IPProto {
	if t.encapsMethod == EncapsMethodGRE {
		return IPP_GRE
	}
	if t.security == SecurityIPSec {
		return IPP_ESP
	}
	return IPP_IPIP
}

func (t *L3Tunnel) TOS() int8 {
	return t.tos
}

func (t *L3Tunnel) SetTOS(tos int8) error {
	if tos < -2 || tos > 63 {
		return errors.New("TOS is out of bound (Must be -2..63)")
	}
	if t.tos != tos {
		if t.notify != nil {
			t.l3notify.L3TOSUpdated(tos)
		}
		t.tos = tos
	}
	return nil
}

func (t *L3Tunnel) String() string {
	return fmt.Sprintf("%v Security=%v TOS=%d", t.tunnel, t.security, t.tos)
}

func (t *L3Tunnel) MarshalJSON() ([]byte, error) {
	m := t.mapJSON()
	m["security"] = t.security
	m["tos"] = t.tos
	return json.Marshal(m)
}

// NewL2Tunnel creates new L3Tunnel param with default setting.
// L2Tunnel should be instantiated with NewL2Tunnel.
//
// Encaps is an encapsulation method. Only EcanpsMethodGRE, or
// EncapsMethodVxLAN are permitted.
//
// Returns nil on the error.
func NewL2Tunnel(encaps EncapsMethod) (*L2Tunnel, error) {
	if encaps != EncapsMethodGRE && encaps != EncapsMethodVxLAN {
		return nil, fmt.Errorf("Invalid encaps method: %v", encaps)
	}

	return &L2Tunnel{
		tunnel:    newTunnel(encaps),
		vxlanPort: DefaultVxLANPort,
	}, nil
}

func (t *L2Tunnel) setNotify(n L2TunnelNotify) {
	t.l2notify = n
	t.tunnel.notify = n.(TunnelNotify)
}

func (t *L2Tunnel) VNI() uint32 {
	return t.vni
}

func (t *L2Tunnel) SetVNI(vni uint32) error {
	if vni > 16777215 {
		return errors.New("VNI is out of bound (Must be 0..16777215)")
	}
	if t.vni != vni {
		if t.l2notify != nil {
			t.l2notify.VNIUpdated(vni)
		}
		t.vni = vni
	}
	return nil
}

func (t *L2Tunnel) TOS() uint8 {
	return t.tos
}

func (t *L2Tunnel) SetTOS(tos uint8) error {
	if tos > 63 {
		return errors.New("TOS is out of bound (Must be 0..63)")
	}
	if t.tos != tos {
		if t.notify != nil {
			t.l2notify.L2TOSUpdated(tos)
		}
		t.tos = tos
	}
	return nil
}

func (t *L2Tunnel) VxLANPort() uint16 {
	return t.vxlanPort
}

func (t *L2Tunnel) SetVxLANPort(port uint16) error {
	if t.encapsMethod != EncapsMethodVxLAN {
		return errors.New("The encapsulation method is not VxLAN.")
	}
	t.vxlanPort = port
	return nil
}

func (t *L2Tunnel) String() string {
	return fmt.Sprintf("%v VNI=%d TOS=%d", t.tunnel, t.vni, t.tos)
}

func (t *L2Tunnel) MarshalJSON() ([]byte, error) {
	m := t.mapJSON()
	m["vni"] = t.vni
	m["tos"] = t.tos
	m["vxlanPort"] = t.vxlanPort
	return json.Marshal(m)
}
