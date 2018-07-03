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
	"errors"
	"fmt"
	"net"
)

// TunnelNotify shall be implemented if the entity wants to receive
// notification upon changes in the tunnel settings.
// Methods are called with the new value.
// Old values are still visible via gtter when these methods are called.
type TunnelNotify interface {
	AddressTypeUpdated(AddressFamily)
	EncapsMethodUpdated(EncapsMethod)
	HopLimitUpdated(uint8)
	LocalAddressUpdated(net.IP)
	RemoteAddressUpdated(net.IP)
	SecurityUpdated(Security)
	TOSUpdated(int8)
}

type Tunnel struct {
	encapsMethod EncapsMethod
	hopLimit     uint8
	local        net.IP
	remote       net.IP
	security     Security
	tos          int8
	addressType  AddressFamily
	notify       TunnelNotify
}

type EncapsMethod int

const (
	EncapsMethodDirect EncapsMethod = iota
	EncapsMethodGRE
)

func (e EncapsMethod) String() string {
	s := map[EncapsMethod]string{
		EncapsMethodDirect: "direct",
		EncapsMethodGRE:    "gre",
	}
	return s[e]
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

// NewTunnel creates new Tunnel param with default setting.
// Tunnel is epected to be instantiated with NewTunnel.
func NewTunnel() *Tunnel {
	return &Tunnel{
		hopLimit:    0,
		tos:         -1,
		addressType: AF_IPv4,
	}
}

func (t *Tunnel) setNotify(n TunnelNotify) {
	t.notify = n
}

func (t *Tunnel) AddressType() AddressFamily {
	return t.addressType
}

func (t *Tunnel) SetAddressType(af AddressFamily) {
	if t.addressType != af {
		if t.notify != nil {
			t.notify.AddressTypeUpdated(af)
		}
		t.addressType = af
	}
}

func (t *Tunnel) EncapsMethod() EncapsMethod {
	return t.encapsMethod
}

func (t *Tunnel) SetEncapsMethod(em EncapsMethod) {
	if t.encapsMethod != em {
		if t.notify != nil {
			t.notify.EncapsMethodUpdated(em)
		}
		t.encapsMethod = em
	}
}

func (t *Tunnel) HopLimit() uint8 {
	return t.hopLimit
}

func (t *Tunnel) SetHopLimit(h uint8) {
	if t.hopLimit != h {
		if t.notify != nil {
			t.notify.HopLimitUpdated(h)
		}
		t.hopLimit = h
	}
}

func (t *Tunnel) LocalAddress() net.IP {
	return t.local
}

func (t *Tunnel) SetLocalAddress(ip net.IP) {
	if !t.local.Equal(ip) {
		if t.notify != nil {
			t.notify.LocalAddressUpdated(ip)
		}
		t.local = ip
	}
}

func (t *Tunnel) RemoteAddress() net.IP {
	return t.remote
}

func (t *Tunnel) SetRemoteAddress(ip net.IP) {
	if !t.remote.Equal(ip) {
		if t.notify != nil {
			t.notify.RemoteAddressUpdated(ip)
		}
		t.remote = ip
	}
}

func (t *Tunnel) Security() Security {
	return t.security
}

func (t *Tunnel) SetSecurity(s Security) {
	if t.security != s {
		if t.notify != nil {
			t.notify.SecurityUpdated(s)
		}
		t.security = s
	}
}

func (t *Tunnel) TOS() int8 {
	return t.tos
}

func (t *Tunnel) SetTOS(tos int8) error {
	if tos < -2 || tos > 63 {
		return errors.New("TOS is out of bound (Must be -2..63)")
	}
	if t.tos != tos {
		if t.notify != nil {
			t.notify.TOSUpdated(tos)
		}
		t.tos = tos
	}
	return nil
}

// IPProto returns supported IPProto value with the given configuration.
func (t *Tunnel) IPProto() IPProto {
	if t.encapsMethod == EncapsMethodGRE {
		return IPP_GRE
	}
	if t.security == SecurityIPSec {
		return IPP_ESP
	}
	return IPP_IPIP
}

func (t *Tunnel) String() string {
	return fmt.Sprintf("AddressType=%v EncapsMethod=%v HopLimit=%d LocalAddress=%v RemoteAddress=%v Security=%v TOS=%d",
		t.addressType, t.encapsMethod, t.hopLimit, t.local, t.remote, t.security, t.tos)
}
