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

/*
#cgo CFLAGS: -I ${SRCDIR}/.. -I${SRCDIR}/../../include -I/usr/local/include/dpdk -m64 -pthread -O3 -msse4.2
#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all -L/usr/local/lib -ldpdk

#include "tunnel.h"
*/
import "C"

import (
	"github.com/lagopus/vsw/vswitch"
)

const (
	// ModuleName Name of Tunnel module.
	ModuleName = C.TUNNEL_MODULE_NAME
	// MaxPktBurst Maximum packet burst size.
	MaxPktBurst = C.MAX_PKT_BURST

	defaultInboundCore  = 2
	defaultOutboundCore = 3
)

// ProtocolType ProtocolType is the type of the tunnel protocol.
type ProtocolType uint8

const (
	// Unknown Unknown.
	Unknown ProtocolType = iota
	// IPsec IPsec.
	IPsec
	// IPIP IPIP.
	IPIP
	// GRE GRE.
	GRE
	// VXLAN VXLAN.
	VXLAN
)

// String Protocol type.
func (p ProtocolType) String() string {
	str := ""
	switch p {
	case Unknown:
		str = "unknown"
	case IPsec:
		str = "ipsec"
	case IPIP:
		str = "ipip"
	case GRE:
		str = "gre"
	case VXLAN:
		str = "vxlan"
	}
	return str
}

// ConcreteIFFactory ConcreteIF factory.
type ConcreteIFFactory func(*vswitch.BaseInstance,
	interface{}, *ModuleConfig) (ConcreteIF, error)

type interfaceState uint8

const (
	initialized interfaceState = iota
	enabled
	disabled
	freed
)
