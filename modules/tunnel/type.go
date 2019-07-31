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

/*
#include "tunnel.h"
*/
import "C"

import (
	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/vswitch"
)

const (
	moduleName              = C.TUNNEL_MODULE_NAME
	maxPktBurst             = C.MAX_PKT_BURST
	maxTunnels              = C.MAX_TUNNELS
	maxMmbufs               = C.MAX_PKT_BURST
	defaultCoreBind         = true
	defaultInboundCore      = 2
	defaultOutboundCore     = 3
	defaultInboundCoreMask  = 0x0
	defaultOutboundCoreMask = 0x0
	defaultHopLimit         = C.DEFAULT_TTL
	defaultTos              = C.DEFAULT_TOS
	defaultRuleFile         = ""
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
	// L2GRE L2GRE.
	L2GRE
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
	case L2GRE:
		str = "l2gre"
	case VXLAN:
		str = "vxlan"
	}
	return str
}

type concreteIFFactory func(accessor ifParamAccessor) (concreteIF, error)

type interfaceState uint8

const (
	initialized interfaceState = iota
	enabled
	disabled
	freed
)

type moduleData struct {
	protocol    ProtocolType
	factory     concreteIFFactory
	inboundOps  vswitch.LagopusRuntimeOps
	outboundOps vswitch.LagopusRuntimeOps
}

type ifParamAccessor interface {
	protocol() ProtocolType
	name() string
	outbound() *dpdk.Ring
	inbound() *dpdk.Ring
	rules() *vswitch.Rules
	interfaceMode() vswitch.VLANMode
	moduleConfig() *ModuleConfig
	l2tunnelConfig() *vswitch.L2Tunnel
	counter() *vswitch.Counter
}

type ifParam struct {
	proto        ProtocolType
	base         *vswitch.BaseInstance
	priv         interface{}
	mode         vswitch.VLANMode
	moduleConf   *ModuleConfig
	l2tunnelConf *vswitch.L2Tunnel
}

func newIfParam(protocol ProtocolType, iface *tunnelIF) *ifParam {
	var l2tunnelConf *vswitch.L2Tunnel
	switch protocol {
	case L2GRE, VXLAN:
		l2tunnelConf, _ = iface.priv.(*vswitch.L2Tunnel)
	default:
		l2tunnelConf = nil
	}

	return &ifParam{
		proto:        protocol,
		base:         iface.base,
		priv:         iface.priv,
		mode:         iface.mode,
		moduleConf:   iface.moduleConf,
		l2tunnelConf: l2tunnelConf,
	}
}

func (i *ifParam) protocol() ProtocolType {
	return i.proto
}

func (i *ifParam) name() string {
	return i.base.Name()
}

func (i *ifParam) outbound() *dpdk.Ring {
	return i.base.Input()
}

func (i *ifParam) inbound() *dpdk.Ring {
	return i.base.SecondaryInput()
}

func (i *ifParam) rules() *vswitch.Rules {
	return i.base.Rules()
}

func (i *ifParam) interfaceMode() vswitch.VLANMode {
	return i.mode
}

func (i *ifParam) moduleConfig() *ModuleConfig {
	return i.moduleConf
}

func (i *ifParam) l2tunnelConfig() *vswitch.L2Tunnel {
	return i.l2tunnelConf
}

func (i *ifParam) counter() *vswitch.Counter {
	return i.base.Counter()
}
