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

package ipsec

// #include "sp6.h"
import "C"
import (
	"fmt"
	"net"
	"unsafe"

	"github.com/lagopus/vsw/vswitch"
)

// C plane APIs for IPv6.

// CSPD6 CSPD for IPv6.
type CSPD6 struct {
	baseCSPD
	dbs map[DirectionType]*C.struct_spd6
}

// NewCSPD6 New SPD for IPv6.
func NewCSPD6() *CSPD6 {
	return &CSPD6{
		baseCSPD: baseCSPD{},
		dbs: map[DirectionType]*C.struct_spd6{
			DirectionTypeIn:  nil,
			DirectionTypeOut: nil,
		},
	}
}

// converter.

func (cs *CSPD6) cspdTocStruct(spd CSPD) *C.struct_spd6 {
	if v, ok := spd.(*C.struct_spd6); ok {
		return (*C.struct_spd6)((unsafe.Pointer(v)))
	}
	return nil
}

func (cs *CSPD6) cACLRulesTocStruct(rules CACLRules) *C.struct_acl6_rules {
	if v, ok := rules.(*C.struct_acl6_rules); ok {
		return (*C.struct_acl6_rules)((unsafe.Pointer(v)))
	}
	return nil
}

func (cs *CSPD6) cACLParamsTocStruct(params CACLParams) *C.struct_acl6_params {
	if v, ok := params.(*C.struct_acl6_params); ok {
		return (*C.struct_acl6_params)((unsafe.Pointer(v)))
	}
	return nil
}

// interface funcs.

// AllocRules Alloc rules.
func (cs *CSPD6) AllocRules(size uint32) CACLRules {
	return C.sp6_alloc_rules(C.size_t(size))
}

// FreeRules Free rules.
func (cs *CSPD6) FreeRules(rules CACLRules) {
	C.sp6_free_rules(cs.cACLRulesTocStruct(rules))
}

// Make Make ACL.
func (cs *CSPD6) Make(spd CSPD, inRules CACLRules, inRulesSize uint32,
	outRules CACLRules, outRulesSize uint32) error {
	s := cs.cspdTocStruct(spd)
	ir := cs.cACLRulesTocStruct(inRules)
	or := cs.cACLRulesTocStruct(outRules)

	if r := LagopusResult(C.sp6_make_spd(s, ir, C.uint32_t(inRulesSize),
		or, C.uint32_t(outRulesSize))); r != LagopusResultOK {
		return fmt.Errorf("Fail sp6_make_spd, %v", r)
	}
	return nil
}

// Stats Get stats.
func (cs *CSPD6) Stats(spd CSPD, spi uint32) (*CSPDStats, error) {
	s := cs.cspdTocStruct(spd)
	st := C.struct_spd_stats{}
	if r := LagopusResult(C.sp6_get_stats(s, &st, C.uint32_t(spi))); r != LagopusResultOK {
		return nil, fmt.Errorf("Fail sp6_get_stats(), %v", r)
	}
	stats := CSPDStats(st)
	return &stats, nil
}

// SetRule Set rule.
func (cs *CSPD6) SetRule(index uint32, rules CACLRules,
	params CACLParams) error {
	r := cs.cACLRulesTocStruct(rules)
	p := cs.cACLParamsTocStruct(params)

	if r := LagopusResult(C.sp6_set_rule(C.size_t(index), r, p)); r != LagopusResultOK {
		return fmt.Errorf("Fail sp6_set_rule, %v", r)
	}
	return nil
}

// DumpRules Dump rules.
func (cs *CSPD6) DumpRules(rules CACLRules, size uint32) {
	C.sp6_dump_rules(cs.cACLRulesTocStruct(rules), C.int32_t(size))
}

// NewParams New ACL params
func (cs *CSPD6) NewParams(args *CACLParamsArgs) CACLParams {
	params := &C.struct_acl6_params{}

	// policy
	params.policy = C.uint16_t(args.Policy)

	// priority
	params.priority = C.int32_t(args.Priority)
	if params.priority > C.RTE_ACL_MAX_PRIORITY {
		params.priority = C.RTE_ACL_MAX_PRIORITY
	}
	if params.priority < C.RTE_ACL_MIN_PRIORITY {
		params.priority = C.RTE_ACL_MIN_PRIORITY
	}

	// SPI
	params.spi = C.uint32_t(args.SPI)

	// Entry ID.
	params.entry_id = C.uint32_t(args.EntryID)

	// proto.
	if args.UpperProtocol == UpperProtocolTypeAny {
		params.proto = 0x0
		params.proto_mask = 0x0
	} else {
		params.proto = C.uint8_t(args.UpperProtocol)
		params.proto_mask = 0xff
	}

	// src IP
	size := net.IPv6len
	if args.LocalIP.IP != nil && args.LocalIP.Mask != nil {
		cs.ipv6ToCUint8Array(unsafe.Pointer(&params.src_ip), size,
			args.LocalIP.IP)
		params.src_ip_mask = cs.maskToCUint32(args.LocalIP.Mask)
	}

	// dst IP
	if args.RemoteIP.IP != nil && args.RemoteIP.Mask != nil {
		cs.ipv6ToCUint8Array(unsafe.Pointer(&params.dst_ip), size,
			args.RemoteIP.IP)
		params.dst_ip_mask = cs.maskToCUint32(args.RemoteIP.Mask)
	}

	params.src_port = C.uint16_t(args.LocalPortRangeStart)
	params.src_port_mask = C.uint16_t(args.LocalPortRangeEnd)

	params.dst_port = C.uint16_t(args.RemotePortRangeStart)
	params.dst_port_mask = C.uint16_t(args.RemotePortRangeEnd)

	return params
}

// ModuleCSPD Get module.
func (cs *CSPD6) ModuleCSPD(vrfIndex vswitch.VRFIndex, direction DirectionType) (CSPD, error) {
	if cs.dbs[direction] == nil {
		if ipm := cs.cModule(direction); ipm != nil {
			if cspd := C.ipsec_get_spd6(ipm.cmodule, C.vrfindex_t(vrfIndex)); cspd != nil {
				cs.dbs[direction] = cspd
				return cs.dbs[direction], nil
			}
			return nil, fmt.Errorf("Not found cspd6")
		}
		return nil, fmt.Errorf("Not found cmodule")
	}
	return cs.dbs[direction], nil
}

// String String.
func (cs *CSPD6) String() string {
	return "SPD6"
}
