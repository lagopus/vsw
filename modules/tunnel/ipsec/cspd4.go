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

// #include "sp4.h"
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/lagopus/vsw/vswitch"
)

// C plane APIs for IPv4.

// CSPD4 CSPD for IPv4.
type CSPD4 struct {
	baseCSPD
	dbs map[DirectionType]*C.struct_spd4
}

// NewCSPD4 New CSPD4.
func NewCSPD4() *CSPD4 {
	return &CSPD4{
		baseCSPD: baseCSPD{},
		dbs: map[DirectionType]*C.struct_spd4{
			DirectionTypeIn:  nil,
			DirectionTypeOut: nil,
		},
	}
}

// converter.

func (cs *CSPD4) cspdTocStruct(spd CSPD) *C.struct_spd4 {
	if v, ok := spd.(*C.struct_spd4); ok {
		return (*C.struct_spd4)((unsafe.Pointer(v)))
	}
	return nil
}

func (cs *CSPD4) cACLRulesTocStruct(rules CACLRules) *C.struct_acl4_rules {
	if v, ok := rules.(*C.struct_acl4_rules); ok {
		return (*C.struct_acl4_rules)((unsafe.Pointer(v)))
	}
	return nil
}

func (cs *CSPD4) cACLParamsTocStruct(params CACLParams) *C.struct_acl4_params {
	if v, ok := params.(*C.struct_acl4_params); ok {
		return (*C.struct_acl4_params)((unsafe.Pointer(v)))
	}
	return nil
}

// interface funcs.

// AllocRules Alloc rules.
func (cs *CSPD4) AllocRules(size uint32) CACLRules {
	return C.sp4_alloc_rules(C.size_t(size))
}

// FreeRules Free rules.
func (cs *CSPD4) FreeRules(rules CACLRules) {
	C.sp4_free_rules(cs.cACLRulesTocStruct(rules))
}

// Make Make ACL.
func (cs *CSPD4) Make(spd CSPD, inRules CACLRules, inRulesSize uint32,
	outRules CACLRules, outRulesSize uint32) error {
	s := cs.cspdTocStruct(spd)
	ir := cs.cACLRulesTocStruct(inRules)
	or := cs.cACLRulesTocStruct(outRules)

	if r := LagopusResult(C.sp4_make_spd(s, ir, C.uint32_t(inRulesSize),
		or, C.uint32_t(outRulesSize))); r != LagopusResultOK {
		return fmt.Errorf("Fail sp4_make_spd, %v", r)
	}
	return nil
}

// Stats Get stats.
func (cs *CSPD4) Stats(spd CSPD, spi uint32) (*CSPDStats, error) {
	s := cs.cspdTocStruct(spd)
	st := C.struct_spd_stats{}
	if r := LagopusResult(C.sp4_get_stats(s, &st, C.uint32_t(spi))); r != LagopusResultOK {
		return nil, fmt.Errorf("Fail sp4_get_stats(), %v", r)
	}
	stats := CSPDStats(st)
	return &stats, nil
}

// SetRule Set rule.
func (cs *CSPD4) SetRule(index uint32, rules CACLRules,
	params CACLParams) error {
	r := cs.cACLRulesTocStruct(rules)
	p := cs.cACLParamsTocStruct(params)

	if r := LagopusResult(C.sp4_set_rule(C.size_t(index), r, p)); r != LagopusResultOK {
		return fmt.Errorf("Fail sp4_set_rule, %v", r)
	}

	return nil
}

// DumpRules Dump rules.
func (cs *CSPD4) DumpRules(rules CACLRules, size uint32) {
	C.sp4_dump_rules(cs.cACLRulesTocStruct(rules), C.int32_t(size))
}

// NewParams New ACL params.
func (cs *CSPD4) NewParams(args *CACLParamsArgs) CACLParams {
	params := &C.struct_acl4_params{}

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

	// proto
	if args.UpperProtocol == UpperProtocolTypeAny {
		params.proto = 0x0
		params.proto_mask = 0x0
	} else {
		params.proto = C.uint8_t(args.UpperProtocol)
		params.proto_mask = 0xff
	}

	// src IP
	if args.LocalIP.IP != nil && args.LocalIP.Mask != nil {
		params.src_ip = cs.ipv4ToCUint32(args.LocalIP.IP)
		params.src_ip_mask = cs.maskToCUint32(args.LocalIP.Mask)
	}

	// dst IP
	if args.RemoteIP.IP != nil && args.RemoteIP.Mask != nil {
		params.dst_ip = cs.ipv4ToCUint32(args.RemoteIP.IP)
		params.dst_ip_mask = cs.maskToCUint32(args.RemoteIP.Mask)
	}

	params.src_port = C.uint16_t(args.LocalPortRangeStart)
	params.src_port_mask = C.uint16_t(args.LocalPortRangeEnd)

	params.dst_port = C.uint16_t(args.RemotePortRangeStart)
	params.dst_port_mask = C.uint16_t(args.RemotePortRangeEnd)

	return params
}

// ModuleCSPD Get module.
func (cs *CSPD4) ModuleCSPD(vrfIndex vswitch.VRFIndex, direction DirectionType) (CSPD, error) {
	if cs.dbs[direction] == nil {
		if ipm := cs.cModule(direction); ipm != nil {
			if cspd := C.ipsec_get_spd4(ipm.cmodule, C.vrfindex_t(vrfIndex)); cspd != nil {
				cs.dbs[direction] = cspd
				return cs.dbs[direction], nil
			}
			return nil, fmt.Errorf("Not found cspd4")
		}
		return nil, fmt.Errorf("Not found cmodule")
	}
	return cs.dbs[direction], nil
}

// String String.
func (cs *CSPD4) String() string {
	return "SPD4"
}
