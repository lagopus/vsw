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

package ipsec

// #include "ipsec.h"
// #include "sp.h"
import "C"
import (
	"bytes"
	"encoding/binary"
	"net"
	"unsafe"

	"github.com/lagopus/vsw/vswitch"
)

// CSPD SPD for C.
type CSPD interface{}

// CACLRules ACLRules for C.
type CACLRules interface{}

// CACLParams ACLParams for C.
type CACLParams interface{}

// CSPDStat struct spd_stat.
type CSPDStat *C.struct_spd_stat

// CSPSelector Selector for CSP.
type CSPSelector struct {
	VRFIndex             vswitch.VRFIndex
	LocalIP              net.IPNet         // Local(src) IP addr and mask
	LocalPortRangeStart  uint16            // Local(src) Port (start of range)
	LocalPortRangeEnd    uint16            // Local(src) Port (end of range)
	RemoteIP             net.IPNet         // Remote(dst) IP addr and mask
	RemotePortRangeStart uint16            // Remote(dst) Port (start of range)
	RemotePortRangeEnd   uint16            // Remote(dst) Port (end of range)
	UpperProtocol        UpperProtocolType // Upper Protocol
}

// Modified Is Modified.
func (s CSPSelector) Modified(newS CSPSelector) bool {
	return (s.VRFIndex != newS.VRFIndex) ||
		!bytes.Equal(s.LocalIP.IP, newS.LocalIP.IP) ||
		!bytes.Equal(s.LocalIP.Mask, newS.LocalIP.Mask) ||
		!bytes.Equal(s.RemoteIP.IP, newS.RemoteIP.IP) ||
		!bytes.Equal(s.RemoteIP.Mask, newS.RemoteIP.Mask) ||
		(s.LocalPortRangeStart != newS.LocalPortRangeStart) ||
		(s.LocalPortRangeEnd != newS.LocalPortRangeEnd) ||
		(s.RemotePortRangeStart != newS.RemotePortRangeStart) ||
		(s.RemotePortRangeEnd != newS.RemotePortRangeEnd) ||
		(s.UpperProtocol != newS.UpperProtocol)
}

// CSPValue Values for CSP.
type CSPValue struct {
	Policy   PolicyType // Policy (DISCARD, IPSEC, BYPASS)
	Priority int32      // Priority
	SPI      uint32     // SPI
	EntryID  uint32     // SP entry ID
}

// CACLParamsArgs Args for ACLParams
type CACLParamsArgs struct {
	CSPSelector // SPSelector in C.
	CSPValue    // SPValue in C.
}

// SPD CSPD interface.
type SPD interface {
	AllocRules(size uint32) CACLRules
	FreeRules(rules CACLRules)
	Make(spd CSPD, inRules CACLRules, inRulesSize uint32,
		outRules CACLRules, outRulesSize uint32) LagopusResult
	Stat(spd CSPD, stat *CSPDStat,
		spi uint32) LagopusResult
	StatLiftimeCurrent(stat CSPDStat) int64
	SetRule(index uint32, rules CACLRules,
		params CACLParams) LagopusResult
	DumpRules(rules CACLRules, size uint32)
	NewParams(args *CACLParamsArgs) CACLParams
	ModuleCSPD(vrfIndex vswitch.VRFIndex, direction DirectionType) (CSPD, error)
	String() string
}

type baseCSPD struct{}

func (cs *baseCSPD) cspdStatTocStruct(stat CSPDStat) *C.struct_spd_stat {
	return (*C.struct_spd_stat)((unsafe.Pointer(stat)))
}

func (cs *baseCSPD) ipv4ToCUint32(ip net.IP) C.uint32_t {
	return C.uint32_t(binary.LittleEndian.Uint32(
		ip.To4()))
}

func (cs *baseCSPD) ipv6ToCUint8Array(dstIP unsafe.Pointer, size int,
	ip net.IP) {
	ipSlice := (*[1 << 30]C.uint8_t)(dstIP)[:size:size]
	for i := 0; i < size; i++ {
		ipSlice[i] = C.uint8_t(ip[i])
	}
}

func (cs *baseCSPD) maskToCUint32(mask net.IPMask) C.uint32_t {
	ones, _ := mask.Size()
	return C.uint32_t(ones)
}

func (cs *baseCSPD) cModule(direction DirectionType) *Module {
	if m, err := module(direction); err == nil {
		return m
	}

	return nil
}

// StatLiftimeCurrent Get liftime (current).
func (cs *baseCSPD) StatLiftimeCurrent(stat CSPDStat) int64 {
	s := cs.cspdStatTocStruct(stat)
	return int64(s.lifetime_current)
}
