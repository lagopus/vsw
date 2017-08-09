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

/*
#include "rule.h"
#include <string.h>
#include <stdio.h>

static void dump(struct vsw_rule **r, int n) {
	for (int i = 0; i < n; i++) {
		if (r[i]->param != NULL) {
			printf("%2d: match=%d, param=%lu, ring=%p\n", i, r[i]->match, r[i]->param[0], r[i]->ring);
		} else {
			printf("%2d: match=%d, ring=%p\n", i, r[i]->match, r[i]->ring);
		}
	}
}
*/
import "C"

import (
	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/carray"
	"unsafe"
)

// R is a bridge to struct vsw_rule for C.
type R C.struct_vsw_rule

// VswMatch is a matching rule.
type VswMatch C.vsw_match_t

const (
	MATCH_ANY           VswMatch = C.VSW_MATCH_ANY           // Default destination
	MATCH_IN_VIF                 = C.VSW_MATCH_IN_VIF        // Incoming VIF matched
	MATCH_OUT_VIF                = C.VSW_MATCH_OUT_VIF       // Outgoing VIF matched
	MATCH_BRIDGE_ID              = C.VSW_MATCH_BRIDGE_ID     // Bridge ID matched
	MATCH_ETH_DST                = C.VSW_MATCH_ETH_DST       // Destination MAC address matched
	MATCH_ETH_DST_SELF           = C.VSW_MATCH_ETH_DST_SELF  // Packet heading to the router itself
	MATCH_ETH_DST_MC             = C.VSW_MATCH_ETH_DST_MC    // Multicast
	MATCH_ETH_SRC                = C.VSW_MATCH_ETH_SRC       // Source MAC address matched
	MATCH_ETH_TYPE_IPV4          = C.VSW_MATCH_ETH_TYPE_IPV4 // IPv4 packet type
	MATCH_ETH_TYPE_IPV6          = C.VSW_MATCH_ETH_TYPE_IPV6 // IPv6 packet type
	MATCH_ETH_TYPE_ARP           = C.VSW_MATCH_ETH_TYPE_ARP  // ARP packet type
	MATCH_ETH_TYPE               = C.VSW_MATCH_ETH_TYPE      // Ether packet type matched
	MATCH_VLAN_ID                = C.VSW_MATCH_VLAN_ID       // VLAN ID matched
	MATCH_IPV4_PROTO             = C.VSW_MATCH_IPV4_PROTO    // IPv4 protocol type matched
	MATCH_IPV4_SRC               = C.VSW_MATCH_IPV4_SRC      // Source IPv4 address matched
	MATCH_IPV4_SRC_NET           = C.VSW_MATCH_IPV4_SRC_NET  // Source IPv4 network address matched
	MATCH_IPV4_DST               = C.VSW_MATCH_IPV4_DST      // Destination IPv4 address matched
	MATCH_IPV4_DST_NET           = C.VSW_MATCH_IPV4_DST_NET  // Destination IPv4 network address matched
	MATCH_IPV4_DST_SELF          = C.VSW_MATCH_IPV4_DST_SELF // IPv4 packet sent to the router itself
	MATCH_TP_SRC                 = C.VSW_MATCH_TP_SRC
	MATCH_TP_DST                 = C.VSW_MATCH_TP_DST
)

var vswMatchStrings = map[VswMatch]string{
	MATCH_ANY:           "Default destination",
	MATCH_IN_VIF:        "Incoming VIF matched",
	MATCH_OUT_VIF:       "Outgoing VIF matched",
	MATCH_BRIDGE_ID:     "Bridge ID matched",
	MATCH_ETH_DST:       "Destination MAC address matched",
	MATCH_ETH_DST_SELF:  "Destination MAC is self",
	MATCH_ETH_DST_MC:    "Destinatino MAC is Multicast",
	MATCH_ETH_SRC:       "Source MAC address matched",
	MATCH_ETH_TYPE_IPV4: "IPv4 packet type",
	MATCH_ETH_TYPE_IPV6: "IPv6 packet type",
	MATCH_ETH_TYPE_ARP:  "ARP packet type",
	MATCH_ETH_TYPE:      "Ether packet type matched",
	MATCH_VLAN_ID:       "VLAN ID matched",
	MATCH_IPV4_PROTO:    "IPv4 protocol type matched",
	MATCH_IPV4_SRC:      "Source IPv4 address matched",
	MATCH_IPV4_SRC_NET:  "Source IPv4 network address matched",
	MATCH_IPV4_DST:      "Destination IPv4 address matched",
	MATCH_IPV4_DST_NET:  "Destination IPv4 network address matched",
	MATCH_IPV4_DST_SELF: "IPv4 packet sent to the router itself",
	MATCH_TP_SRC:        "TP Source",
	MATCH_TP_DST:        "TP Destination",
}

func (vm VswMatch) String() string { return vswMatchStrings[vm] }

var hasParam = map[VswMatch]bool{
	MATCH_ANY:           false,
	MATCH_IN_VIF:        true,
	MATCH_OUT_VIF:       true,
	MATCH_BRIDGE_ID:     true,
	MATCH_ETH_DST:       true,
	MATCH_ETH_DST_SELF:  false,
	MATCH_ETH_DST_MC:    false,
	MATCH_ETH_SRC:       true,
	MATCH_ETH_TYPE_IPV4: false,
	MATCH_ETH_TYPE_IPV6: false,
	MATCH_ETH_TYPE_ARP:  false,
	MATCH_ETH_TYPE:      true,
	MATCH_VLAN_ID:       true,
	MATCH_IPV4_PROTO:    true,
	MATCH_IPV4_SRC:      true,
	MATCH_IPV4_SRC_NET:  true,
	MATCH_IPV4_DST:      true,
	MATCH_IPV4_DST_NET:  true,
	MATCH_IPV4_DST_SELF: false,
	MATCH_TP_SRC:        true,
	MATCH_TP_DST:        true,
}

// Rule specifies the packet dispatch rule
type Rule struct {
	Match VswMatch   // Match rule
	Param []uint64   // Parameters for the match rule
	Ring  *dpdk.Ring // Input ring of the next module
}

// Rules is a collection of Rule
type Rules struct {
	rules   map[VswMatch]([]Rule)
	watcher Watcher
}

// Watcher is to monitor the changes of the rule on the fly
type Watcher interface {
	Updated(r *Rules) // Called when rule is updated.
}

// ByMatch implements sort.Interface for []Rule based on the Match field.
type ByMatch []Rule

func (m ByMatch) Len() int           { return len(m) }
func (m ByMatch) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }
func (m ByMatch) Less(i, j int) bool { return m[i].Match < m[j].Match }

func newRules() *Rules {
	return &Rules{rules: make(map[VswMatch]([]Rule))}
}

// Watch enables to monitor changes on rule.
// Pass a pointer to the interface that implements Watcher interface.
// Pass nil to disable.
func (r *Rules) Watch(w interface{}) bool {
	if w == nil {
		r.watcher = nil
		return true
	}

	if watcher, ok := w.(Watcher); ok {
		r.watcher = watcher
		return true
	}

	return false
}

func (r *Rules) notify() {
	if r.watcher != nil {
		r.watcher.Updated(r)
	}
}

func (r *Rules) add(match VswMatch, param []uint64, ring *dpdk.Ring) {
	e := Rule{
		Match: match,
		Param: param,
		Ring:  ring,
	}

	if !hasParam[match] {
		if r.rules[match] == nil {
			r.rules[match] = make([]Rule, 1, 1)
		}
		e.Param = nil
		r.rules[match][0] = e
	} else {
		r.rules[match] = append(r.rules[match], e)
	}

	r.notify()
}

func (r *Rules) remove(match VswMatch) {
	r.rules[match] = nil
	r.notify()
}

func (r *Rules) removeAll() {
	r.rules = make(map[VswMatch]([]Rule))
	r.notify()
}

func (r *Rules) rulesCount() int {
	count := 0
	for _, entries := range r.rules {
		count += len(entries)
	}
	return count
}

// Rules returns a copy of entire rule.
func (r *Rules) Rules() []Rule {
	count := r.rulesCount()
	rules := make([]Rule, count)
	n := 0
	for _, rs := range r.rules {
		for _, rule := range rs {
			rules[n] = rule
			n++
		}
	}
	return rules
}

// SubRules returns a rules for given match.
func (r *Rules) SubRules(match VswMatch) []Rule {
	rules := make([]Rule, len(r.rules[match]))
	copy(rules, r.rules[match])
	return rules
}

// Output returns a ring for the specified match.
// If the match has none or more than one output ring associated,
// it returns nil.
func (r *Rules) Output(match VswMatch) *dpdk.Ring {
	if len(r.rules[match]) != 1 {
		return nil
	}
	return r.rules[match][0].Ring
}

// CArray creates an array of pointrs to struct vsw_rule, copies
// entire rule, and returns a pointer to array and a number of elements.
// Returned array and structs shall be freed by caller.
// Params in the structs are also pointers to an array of uint64_t.
func (r *Rules) CArray() (**C.struct_vsw_rule, int) {
	count := r.rulesCount()
	rules := make([]*C.struct_vsw_rule, count)
	n := 0
	for _, entries := range r.rules {
		for _, e := range entries {
			rules[n] = (*C.struct_vsw_rule)(C.malloc(C.sizeof_struct_vsw_rule))
			rules[n].match = C.vsw_match_t(e.Match)
			rules[n].ring = (*C.struct_rte_ring)(unsafe.Pointer(e.Ring))

			length := C.sizeof_uint64_t * len(e.Param)
			if length > 0 {
				rules[n].param = (*C.uint64_t)(carray.Dup(unsafe.Pointer(&e.Param[0]), length))
			} else {
				rules[n].param = nil
			}

			n++
		}
	}

	carray := carray.DupPointers(unsafe.Pointer(&rules[0]), count)

	if false {
		C.dump((**C.struct_vsw_rule)(carray), C.int(count))
	}

	return (**C.struct_vsw_rule)(carray), count
}
