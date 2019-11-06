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
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/notifier"
)

// VswMatch is a matching rule.
type VswMatch int

const (
	MatchNone         VswMatch = iota // No rule
	MatchAny                          // Default destination (arg: none)
	MatchInVIF                        // Incoming VIF matched (arg: *VIF)
	MatchOutVIF                       // Outgoing VIF matched (arg: *VIF)
	MatchEthDst                       // Destination MAC address matched (arg: net.HardwareAddr)
	MatchEthDstSelf                   // Packet heading to the router itself (arg: none)
	MatchEthDstMC                     // Multicast (arg: none)
	MatchEthDstBC                     // Broadcast (arg: none)
	MatchEthSrc                       // Source MAC address matched (arg: net.HardwareAddr)
	MatchEthTypeIPv4                  // IPv4 packet type (arg: none)
	MatchEthTypeIPv6                  // IPv6 packet type (arg: none)
	MatchEthTypeARP                   // ARP packet type (arg: none)
	MatchEthType                      // Ether packet type matched (arg: dpdk.EtherType)
	MatchVID                          // VLAN ID matched (arg: VID)
	MatchIPv4Proto                    // IPv4 protocol type matched (arg: IPProto)
	MatchIPv4Src                      // Source IPv4 address matched (arg: net.IP)
	MatchIPv4SrcNet                   // Source IPv4 network address matched (arg: IPAddr)
	MatchIPv4Dst                      // Destination IPv4 address matched (arg: net.IP)
	MatchIPv4DstNet                   // Destination IPv4 network address matched (arg: IPAddr)
	MatchIPv4DstSelf                  // IPv4 packet sent to the router itself (none)
	MatchIPv4DstInVIF                 // IPv4 packet received from input VIF (arg: ScopedAddress)
	Match5Tuple                       // 5-Tuple (arg: *FiveTuple)
	MatchVxLAN                        // VxLAN (arg: *VxLAN)
)

var vswMatchStrings = map[VswMatch]string{
	MatchAny:          "MatchAny",
	MatchInVIF:        "MatchInVIF",
	MatchOutVIF:       "MatchOutVIF",
	MatchEthDst:       "MatchEthDst",
	MatchEthDstSelf:   "MatchEthDstSelf",
	MatchEthDstMC:     "MatchEthDstMC",
	MatchEthDstBC:     "MatchEthDstBC",
	MatchEthSrc:       "MatchEthSrc",
	MatchEthTypeIPv4:  "MatchEthTypeIPv4",
	MatchEthTypeIPv6:  "MatchEthTypeIPv6",
	MatchEthTypeARP:   "MatchEthTypeARP",
	MatchEthType:      "MatchEthType",
	MatchVID:          "MatchVID",
	MatchIPv4Proto:    "MatchIPv4Proto",
	MatchIPv4Src:      "MatchIPv4Src",
	MatchIPv4SrcNet:   "MatchIPv4SrcNet",
	MatchIPv4Dst:      "MatchIPv4Dst",
	MatchIPv4DstNet:   "MatchIPv4DstNet",
	MatchIPv4DstSelf:  "MatchIPv4DstSelf",
	MatchIPv4DstInVIF: "MatchIPv4DstInVIF",
	Match5Tuple:       "Match5Tuple",
	MatchVxLAN:        "MatchVxLAN",
}

func (vm VswMatch) String() string { return vswMatchStrings[vm] }

var paramTypes = map[VswMatch]reflect.Type{
	MatchAny:          nil,
	MatchInVIF:        reflect.TypeOf((*VIF)(nil)),
	MatchOutVIF:       reflect.TypeOf((*VIF)(nil)),
	MatchEthDst:       reflect.TypeOf((*net.HardwareAddr)(nil)),
	MatchEthDstSelf:   nil,
	MatchEthDstMC:     nil,
	MatchEthDstBC:     nil,
	MatchEthSrc:       reflect.TypeOf((*net.HardwareAddr)(nil)),
	MatchEthTypeIPv4:  nil,
	MatchEthTypeIPv6:  nil,
	MatchEthTypeARP:   nil,
	MatchEthType:      reflect.TypeOf(dpdk.EtherType(0)),
	MatchVID:          reflect.TypeOf(VID(0)),
	MatchIPv4Proto:    reflect.TypeOf(IPProto(0)),
	MatchIPv4Src:      reflect.TypeOf((*net.IP)(nil)),
	MatchIPv4SrcNet:   reflect.TypeOf((*IPAddr)(nil)),
	MatchIPv4Dst:      reflect.TypeOf((*net.IP)(nil)),
	MatchIPv4DstNet:   reflect.TypeOf((*IPAddr)(nil)),
	MatchIPv4DstSelf:  nil,
	MatchIPv4DstInVIF: reflect.TypeOf((*ScopedAddress)(nil)),
	Match5Tuple:       reflect.TypeOf((*FiveTuple)(nil)),
	MatchVxLAN:        reflect.TypeOf((*VxLAN)(nil)),
}

const ruleNotificationBuffer = 10

// Rule specifies the packet dispatch rule
type Rule struct {
	Match VswMatch    // Match rule
	Param interface{} // Parameters for the match rule
	Ring  *dpdk.Ring  // Input ring of the next module
}

// Rules is a collection of Rule
type Rules struct {
	rules map[VswMatch]([]Rule)
	noti  *notifier.Notifier
	once  sync.Once
	rn    RulesNotify
}

// RulesNotify needs to be implemented if the entity wants to receive
// notifiication upon changes in the Rules.
//
// Calls to these methods are synchronous.
//
// It is highly recommeneded that callee apply rules immediately.
// Rules should become effective before returning from these
// methods.
type RulesNotify interface {
	RuleAdded(Rule)
	RuleDeleted(Rule)
}

// ByMatch implements sort.Interface for []Rule based on the Match field.
type ByMatch []Rule

func (m ByMatch) Len() int           { return len(m) }
func (m ByMatch) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }
func (m ByMatch) Less(i, j int) bool { return m[i].Match < m[j].Match }

func newRules() *Rules {
	return &Rules{rules: make(map[VswMatch]([]Rule))}
}

func (r *Rules) setRulesNotify(rn RulesNotify) {
	r.rn = rn
}

// Notifier returns notifier for the rule set.
//
// The following notifications will be sent out:
//
// 1. Rule is added:
//	Type: Notifier.Add
//	Target: *Rules
//	Value: Rule
//
// 2. Rule is deleted:
//	Type: Notifier.Delete
//	Target: *Rules
//	Value: Rule
//
func (r *Rules) Notifier() *notifier.Notifier {
	r.once.Do(func() {
		r.noti = notifier.NewNotifier(ruleNotificationBuffer)
	})
	return r.noti
}

func (r *Rules) notify(op notifier.Type, rule Rule) {
	if r.noti != nil {
		r.noti.Notify(op, r, rule)
	}

	if r.rn != nil {
		if op == notifier.Add {
			r.rn.RuleAdded(rule)
		} else if op == notifier.Delete {
			r.rn.RuleDeleted(rule)
		}
	}
}

// Convert IP Address format to 16-byte form
// because we use reflect.DeepEqual() to remove a rule
// if a matching rule is MatchIPv4DstInVIF or Match5Tuple, MatchVxLAN.
func to16(param interface{}) interface{} {
	switch v := param.(type) {
	case *ScopedAddress:
		sa := *v
		sa.address = v.address.To16()
		return &sa
	case *FiveTuple:
		ft := *v
		ft.SrcIP.IP = v.SrcIP.IP.To16()
		ft.DstIP.IP = v.DstIP.IP.To16()
		return &ft
	case *VxLAN:
		vxlan := *v
		vxlan.Src = v.Src.To16()
		vxlan.Dst = v.Dst.To16()
		return &vxlan
	default:
		return v
	}
}

func (r *Rules) add(match VswMatch, param interface{}, ring *dpdk.Ring) error {
	var rule Rule

	if ring == nil {
		return errors.New("Input ring not set")
	}

	t := paramTypes[match]
	if t != nil {
		if t != reflect.TypeOf(param) {
			return fmt.Errorf("Type %v is expected for %v", t, match)
		}
		rule.Param = param
	}

	rule.Match = match
	rule.Ring = ring

	if t == nil {
		// FIXME: We must remove the old Rule if there's one already.
		r.rules[match] = make([]Rule, 1, 1)
		r.rules[match][0] = rule
	} else {
		r.rules[match] = append(r.rules[match], rule)
	}

	r.notify(notifier.Add, rule)

	return nil
}

func (r *Rules) deleteRule(i int, match VswMatch, rule Rule) {
	rules := r.rules[match]
	l := len(rules) - 1
	rules[i] = rules[l]
	rules[l] = Rule{}

	r.rules[match] = rules[:l]
	r.notify(notifier.Delete, rule)
}

func (r *Rules) remove(match VswMatch, param interface{}) error {
	switch match {
	case MatchIPv4DstInVIF, Match5Tuple, MatchVxLAN:
		// Convert IP Address format to 16-byte form.
		p := to16(param)
		for i, rule := range r.rules[match] {
			if reflect.DeepEqual(to16(rule.Param), p) {
				r.deleteRule(i, match, rule)
				return nil
			}
		}
	default:
		for i, rule := range r.rules[match] {
			if rule.Param == param {
				r.deleteRule(i, match, rule)
				return nil
			}
		}
	}

	return fmt.Errorf("No match to %v (param=%v)", match, param)
}

func (r *Rules) removeAll() {
	for _, rules := range r.rules {
		for _, rule := range rules {
			r.notify(notifier.Delete, rule)
		}
	}
	r.rules = make(map[VswMatch]([]Rule))
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
