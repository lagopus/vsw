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
	"reflect"
	"sync"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/notifier"
)

// VswMatch is a matching rule.
type VswMatch int

const (
	MATCH_NONE          VswMatch = iota // No rule
	MATCH_ANY                           // Default destination (arg: none)
	MATCH_IN_VIF                        // Incoming VIF matched (arg: *VIF)
	MATCH_OUT_VIF                       // Outgoing VIF matched (arg: *VIF)
	MATCH_ETH_DST                       // Destination MAC address matched (arg: net.HardwareAddr)
	MATCH_ETH_DST_SELF                  // Packet heading to the router itself (arg: none)
	MATCH_ETH_DST_MC                    // Multicast (arg: none)
	MATCH_ETH_DST_BC                    // Broadcast (arg: none)
	MATCH_ETH_SRC                       // Source MAC address matched (arg: net.HardwareAddr)
	MATCH_ETH_TYPE_IPV4                 // IPv4 packet type (arg: none)
	MATCH_ETH_TYPE_IPV6                 // IPv6 packet type (arg: none)
	MATCH_ETH_TYPE_ARP                  // ARP packet type (arg: none)
	MATCH_ETH_TYPE                      // Ether packet type matched (arg: dpdk.EtherType)
	MATCH_VLAN_ID                       // VLAN ID matched (arg: VID)
	MATCH_IPV4_PROTO                    // IPv4 protocol type matched (arg: IPProto)
	MATCH_IPV4_SRC                      // Source IPv4 address matched (arg: net.IP)
	MATCH_IPV4_SRC_NET                  // Source IPv4 network address matched (arg: IPAddr)
	MATCH_IPV4_DST                      // Destination IPv4 address matched (arg: net.IP)
	MATCH_IPV4_DST_NET                  // Destination IPv4 network address matched (arg: IPAddr)
	MATCH_IPV4_DST_SELF                 // IPv4 packet sent to the router itself (none)
)

var vswMatchStrings = map[VswMatch]string{
	MATCH_ANY:           "MATCH_ANY",
	MATCH_IN_VIF:        "MATCH_IN_VIF",
	MATCH_OUT_VIF:       "MATCH_OUT_VIF",
	MATCH_ETH_DST:       "MATCH_ETH_DST",
	MATCH_ETH_DST_SELF:  "MATCH_ETH_DST_SELF",
	MATCH_ETH_DST_MC:    "MATCH_ETH_DST_MC",
	MATCH_ETH_DST_BC:    "MATCH_ETH_DST_BC",
	MATCH_ETH_SRC:       "MATCH_ETH_SRC",
	MATCH_ETH_TYPE_IPV4: "MATCH_ETH_TYPE_IPV4",
	MATCH_ETH_TYPE_IPV6: "MATCH_ETH_TYPE_IPV6",
	MATCH_ETH_TYPE_ARP:  "MATCH_ETH_TYPE_ARP",
	MATCH_ETH_TYPE:      "MATCH_ETH_TYPE",
	MATCH_VLAN_ID:       "MATCH_VLAN_ID",
	MATCH_IPV4_PROTO:    "MATCH_IPV4_PROTO",
	MATCH_IPV4_SRC:      "MATCH_IPV4_SRC",
	MATCH_IPV4_SRC_NET:  "MATCH_IPV4_SRC_NET",
	MATCH_IPV4_DST:      "MATCH_IPV4_DST",
	MATCH_IPV4_DST_NET:  "MATCH_IPV4_DST_NET",
	MATCH_IPV4_DST_SELF: "MATCH_IPV4_DST_SELF",
}

func (vm VswMatch) String() string { return vswMatchStrings[vm] }

var paramTypes = map[VswMatch]reflect.Type{
	MATCH_ANY:           nil,
	MATCH_IN_VIF:        reflect.TypeOf((*VIF)(nil)),
	MATCH_OUT_VIF:       reflect.TypeOf((*VIF)(nil)),
	MATCH_ETH_DST:       reflect.TypeOf((*net.HardwareAddr)(nil)),
	MATCH_ETH_DST_SELF:  nil,
	MATCH_ETH_DST_MC:    nil,
	MATCH_ETH_DST_BC:    nil,
	MATCH_ETH_SRC:       reflect.TypeOf((*net.HardwareAddr)(nil)),
	MATCH_ETH_TYPE_IPV4: nil,
	MATCH_ETH_TYPE_IPV6: nil,
	MATCH_ETH_TYPE_ARP:  nil,
	MATCH_ETH_TYPE:      reflect.TypeOf(dpdk.EtherType(0)),
	MATCH_VLAN_ID:       reflect.TypeOf(VID(0)),
	MATCH_IPV4_PROTO:    reflect.TypeOf(IPProto(0)),
	MATCH_IPV4_SRC:      reflect.TypeOf((*net.IP)(nil)),
	MATCH_IPV4_SRC_NET:  reflect.TypeOf((*IPAddr)(nil)),
	MATCH_IPV4_DST:      reflect.TypeOf((*net.IP)(nil)),
	MATCH_IPV4_DST_NET:  reflect.TypeOf((*IPAddr)(nil)),
	MATCH_IPV4_DST_SELF: nil,
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
}

// ByMatch implements sort.Interface for []Rule based on the Match field.
type ByMatch []Rule

func (m ByMatch) Len() int           { return len(m) }
func (m ByMatch) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }
func (m ByMatch) Less(i, j int) bool { return m[i].Match < m[j].Match }

func newRules() *Rules {
	return &Rules{rules: make(map[VswMatch]([]Rule))}
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
		r.rules[match] = make([]Rule, 1, 1)
		r.rules[match][0] = rule
	} else {
		r.rules[match] = append(r.rules[match], rule)
	}

	r.notify(notifier.Add, rule)

	return nil
}

func (r *Rules) remove(match VswMatch, param interface{}) error {
	rules := r.rules[match]

	for i, rule := range rules {
		if rule.Param == param {
			l := len(rules) - 1
			rules[i] = rules[l]
			rules[l] = Rule{}

			r.rules[match] = rules[:l]
			r.notify(notifier.Delete, rule)

			return nil
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
