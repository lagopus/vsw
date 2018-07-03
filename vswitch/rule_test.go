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
	"fmt"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/notifier"
)

func checkCount(t *testing.T, r *Rules, e int) {
	count := len(r.Rules())
	if count != e {
		t.Fatalf("Go %d entries (should be %d)\n", count, e)
	}
}

func checkRule(t *testing.T, r *Rules, index int, rule Rule) {
	rules := r.Rules()
	if rules[index].Match != rule.Match ||
		rules[index].Ring != rule.Ring || rules[index].Param != rule.Param {
		t.Fatalf("Rule is not correct (%v). (should be %v)\n", rules[index], rule)
	}
}

func showRules(t *testing.T, r *Rules) {
	rules := r.Rules()
	sort.Sort(ByMatch(rules))
	t.Logf("--------")
	for i, r := range rules {
		t.Logf("%d: %v\n", i, r)
	}
	t.Logf("--------")
}

const (
	target_match  = MATCH_ANY
	invalid_match = MATCH_ETH_DST_SELF
	vif_match     = MATCH_OUT_VIF
	num_vifs      = 5
)

var testParams = map[VswMatch]interface{}{
	MATCH_ANY:           nil,
	MATCH_IN_VIF:        &VIF{index: 1},
	MATCH_OUT_VIF:       &VIF{index: 2},
	MATCH_ETH_DST:       &net.HardwareAddr{},
	MATCH_ETH_DST_SELF:  nil,
	MATCH_ETH_DST_MC:    nil,
	MATCH_ETH_SRC:       &net.HardwareAddr{},
	MATCH_ETH_TYPE_IPV4: nil,
	MATCH_ETH_TYPE_IPV6: nil,
	MATCH_ETH_TYPE_ARP:  nil,
	MATCH_ETH_TYPE:      dpdk.EtherType(0),
	MATCH_VLAN_ID:       VID(0),
	MATCH_IPV4_PROTO:    IPP_ESP,
	MATCH_IPV4_SRC:      &net.IP{},
	MATCH_IPV4_SRC_NET:  &IPAddr{},
	MATCH_IPV4_DST:      &net.IP{},
	MATCH_IPV4_DST_NET:  &IPAddr{},
	MATCH_IPV4_DST_SELF: nil,
}

// A place holder for a dummy ring used through out the tests
var ruleRing *dpdk.Ring

func TestRule(t *testing.T) {
	ruleRing = dpdk.RingCreate("ring4rule", 1, dpdk.SOCKET_ID_ANY, 0)

	t.Logf("Creating a new Rules\n")
	r := newRules()

	// add a rule
	t.Logf("Adding one entry\n")
	if err := r.add(target_match, nil, ruleRing); err != nil {
		t.Fatalf("r.add failed: %v", err)
	}
	checkCount(t, r, 1)

	// override a rule
	t.Logf("Overriding a rule\n")
	if err := r.add(target_match, nil, ruleRing); err != nil {
		t.Fatalf("r.add failed: %v", err)
	}
	checkCount(t, r, 1)
	checkRule(t, r, 0, Rule{target_match, nil, ruleRing})

	// remove non-existing rule
	t.Logf("Remove non-existing rule")
	if err := r.remove(invalid_match, nil); err == nil {
		t.Fatalf("r.remove should have failed")
	} else {
		t.Logf("remove failed. ok: %v", err)
	}
	checkCount(t, r, 1)
	checkRule(t, r, 0, Rule{target_match, nil, ruleRing})

	// remove the current one
	t.Logf("Remove existing rule")
	if err := r.remove(target_match, nil); err != nil {
		t.Fatalf("r.remove failed: %v", err)
	}
	checkCount(t, r, 0)

	// add all
	t.Logf("Add all rules")
	for k, v := range testParams {
		if err := r.add(k, v, ruleRing); err != nil {
			t.Fatalf("r.add failed: %v", err)
		}
	}
	checkCount(t, r, len(testParams))
	showRules(t, r)

	// add twice
	t.Logf("Add all rules twice")
	twice := 0
	for k, v := range testParams {
		if err := r.add(k, v, ruleRing); err != nil {
			t.Fatalf("r.add failed: %v", err)
		}
		if v != nil {
			twice++
		}
	}
	checkCount(t, r, len(testParams)+twice)
	showRules(t, r)

	// remove all
	t.Logf("Remove all rules")
	r.removeAll()
	checkCount(t, r, 0)
}

func checkNotification(ch chan notifier.Notification, t notifier.Type, target *Rules, expect Rule) error {
	timer := time.NewTimer(3 * time.Second)

	select {
	case n := <-ch:
		timer.Stop()
		if t != n.Type || target != n.Target || expect != n.Value {
			return fmt.Errorf("Expected: %v(%v, %v), Actual: %v(%v, %v)",
				t, target, expect, n.Type, n.Target, n.Value)
		}
		return nil
	case <-timer.C:
		return fmt.Errorf("Timed out. No notification.")
	}
}

func TestRuleNotify(t *testing.T) {
	r := newRules()

	t.Logf("Notify test. installing observer")
	ch := r.Notifier().Listen()

	t.Logf("Check add notification")
	r.add(target_match, nil, ruleRing)
	if err := checkNotification(ch, notifier.Add, r, Rule{target_match, nil, ruleRing}); err != nil {
		t.Fatalf("Add notification failed: %v", err)
	}

	t.Logf("Check remove notification")
	r.remove(target_match, nil)
	if err := checkNotification(ch, notifier.Delete, r, Rule{target_match, nil, ruleRing}); err != nil {
		t.Fatalf("Delete notification failed: %v", err)
	}

	t.Logf("Check add after uninstalling watcher")
	r.add(target_match, nil, ruleRing)
	if err := checkNotification(ch, notifier.Add, r, Rule{target_match, nil, ruleRing}); err != nil {
		t.Fatalf("Add notification failed: %v", err)
	}
}

func TestSubRule(t *testing.T) {
	r := newRules()

	t.Logf("Sub rules extraction test. Adding %d entries\n", num_vifs)
	for i := 0; i < num_vifs; i++ {
		r.add(vif_match, &VIF{index: VIFIndex(i)}, ruleRing)
	}

	t.Log("extract sub rule")
	sr := r.SubRules(vif_match)
	if len(sr) != num_vifs {
		t.Fatalf("Number of entry doesn't match (%d != %d)", len(sr), num_vifs)
	}
	t.Logf("Subrule: %v", sr)

	t.Log("mark entries found")
	check := make(map[VIFIndex]bool)
	for _, r := range sr {
		if vif, ok := r.Param.(*VIF); ok {
			check[vif.index] = true
		} else {
			t.Fatalf("Unexpected entry: %v", r)
		}
	}

	t.Log("check if all entry exists")
	for i := 0; i < num_vifs; i++ {
		if !check[VIFIndex(i)] {
			t.Fatalf("Couldn't find %d!", i)
		}
	}

	t.Log("extract non-existing sub rule")
	badSr := r.SubRules(target_match)
	if len(badSr) != 0 {
		t.Fatal("Got sub rules for non-existing match")
	}
	t.Logf("Bad Subrule: %v", badSr)
}
