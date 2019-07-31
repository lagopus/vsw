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
	target_match  = MatchAny
	invalid_match = MatchEthDstSelf
	vif_match     = MatchOutVIF
	num_vifs      = 5
)

var testParams = map[VswMatch]interface{}{
	MatchAny:         nil,
	MatchInVIF:       &VIF{index: 1},
	MatchOutVIF:      &VIF{index: 2},
	MatchEthDst:      &net.HardwareAddr{},
	MatchEthDstSelf:  nil,
	MatchEthDstMC:    nil,
	MatchEthSrc:      &net.HardwareAddr{},
	MatchEthTypeIPv4: nil,
	MatchEthTypeIPv6: nil,
	MatchEthTypeARP:  nil,
	MatchEthType:     dpdk.EtherType(0),
	MatchVID:         VID(0),
	MatchIPv4Proto:   IPP_ESP,
	MatchIPv4Src:     &net.IP{},
	MatchIPv4SrcNet:  &IPAddr{},
	MatchIPv4Dst:     &net.IP{},
	MatchIPv4DstNet:  &IPAddr{},
	MatchIPv4DstSelf: nil,
	Match5Tuple:      NewFiveTuple(),
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
	timer := time.NewTimer(100 * time.Millisecond)

	select {
	case n, ok := <-ch:
		timer.Stop()
		if ok {
			if t != n.Type || target != n.Target || expect != n.Value {
				return fmt.Errorf("Expected: %v(%v, %v), Actual: %v(%v, %v)",
					t, target, expect, n.Type, n.Target, n.Value)
			}
			return nil
		} else {
			return fmt.Errorf("Channel closed.")
		}
	case <-timer.C:
		return fmt.Errorf("Timed out. No notification.")
	}
}

func checkNotification2(ch chan *ruleMsg, added bool, expect *Rule) error {
	timer := time.NewTimer(100 * time.Millisecond)

	select {
	case m := <-ch:
		timer.Stop()
		if m.added != added || *m.rule != *expect {
			return fmt.Errorf("Expected: added=%v(%v), Actual: %v(%v)",
				added, expect, m.added, m.rule)
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
	t.Logf("ok")

	t.Logf("Check remove notification")
	r.remove(target_match, nil)
	if err := checkNotification(ch, notifier.Delete, r, Rule{target_match, nil, ruleRing}); err != nil {
		t.Fatalf("Delete notification failed: %v", err)
	}
	t.Logf("ok")

	t.Logf("Check add after uninstalling watcher")
	r.Notifier().Close(ch)
	r.add(target_match, nil, ruleRing)
	if err := checkNotification(ch, notifier.Add, r, Rule{target_match, nil, ruleRing}); err == nil {
		t.Fatalf("Add notification called after uninstalling listener.")
	} else {
		t.Logf("ok: %v", err)
	}
}

type ruleMsg struct {
	rule  *Rule
	added bool
}

type ruleTest struct {
	ch chan *ruleMsg
	t  *testing.T
}

func (rt *ruleTest) RuleAdded(r Rule) {
	rt.t.Logf("Add: %v", r)
	rt.ch <- &ruleMsg{&r, true}
}

func (rt *ruleTest) RuleDeleted(r Rule) {
	rt.t.Logf("Delete: %v", r)
	rt.ch <- &ruleMsg{&r, false}
}

func TestRuleNotify2(t *testing.T) {
	rt := &ruleTest{make(chan *ruleMsg, 1), t}

	r := newRules()

	t.Logf("RulesNotify test. installing observer")
	r.setRulesNotify(rt)

	t.Logf("Check add notification")
	r.add(target_match, nil, ruleRing)
	if err := checkNotification2(rt.ch, true, &Rule{target_match, nil, ruleRing}); err != nil {
		t.Fatalf("Add notification failed: %v", err)
	}
	t.Logf("ok")

	t.Logf("Check remove notification")
	r.remove(target_match, nil)
	if err := checkNotification2(rt.ch, false, &Rule{target_match, nil, ruleRing}); err != nil {
		t.Fatalf("Delete notification failed: %v", err)
	}
	t.Logf("ok")

	t.Logf("Check add after uninstalling watcher")
	r.setRulesNotify(nil)
	r.add(target_match, nil, ruleRing)
	if err := checkNotification2(rt.ch, true, &Rule{target_match, nil, ruleRing}); err == nil {
		t.Fatalf("Add notification called.")
	} else {
		t.Logf("ok: %v", err)
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
