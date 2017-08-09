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
	"sort"
	"testing"
)

func checkCount(t *testing.T, r *Rules, e int) {
	count := len(r.Rules())
	if count != e {
		t.Fatalf("Go %d entries (should be %d)\n", count, e)
	}
}

func compareSlices(a, b []uint64) bool {

	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func checkRule(t *testing.T, r *Rules, index int, rule Rule) {
	rules := r.Rules()
	if rules[index].Match != rule.Match ||
		rules[index].Ring != rule.Ring || !compareSlices(rules[index].Param, rule.Param) {
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

// For Watcher test
type TestWatcher struct{ updated bool }

func (w *TestWatcher) Updated(r *Rules) {
	w.updated = true
}

func checkWatcher(t *testing.T, w *TestWatcher, e bool) {
	t.Logf("Expected: %v, got %v", e, w.updated)
	if w.updated != e {
		t.Fatal("Unexpected watcher state")
	}
	w.updated = false
}

func TestRule(t *testing.T) {
	t.Logf("Creating a new Rules\n")
	r := newRules()

	// add a rule
	t.Logf("Adding one entry\n")
	r.add(target_match, []uint64{0}, nil)
	checkCount(t, r, 1)

	// override a rule
	t.Logf("Overriding a rule\n")
	r.add(target_match, []uint64{1}, nil)
	checkCount(t, r, 1)
	checkRule(t, r, 0, Rule{target_match, nil, nil})

	// remove non-existing rule
	t.Logf("Remove non-existing rule")
	r.remove(invalid_match)
	checkCount(t, r, 1)
	checkRule(t, r, 0, Rule{target_match, nil, nil})

	// remove the current one
	t.Logf("Remove existing rule")
	r.remove(target_match)
	checkCount(t, r, 0)

	// add all
	t.Logf("Add all rules")
	for k, _ := range hasParam {
		r.add(k, []uint64{1}, nil)
	}
	checkCount(t, r, len(hasParam))
	showRules(t, r)

	// add twice
	t.Logf("Add all rules twice")
	twice := 0
	for k, v := range hasParam {
		r.add(k, []uint64{2, 3}, nil)
		if v {
			twice++
		}
	}
	checkCount(t, r, len(hasParam)+twice)
	showRules(t, r)

	// check CArray
	t.Logf("Get carray")
	ca, n := r.CArray()
	t.Logf("carray (%d entries)> %v\n", n, ca)

	// remove all
	t.Logf("Remove all rules")
	r.removeAll()
	checkCount(t, r, 0)
}

func TestRuleWatcher(t *testing.T) {
	r := newRules()

	// watcher test
	t.Logf("Watcher test. installing watcher")
	w := &TestWatcher{updated: false}
	if !r.Watch(w) {
		t.Fatal("Installing watcher failed.")
	}
	t.Logf("watch add")
	r.add(target_match, nil, nil)
	checkWatcher(t, w, true)
	t.Logf("watch remove")
	r.remove(target_match)
	checkWatcher(t, w, true)

	if !r.Watch(nil) {
		t.Fatal("Uninstalling watcher failed.")
	}
	t.Logf("watch add after uninstalling watcher")
	r.add(target_match, nil, nil)
	checkWatcher(t, w, false)
}

func TestSubRule(t *testing.T) {
	r := newRules()

	t.Logf("Sub rules extraction test. Adding %d entries\n", num_vifs)
	for i := 0; i < num_vifs; i++ {
		r.add(vif_match, []uint64{uint64(i)}, nil)
	}

	t.Log("extract sub rule")
	sr := r.SubRules(vif_match)
	if len(sr) != num_vifs {
		t.Fatalf("Number of entry doesn't match (%d != %d)", len(sr), num_vifs)
	}
	t.Logf("Subrule: %v", sr)

	t.Log("mark entries found")
	check := make(map[uint64]bool)
	for _, r := range sr {
		if r.Param == nil {
			t.Fatalf("Unexpected entry: %v", r)
		}
		check[r.Param[0]] = true
	}

	t.Log("check if all entry exists")
	for i := 0; i < num_vifs; i++ {
		if !check[uint64(i)] {
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
