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

package hashlist

import "testing"

var d = map[string]string{
	"Key1": "Value1",
	"Key2": "Value2",
	"Key3": "Value3",
	"Key4": "Value4",
}

var hl *HashList

func TestCreateHash(t *testing.T) {
	hl = New()
	if hl == nil {
		t.Fatal("Hash creation failed.")
	}
}

func TestInsertion(t *testing.T) {
	if hl == nil {
		t.Fatal("No Hashlist")
	}

	for k, v := range d {
		if !hl.Add(k, v) {
			t.Fatal("Add() should return true for the first time.")
		} else {
			e := hl.List().Back()
			if e.Value != v {
				t.Fatal("Wasn't added to the tail.")
			}
		}
	}

	check := make(map[string]bool)
	for _, v := range d {
		check[v] = true
	}

	for e := hl.List().Front(); e != nil; e = e.Next() {
		t.Log(e.Value)
		check[e.Value.(string)] = false
	}

	for _, v := range check {
		if v {
			t.Fatalf("%v wasn't registered.", v)
		}
	}
}

func TestFind(t *testing.T) {
	if hl == nil {
		t.Fatal("No Hashlist")
	}

	for k, v := range d {
		e := hl.Find(k)
		if e.Value != v {
			t.Fatalf("key-value doesn't match: got %v instead of %v", e.Value, v)
		}
	}
}

func TestDuplicatedInsertion(t *testing.T) {
	if hl == nil {
		t.Fatal("No Hashlist")
	}

	if hl.Add("Key1", "ValueX") {
		t.Fatal("Add() should return false for the duplicates.")
	} else {
		e := hl.Find("Key1")
		if e.Value != "ValueX" {
			t.Fatalf("Value didn't match with 'ValueX': %v", e.Value)
		}
	}
}

func TestRemoval(t *testing.T) {
	if hl == nil {
		t.Fatal("No Hashlist")
	}

	for k, _ := range d {
		if !hl.Remove(k) {
			t.Fatal("Can't remove %v", k)
		}

		if hl.Remove(k) {
			t.Fatal("Could remove %v after 2nd attempt", k)
		}
	}

	len := hl.List().Len()
	if len != 0 {
		t.Fatal("Item remained after removing all items: %v count remaind.", len)
	}
}
