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
	"math/rand"
	"testing"
	"time"
)

var vrflist = []string{
	"vrf1",
	"vrf2",
	"vrf3",
}

func TestVRFBasic(t *testing.T) {
	vrfs := make([]*VRF, len(vrflist))
	indices := make([]VRFIndex, len(vrflist))
	check := make(map[string]bool)
	for n, name := range vrflist {
		var err error
		vrfs[n], err = NewVRF(name)
		if err != nil {
			t.Fatalf("NewVRF(%v) failed: %v", name, err)
		}
		check[name] = false
		t.Logf("NewVRF(%s) ok", name)

		indices[n] = vrfs[n].Index()
		t.Logf("VRF index for %s = %d", name, vrfs[n].Index())
	}

	vrfs2 := GetAllVRF()
	if len(vrfs2) != len(vrfs) {
		t.Fatalf("GetAllVRF() didn't return all VRF: registerd %d VRF(s). Got %d VRF(s)", len(vrfs), len(vrfs2))
	}
	for _, v := range vrfs2 {
		check[v.Name()] = true
	}
	for name, found := range check {
		if !found {
			t.Fatalf("Can't find VRF %v", name)
		}
	}
	t.Logf("GetAllVRF() returned all VRF - ok: %v", vrfs2)

	for _, name := range vrflist {
		vrf := GetVRFByName(name)
		if vrf == nil {
			t.Fatalf("Can't find VRF %v", name)
		}
		if vrf.Name() != name {
			t.Fatalf("Wrong VRF retuend by GetVRFByName: requested %v. got %v", name, vrf)
		}
		t.Logf("GetVRFByName(%v) - ok", name)
	}

	for _, n := range indices {
		vrf := GetVRFByIndex(n)
		if vrf == nil {
			t.Fatalf("Can't find VRF with index %v", n)
		}
		if vrf.Index() != n {
			t.Fatalf("Wrong VRF retuend by GetVRFByIndex: requested %d. got %d", n, vrf.Index())
		}
		t.Logf("GetVRFByIndex(%d) - ok", n)
	}

	for _, vrf := range vrfs {
		vrf.Free()
	}
}

func TestVRFIndex(t *testing.T) {
	var vrfs [MaxVRF]*VRF

	oldIndex := -1
	for i := 0; i < MaxVRF; i++ {
		name := fmt.Sprintf("vrf%d", i)
		vrf, err := NewVRF(name)
		if err != nil {
			t.Fatalf("NewVRF(%v) failed: %v", name, err)
		}
		index := int(vrf.Index())
		t.Logf("NewVRF(%v) got index of %d", name, index)
		vrfs[i] = vrf

		if oldIndex == index {
			t.Fatalf("The same index as the old one!")
		}
		oldIndex = index
	}

	// Should faile now
	name := "vrf999999"
	_, err := NewVRF(name)
	if err == nil {
		t.Fatalf("NewVRF(%v) should have failed", name)
	}
	t.Logf("NewVRF(%v), %d-th VRF, failed. Ok.", name, MaxVRF+1)

	// Delete one
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	idx := uint8(r.Uint32() & 0xff)
	index := vrfs[idx].Index()
	t.Logf("Freeing %d-th VRF; index = %d", idx, index)
	vrfs[idx].Free()

	// Create once againg
	vrfs[idx], err = NewVRF(name)
	if err != nil {
		t.Fatalf("NewVRF(%v) failed: %v", name, err)
	}
	if vrfs[idx].Index() != index {
		t.Fatalf("Index seems to be wrong. Not as expected: %d", vrfs[idx].Index())
	}
	t.Logf("Got vacant VRF slot; %d", vrfs[idx].Index())

	for _, vrf := range vrfs {
		vrf.Free()
	}
}

func TestVRFErrorCase(t *testing.T) {
	const badVRF = "badVRF"

	if _, err := NewVRF(badVRF); err == nil {
		t.Fatalf(`NewVRF("%s") should faild`, badVRF)
	} else {
		t.Logf(`NewVRF("%s") failed - ok: %v`, badVRF, err)
	}
}
