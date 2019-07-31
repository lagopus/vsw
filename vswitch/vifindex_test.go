//
// Copyright 2019 Nippon Telegraph and Telephone Corporation.
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

import "testing"

func TestVIFIndex(t *testing.T) {
	// reset vifIdxMgr
	vifIdxMgr.reset()

	dummy := &VIF{}

	indices := make(map[VIFIndex]struct{})

	// OK cases
	for i := 1; i <= MaxVIFIndex; i++ {
		idx, err := vifIdxMgr.allocVIFIndex(dummy)

		if err != nil {
			t.Fatalf("Allocating VIFIndex failed at %d-th try: %v", idx, err)
		}

		if _, ok := indices[idx]; ok {
			t.Fatalf("Duplicated VIFIndex %d found", idx)
		}

		indices[idx] = struct{}{}
	}

	t.Logf("Successively allocated %d VIF indices", len(indices))

	// Bad cases
	idx, err := vifIdxMgr.allocVIFIndex(dummy)
	if err == nil {
		t.Fatalf("VIFIndex %d allocated after limit %d-th VIFIndex", idx, MaxVIFIndex)
	}

	// Free invalid vif index
	if err := vifIdxMgr.freeVIFIndex(InvalidVIFIndex); err == nil {
		t.Fatalf("Can free InvalidVIFIndex")
	}

	// Free out of range vif index
	if err := vifIdxMgr.freeVIFIndex(9999); err == nil {
		t.Fatalf("Can free VIFIndex 9999")
	}

	// Free one index
	idx = 1234
	if err := vifIdxMgr.freeVIFIndex(idx); err != nil {
		t.Fatalf("Can't free VIFIndex %d: %v", idx, err)
	}

	// Free again
	if err := vifIdxMgr.freeVIFIndex(idx); err == nil {
		t.Fatalf("Could free freed VIFIndex %d", idx)
	}

	// Check if the VIFIndex is reused properly
	idx2, err := vifIdxMgr.allocVIFIndex(dummy)
	if err != nil {
		t.Fatalf("Can't allocate VIFIndex: %v", err)
	}

	if idx2 != idx {
		t.Fatalf("VIFIndex hasn't been reused: expected %v != got %v", idx, idx2)
	}

	t.Logf("VIFIndex %d reused.", idx)

	// reset vifIdxMgr
	vifIdxMgr.reset()
}
