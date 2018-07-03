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

package ipip

import (
	"strconv"
	"testing"
)

func TestAddDeleteTunnelIF(t *testing.T) {
	iface, err := mgr.addTunnelIF("ifIn", nil, nil)

	if iface == nil || err != nil {
		t.Fatalf("addTunnelIF error: %v\n", err)
	}

	if len(mgr.ifTable) != 1 {
		t.Fatalf("ifTable size error: %d\n", len(mgr.ifTable))
	}

	if mgr.freeIndexes.Len() != (maxTunnels - 1) {
		t.Fatalf("freeIndexes size error: %d\n", mgr.freeIndexes.Len())
	}

	mgr.deleteTunnelIF(iface.index)

	if len(mgr.ifTable) != 0 {
		t.Fatalf("ifTable size error: %d\n", len(mgr.ifTable))
	}

	if mgr.freeIndexes.Len() != maxTunnels {
		t.Fatalf("freeIndexes size error: %d\n", mgr.freeIndexes.Len())
	}
}

func TestAddTunnelIFMax(t *testing.T) {
	// add max TunnelIF
	for i := 1; i <= maxTunnels; i++ {
		iface, err := mgr.addTunnelIF("ifIn" + strconv.Itoa(i), nil, nil)
		if iface == nil || err != nil {
			t.Fatalf("addTunnelIF error: %v\n", err)
		}
	}
	if len(mgr.ifTable) != maxTunnels {
		t.Fatalf("ifTable size error: %d\n", len(mgr.ifTable))
	}
	if mgr.freeIndexes.Len() != 0 {
		t.Fatalf("freeIndexes size error: %d\n", mgr.freeIndexes.Len())
	}

	if _, err := mgr.addTunnelIF("invalidIF", nil, nil); err == nil {
		t.Fatalf("no error occurred\n")
	}

	// delete all TunnelIF
	for i := 1; i <= maxTunnels; i++ {
		mgr.deleteTunnelIF(uint16(i))
	}
	if len(mgr.ifTable) != 0 {
		t.Fatalf("ifTable size error: %d\n", len(mgr.ifTable))
	}
	if mgr.freeIndexes.Len() != maxTunnels {
		t.Fatalf("freeIndexes size error: %d\n", mgr.freeIndexes.Len())
	}
}

func TestDeleteTunnelIFMin(t *testing.T) {
	mgr.deleteTunnelIF(1)

	if len(mgr.ifTable) != 0 {
		t.Fatalf("ifTable size error: %d\n", len(mgr.ifTable))
	}

	if mgr.freeIndexes.Len() != maxTunnels {
		t.Fatalf("freeIndexes size error: %d\n", mgr.freeIndexes.Len())
	}
}
