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

package dpdk

import "testing"

func TestLcore(t *testing.T) {
	mc := GetMasterLcore()
	t.Logf("MasterLcore = %d", mc)

	id := LcoreId()
	t.Logf("LcoreID = %d", id)

	t.Logf("Count = %d", LcoreCount())
}

func TestEnumLcore(t *testing.T) {
	master := GetMasterLcore()
	sockets := make(map[uint]struct{})
	n := uint(0)
	for n < MaxLcore {
		if n != master && LcoreIsEnabled(n) {
			t.Logf("slave lcore %d is enabled.\n", n)
			sockets[LcoreToSocketId(n)] = struct{}{}
		}
		n++
	}

	// sockets
	t.Logf("Found sockets:\n")
	for sid := range sockets {
		t.Logf("socket %d\n", sid)
	}
}
