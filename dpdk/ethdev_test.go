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

func TestEthDevEnumerate(t *testing.T) {
	var err error

	count := int(EthDevCount())
	t.Logf("Found %d devices", count)

	names := make([]string, count)
	for i := 0; i < count; i++ {
		names[i], err = EthDevGetNameByPort(uint(i))
		if err != nil {
			t.Errorf("Error getting name for port %d: %v", i, err)
			continue
		}
		t.Logf("Port %d: %s", i, names[i])
	}

	for port, name := range names {
		p, err := EthDevGetPortByName(name)
		if err != nil {
			t.Errorf("Error getting port for name %s: %v", name, err)
			continue
		}
		t.Logf("%s: port %d", name, p)
		if int(p) != port {
			t.Errorf("Port doesn't match for %s (%d != %d)", name, p, port)
		}
	}
}
