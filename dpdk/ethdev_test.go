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

	t.Logf("Testing EthDevGetNameByPort()")
	names := make([]string, count)
	for i := 0; i < count; i++ {
		names[i], err = EthDevGetNameByPort(uint16(i))
		if err != nil {
			t.Errorf("Error getting name for port %d: %v", i, err)
			continue
		}
		t.Logf("Port %d: %s", i, names[i])
	}

	t.Logf("Testing EthDevGetPortByName()")
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

	t.Logf("Testing EthDevOpenByName()")
	for _, name := range names {
		dev, err := EthDevOpenByName(name)
		if err == nil {
			t.Logf("%v: %v", name, dev.PortID())
		} else {
			t.Fatalf("Device %v: %v", name, err)
		}
	}

}

func TestEthDevSocketID(t *testing.T) {
	count := int(EthDevCount())
	for i := 0; i < count; i++ {
		dev, err := EthDevOpen(uint16(i))
		if err == nil {
			t.Logf("Port %v (%v): Socket %v", i, dev.PortID(), dev.SocketID())
		} else {
			t.Fatalf("Port %v: %v", i, err)
		}
	}
}
