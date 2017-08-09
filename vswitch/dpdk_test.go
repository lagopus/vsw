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
	"github.com/lagopus/vsw/dpdk"
	"testing"
)

func getSc(dr *DpdkResource, ch chan uint) {
	sc, _ := dr.AllocLcore()
	ch <- sc
	if sc == 0 {
		close(ch)
	}
}

func TestLcore(t *testing.T) {
	count := int(dpdk.LcoreCount())

	dr := GetDpdkResource()

	// Should success Lcore - 1 times
	var sc []uint
	for i := 0; i < count; i++ {
		c, err := dr.AllocLcore()
		t.Logf("Got core %d. err=%v\n", c, err)
		if err == nil {
			sc = append(sc, c)
		}
	}

	// put back
	for _, c := range sc {
		t.Logf("Putting back %d.\n", c)
		dr.FreeLcore(c)
	}

	// we now should all back again
	rc := make(chan uint)
	for i := 0; i < count; i++ {
		go getSc(dr, rc)
	}

	for v := range rc {
		t.Logf("Got core %d.\n", v)
	}
}
