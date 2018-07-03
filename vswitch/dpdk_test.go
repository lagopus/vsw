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
	"testing"
	"time"

	"github.com/lagopus/vsw/dpdk"
)

func getSc(dr *DpdkResource, ch chan uint) {
	sc, _ := dr.AllocLcore("test")
	ch <- sc
}

func waitAll(t *testing.T, ch chan uint) []uint {
	var sc []uint

	timeout := time.After(time.Second)
	for {
		select {
		case c := <-ch:
			t.Logf("Got core %d.\n", c)
			sc = append(sc, c)
		case <-timeout:
			return sc
		}
	}
}

func TestLcore(t *testing.T) {
	count := int(dpdk.LcoreCount())

	dr := GetDpdkResource()

	// Should success Lcore - 1st time
	var sc []uint
	for i := 0; i < count; i++ {
		c, err := dr.AllocLcore("test")
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

	sc = waitAll(t, rc)
	t.Logf("Got %d cores: %v", len(sc), sc)

	for _, c := range sc {
		dr.FreeLcore(c)
	}

	t.Logf("Returned all lcore")
}
