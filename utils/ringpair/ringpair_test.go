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

package ringpair

import (
	"flag"
	"github.com/lagopus/vsw/dpdk"
	"os"
	"testing"
	"unsafe"
)

var pool *dpdk.MemPool

func checkRing(t *testing.T, ring *dpdk.Ring) bool {
	snd := pool.AllocMbuf()
	rc := ring.Enqueue(unsafe.Pointer(snd))
	if rc != 0 {
		t.Fatal("Enqueue() returned %v", rc)
		return false
	}

	var rcv *dpdk.Mbuf
	xrcv := unsafe.Pointer(rcv)
	rc = ring.Dequeue(&xrcv)
	if rc != 0 {
		t.Fatal("Dequeue() returned %v", rc)
		return false
	}
	if snd != (*dpdk.Mbuf)(xrcv) {
		t.Fatal("Didn't get the same buffer...")
		return false
	}

	return true
}

func TestDefaultRing(t *testing.T) {
	rp := Create(nil)

	for i, r := range rp.Rings {
		if r == nil {
			t.Fatal("Rings[%d] == nil", i)
		}
		if i > 1 {
			t.Fatal("More than 2 rings created.")
		}

		if !checkRing(t, r) {
			t.Fatal("Ring test failed...")
		}
	}

	if rp.Config == nil {
		t.Fatal("No config supplied")
	}

	rp2 := Create(nil)
	if rp2.Config == rp.Config {
		t.Fatal("The same config instance.")
	}
}

func TestMain(m *testing.M) {
	args := []string{"test", "-v", "-c", "0xff", "-n", "2"}
	dpdk.EalInit(args)

	pool = dpdk.PktMbufPoolCreate("pool", 128, 0, 0, dpdk.RTE_PKTMBUF_HEADROOM, dpdk.SOCKET_ID_ANY)
	if pool == nil {
		os.Exit(1)
	}

	flag.Parse()
	os.Exit(m.Run())

}
