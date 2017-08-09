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

import (
	"fmt"
	"testing"
	"time"
)

func compareMbufs(b1, b2 []*Mbuf, count int) bool {
	for i := 0; i < count; i++ {
		if *b1[i] != *b2[i] {
			return false
		}
	}
	return true
}

func createRingAndPool() (*Ring, *MemPool) {
	ring := RingCreate("basic", 1024, SOCKET_ID_ANY, RING_F_SC_DEQ)
	if ring == nil {
		return nil, nil
	}

	pool := PktMbufPoolCreate("pool", 128, 0, 0, RTE_PKTMBUF_HEADROOM, SOCKET_ID_ANY)
	if pool == nil {
		ring.Free()
		return nil, nil
	}

	return ring, pool
}

const MBUF_COUNT = 10

func TestBasicRing(t *testing.T) {
	ring, pool := createRingAndPool()
	if ring == nil || pool == nil {
		t.Fatalf("Creating Ring or PktMbuf pool failed.")
	}

	mbufs := make([]*Mbuf, MBUF_COUNT)
	for i := 0; i < MBUF_COUNT; i++ {
		mbufs[i] = pool.AllocMbuf()
	}
	count := ring.EnqueueBurstMbufs(mbufs)
	fmt.Printf("tx count=%d\n", count)

	bufs := make([]*Mbuf, MBUF_COUNT*2)
	count = ring.DequeueBurstMbufs(&bufs)
	fmt.Printf("rx count=%d\n", count)

	if compareMbufs(mbufs, bufs, int(count)) {
		fmt.Printf("All mbuf matched.\n")
	} else {
		t.Fatalf("mbuf didn't match.\n")
	}

	for _, m := range mbufs {
		m.Free()
	}
	mbufs = nil

	// clean up
	ring.Free()
	pool.Free()
}

func TestBasicRingWithBulk(t *testing.T) {
	ring, pool := createRingAndPool()
	if ring == nil || pool == nil {
		t.Fatalf("Creating Ring or PktMbuf pool failed.")
	}

	mbufs := pool.AllocBulkMbufs(MBUF_COUNT)
	fmt.Printf("%d mbuf(s) allocated\n", len(mbufs))

	for i, m := range mbufs {
		fmt.Printf("%d: @%v\n", i, m.buf_addr)
	}

	count := ring.EnqueueBurstMbufs(mbufs)
	fmt.Printf("tx count=%d\n", count)

	bufs := make([]*Mbuf, MBUF_COUNT*2)
	count = ring.DequeueBurstMbufs(&bufs)
	fmt.Printf("rx count=%d\n", count)

	if compareMbufs(mbufs, bufs, int(count)) {
		fmt.Printf("All mbuf matched.\n")
	} else {
		t.Fatalf("mbuf didn't match.\n")
	}

	for _, m := range mbufs {
		m.Free()
	}
	mbufs = nil

	ring.Free()
	pool.Free()
}

func receiver(ring *Ring, expect int, c chan int) {
	bufs := make([]*Mbuf, expect)
	count := 0

	c <- 0

	fmt.Printf("waiting to receive...\n")
	for count < expect {
		ct := int(ring.DequeueBurstMbufs(&bufs))
		fmt.Printf("got %d.\n", ct)
		count += ct
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Printf("rx count=%d\n", count)

	c <- count
}

func TestMultiThread(t *testing.T) {
	ring, pool := createRingAndPool()
	if ring == nil || pool == nil {
		t.Fatalf("Creating Ring or PktMbuf pool failed.")
	}

	c := make(chan int)

	go receiver(ring, MBUF_COUNT, c)

	_ = <-c

	fmt.Printf("receiver is ready.\n")

	mbufs := pool.AllocBulkMbufs(MBUF_COUNT)
	count := ring.EnqueueBurstMbufs(mbufs)
	fmt.Printf("tx count=%d\n", count)

	rx := <-c
	fmt.Printf("receiver got %d count.\n", rx)

	ring.Free()
	pool.Free()
}
