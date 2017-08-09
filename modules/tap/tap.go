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

package tap

import (
	nlagent "github.com/lagopus/vsw/agents/netlink"
	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/vswitch"
	"os"
	"reflect"
	"runtime"
	"sync"
	"time"
)

const (
	tapMaxRetryCount = 100
	tapRetryInterval = 100 * time.Millisecond
)

var log = vswitch.Logger

type vif struct {
	output *dpdk.Ring
	tap    *os.File
	ch     chan *dpdk.Mbuf
}

type TapModule struct {
	vswitch.ModuleService
	running bool
	pool    *dpdk.MemPool
	input   *dpdk.Ring
	indices map[vswitch.VifIndex]int
	vifs    []vif
	stop    chan struct{}
	wg      sync.WaitGroup
}

func newTap(p *vswitch.ModuleParam) (vswitch.Module, error) {
	module := &TapModule{
		ModuleService: vswitch.NewModuleService(p),
		pool:          vswitch.GetDpdkResource().Mempool,
		indices:       make(map[vswitch.VifIndex]int),
	}
	return module, nil
}

func (tm *TapModule) Control(cmd string, v interface{}) interface{} {
	return false
}

func newCase(v interface{}) reflect.SelectCase {
	return reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(v)}
}

func (tm *TapModule) txTask() {
	len := len(tm.vifs)
	cases := make([]reflect.SelectCase, len+1)
	for i, vif := range tm.vifs {
		cases[i] = newCase(vif.ch)
	}
	cases[len] = newCase(tm.stop)

	for {
		chosen, value, ok := reflect.Select(cases)
		if !ok {
			// Stop requested
			if chosen == len {
				tm.wg.Done()
				return
			}
			cases[chosen].Chan = reflect.ValueOf(nil)
			continue
		}
		if mbuf, ok := value.Interface().(*dpdk.Mbuf); ok {
			//			log.Printf("%v: Forwarding packet to %d.", tm, chosen)
			tm.vifs[chosen].output.EnqueueMbuf(mbuf)
		}
	}
}

func (tm *TapModule) readFromTap(vidx vswitch.VifIndex) {
	// MAC Header (14 Bytes) + MTU
	buf := make([]byte, vswitch.GetVifInfo(vidx).MTU()+14)

	index := tm.indices[vidx]
	ch := tm.vifs[index].ch
	tap := tm.vifs[index].tap

	for {
		// XXX: We may want to imporove this by passing the pointer to
		// data directly. We then will need to update data_len of the
		// Mbuf.
		n, err := tap.Read(buf)
		if err != nil {
			log.Printf("%v: Read from Tap failed: %v", tm, err)
			return
		}

		if mbuf := tm.pool.AllocMbuf(); mbuf != nil {
			mbuf.SetData(buf[:n])
			ch <- mbuf
		} else {
			log.Printf("%v: %d bytes packet from tap of VIF %d dropped. No Mbuf.", tm, n, vidx)
		}
	}
}

func (tm *TapModule) rxTask() {
	input := tm.input
	mbufs := make([]*dpdk.Mbuf, queueLength)
	for tm.running {
		n := input.DequeueBurstMbufs(&mbufs)
		for _, mbuf := range mbufs[:n] {
			md := (*vswitch.Metadata)(mbuf.Metadata())
			index := tm.indices[md.InVIF()]
			tap := tm.vifs[index].tap
			frame := mbuf.Data()
			_, err := tap.Write(frame)
			mbuf.Free()
			if err != nil {
				log.Printf("%v: Write to Tap failed: %v", tm, err)
				return
			}
			//			log.Printf("%v: Written %d bytes packet to tap of VIF %d.", tm, len(frame), md.InVIF())
		}
		runtime.Gosched()
	}
	tm.wg.Done()
}

const queueLength = 64

func (tm *TapModule) Start() bool {
	log.Printf("%v: Start()", tm)

	tm.input = tm.Input()
	if tm.input == nil {
		log.Printf("%v: Input ring not specified.", tm)
		return false
	}

	rules := tm.Rules().SubRules(vswitch.MATCH_OUT_VIF)

	if len(rules) == 0 {
		log.Printf("%v: No outputs specified.", tm)
		return false
	}

	tm.vifs = make([]vif, len(rules))
	for n, rule := range rules {
		vifidx := vswitch.VifIndex(rule.Param[0])

		var tap *os.File
		ok := false
		for i := 0; i < tapMaxRetryCount; i++ {
			tap, ok = nlagent.GetTapFile(vifidx)
			if ok {
				break
			}
			time.Sleep(tapRetryInterval)
		}

		if !ok {
			log.Fatalf("%v: No tap for VIF %v", tm, vifidx)
		}

		tm.indices[vifidx] = n
		tm.vifs[n] = vif{rule.Ring, tap, make(chan *dpdk.Mbuf)}

		go tm.readFromTap(vifidx)
	}

	// launch
	tm.running = true
	tm.stop = make(chan struct{})
	go tm.txTask()
	go tm.rxTask()

	return true
}

func (tm *TapModule) Stop() {
	tm.wg.Add(2)
	for _, vif := range tm.vifs {
		vif.tap.Close()
	}
	close(tm.stop)
	tm.running = false
}

func (tm *TapModule) Wait() {
	tm.wg.Wait()
}

func (tm *TapModule) String() string {
	return tm.Name()
}

func init() {
	rp := &vswitch.RingParam{
		Count:    queueLength,
		SocketId: dpdk.SOCKET_ID_ANY,
		Flags:    0,
	}

	if !vswitch.RegisterModule("tap", newTap, rp, vswitch.TypeOther) {
		log.Fatalf("Failed to register Tap class.")
	}
}
