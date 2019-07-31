//
// Copyright 2017-2019 Nippon Telegraph and Telephone Corporation.
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

package dummymat

import (
	"runtime"
	"sync"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/notifier"
	"github.com/lagopus/vsw/vswitch"
	vlog "github.com/lagopus/vsw/vswitch/log"
)

const (
	moduleName = "dummymat"
)

var log = vswitch.Logger

type DummyMATInstance struct {
	base    *vswitch.BaseInstance
	noti    *notifier.Notifier
	notiCh  chan notifier.Notification
	enabled bool
	done    chan int
	bridges map[vswitch.VID]*dpdk.Ring
	mutex   sync.RWMutex
}

func newDummyMATInstance(base *vswitch.BaseInstance, p interface{}) (vswitch.Instance, error) {
	d := &DummyMATInstance{
		base:    base,
		noti:    base.Rules().Notifier(),
		done:    make(chan int),
		bridges: make(map[vswitch.VID]*dpdk.Ring),
	}
	d.notiCh = d.noti.Listen()
	go d.listener()
	return d, nil
}

func (d *DummyMATInstance) listener() {
	for n := range d.notiCh {
		rule, ok := n.Value.(vswitch.Rule)
		if !ok || rule.Match != vswitch.MatchVID {
			log.Printf("%s: Unexpected rule: %v", d.base.Name(), rule)
			continue
		}

		vid, ok := rule.Param.(vswitch.VID)
		if !ok {
			log.Printf("%s: Unexpected param: %v", d.base.Name(), vid)
			continue
		}

		d.mutex.Lock()
		switch n.Type {
		case notifier.Add:
			log.Printf("%s: VID %v added", d.base.Name(), vid)
			d.bridges[vid] = rule.Ring
		case notifier.Delete:
			log.Printf("%s: VID %v deleted", d.base.Name(), vid)
			delete(d.bridges, vid)
		}
		d.mutex.Unlock()
	}
}

func (d *DummyMATInstance) process() {
	input := d.base.Input()
	mbufs := make([]*dpdk.Mbuf, 512)

	for d.enabled {
		if rxc := int(input.DequeueBurstMbufs(&mbufs)); rxc > 0 {
			d.mutex.RLock()
			for i := 0; i < rxc; i++ {
				mbuf := mbufs[i]
				vid := vswitch.VID(mbuf.VlanTCI())

				log.Printf("%s: received packet from vid %v", d.base.Name(), vid)

				// Do something here
				sent := false
				for v, output := range d.bridges {
					// pick bridge that doesn't match to the mbuf's vid
					if v != vid {
						// rewrite VID
						mbuf.SetVlanTCI(uint16(v))
						if output.EnqueueMbuf(mbuf) == 0 {
							log.Printf("%s: forwarding to vid %v", d.base.Name(), v)
							sent = true
						} else {
							// failed. set VID back.
							mbuf.SetVlanTCI(uint16(vid))
						}
						break
					}
				}

				if !sent {
					// send it back to its origin
					log.Printf("%s: sending back to vid %v", d.base.Name(), vid)
					if d.bridges[vid].EnqueueMbuf(mbuf) != 0 {
						mbuf.Free()
					}
				}
			}
			d.mutex.RUnlock()
		}
		runtime.Gosched()
	}
	d.done <- 0
}

func (d *DummyMATInstance) Enable() error {
	log.Printf("%s: Enable()", d.base.Name())
	d.enabled = true
	go d.process()
	return nil
}

func (d *DummyMATInstance) Disable() {
	log.Printf("%s: Disable()", d.base.Name())
	d.enabled = false
	<-d.done
}

func (d *DummyMATInstance) Free() {
}

/*
 * Do module registration here.
 */
func init() {
	if l, err := vlog.New(moduleName); err == nil {
		log = l
	} else {
		log.Fatalf("Can't create logger: %s", moduleName)
	}

	if err := vswitch.RegisterModule("mat", newDummyMATInstance, nil, vswitch.TypeOther); err != nil {
		log.Fatalf("Failed to register the class: %v", err)
	}
}
