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

package vxlan

import (
	"fmt"
	"sync"
	"time"

	"github.com/lagopus/vsw/modules/tunnel/log"
)

const (
	// IntervalMillisecond Interval for Ticker.
	IntervalMillisecond uint64 = 1000
	// Interval Interval (type of Duration)
	Interval time.Duration = time.Duration(IntervalMillisecond) * time.Millisecond
	// DefaultAgingTime AgingTime.
	DefaultAgingTime uint64 = 300
	// EventChSize size of eventCh
	EventChSize = 128
)

//// Handler.

// handler handler.
type handler struct {
	eventCh chan []CEventqEntry
	stopCh  chan interface{}
	wg      *sync.WaitGroup
}

func newHandler() *handler {
	return &handler{
		eventCh: make(chan []CEventqEntry, EventChSize),
		stopCh:  make(chan interface{}),
		wg:      &sync.WaitGroup{},
	}
}

func (h *handler) pollEventq() {
	// clean up.
	defer h.wg.Done()

	log.Logger.Debug(0, "Start pollEventq.")

	for {
		select {
		case <-h.stopCh:
			log.Logger.Debug(0, "Stop pollEventq.")
			return
		default:
			// get queue.
			if entries, err := GetEvents(); err == nil {
				if len(entries) != 0 {
					h.eventCh <- entries
				}
			}
		}
	}
}

func (h *handler) listen() {
	// clean up.
	defer h.wg.Done()

	log.Logger.Debug(0, "Start listen.")

	mgr := GetMgr()
	ticker := time.NewTicker(Interval)

	for {
		select {
		case <-ticker.C:
			// aging.
			if err := mgr.fdbAging(); err != nil {
				log.Logger.Err("%v", err)
				return
			}
		case entries := <-h.eventCh:
			for _, entry := range entries {
				switch entry.CmdType() {
				case L2tunCmdLearn:
					/* learn. */
					if err := mgr.fdbLearn(entry.VNI(),
						entry.FDBEntry()); err != nil {
						log.Logger.Err("%v", err)
						return
					}
				case L2tunCmdDel:
					mgr.fdbDelete(entry.VNI(), entry.FDBEntry())
				case L2tunCmdClear:
					mgr.fdbClear(entry.VNI())
				}
			}
		case <-h.stopCh:
			ticker.Stop()
			log.Logger.Debug(0, "Stop listen.")
			return
		}
	}
}

func (h *handler) start() {
	h.wg.Add(1)
	go h.pollEventq()
	h.wg.Add(1)
	go h.listen()
}

func (h *handler) stop() {
	// broadcast stop event.
	close(h.stopCh)
	h.wg.Wait()
}

//// Manager.

// Mgr VXLAN manager.
type Mgr struct {
	fdbs    map[VNI]*FDB
	handler *handler
	lock    sync.Mutex
}

var vxlanMgr = newVXLANMgr()

func newVXLANMgr() *Mgr {
	mgr := &Mgr{
		fdbs: map[VNI]*FDB{},
	}
	return mgr
}

func (mgr *Mgr) fdbLearn(vni VNI, entry *CFDBEntry) error {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	if fdb, ok := mgr.fdbs[vni]; ok {
		fdb.Learn(entry.MacAddr(), entry.RemoteIP())
	} else {
		err := fmt.Errorf("Not found FDB: VNI = %v", vni)
		log.Logger.Err("%v", err)
		return err
	}
	return nil
}

func (mgr *Mgr) fdbDelete(vni VNI, entry *CFDBEntry) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	if fdb, ok := mgr.fdbs[vni]; ok {
		fdb.Delete(entry.MacAddr())
	}
}

func (mgr *Mgr) fdbClear(vni VNI) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	if fdb, ok := mgr.fdbs[vni]; ok {
		fdb.Clear()
	}
}

func (mgr *Mgr) fdbAging() error {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	for _, fdb := range mgr.fdbs {
		if err := fdb.Aging(); err != nil {
			log.Logger.Err("%v", err)
			return err
		}
	}
	return nil
}

// Public.

// NewFDB Create FDB. And Start handler.
func (mgr *Mgr) NewFDB(vni VNI, agingTime uint64, ctrlFunc ControlFunc) error {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	if _, ok := mgr.fdbs[vni]; ok {
		err := fmt.Errorf("Already exists FDB: VNI = %v", vni)
		log.Logger.Err("%v", err)
		return err
	}

	agingTimeSecond := time.Duration(agingTime) * time.Second
	mgr.fdbs[vni] = NewFDB(VNI(vni), agingTimeSecond, ctrlFunc)

	if mgr.handler == nil {
		mgr.handler = newHandler()
		mgr.handler.start()
	}

	return nil
}

// DeleteFDB Delete FDB. And Stop handler.
func (mgr *Mgr) DeleteFDB(vni VNI) {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	delete(mgr.fdbs, vni)

	if len(mgr.fdbs) == 0 {
		mgr.handler.stop()
		mgr.handler = nil
	}
}

// GetMgr Get manager.
func GetMgr() *Mgr {
	return vxlanMgr
}
