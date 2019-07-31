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
	"container/list"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lagopus/vsw/modules/tunnel/log"
)

const (
	// MacAddressLen Length of mac addr.
	MacAddressLen = 6
)

// MacAddress MAC Address.
// NOTE: net.HardwareAddr is not in key of map[].
type MacAddress [MacAddressLen]byte

const hexDigit = "0123456789abcdef"

func (m MacAddress) String() string {
	buf := make([]byte, 0, len(m)*3-1)
	for i, b := range m {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigit[b>>4])
		buf = append(buf, hexDigit[b&0xF])
	}

	return string(buf)
}

// VNI VNI.
type VNI uint32

// Entry Entry of FDB.
type Entry struct {
	MacAddr  MacAddress
	RemoteIP net.IP
	lifeTime time.Time
}

func newEntry(mac *MacAddress, ip *net.IP) *Entry {
	return &Entry{
		MacAddr:  *mac,
		RemoteIP: *ip,
	}
}

func (e *Entry) isExpiredLifeTime(now time.Time) bool {
	return !e.lifeTime.IsZero() &&
		e.lifeTime.UnixNano() <= now.UnixNano()
}

func (e *Entry) compareLifeTime(lifeTime time.Time) int {
	t1 := e.lifeTime.UnixNano()
	t2 := lifeTime.UnixNano()
	if t1 > t2 {
		return 1
	} else if t1 < t2 {
		return -1
	}
	return 0
}

func (e *Entry) String() string {
	return fmt.Sprintf("MAC: %v, RemoteIP: %v, LifeTime: %v",
		e.MacAddr, e.RemoteIP, e.lifeTime)
}

// FDB FDB.
type FDB struct {
	vni            VNI
	db             map[MacAddress]*list.Element
	limitedEntries *list.List // Entry with 'lifetime != 0'
	agingTime      time.Duration
	ctrlFunc       ControlFunc
	lock           sync.Mutex
}

// NewFDB Create FDB.
func NewFDB(vni VNI, agingTime time.Duration, ctrlFunc ControlFunc) *FDB {
	return &FDB{
		vni:            vni,
		db:             map[MacAddress]*list.Element{},
		limitedEntries: list.New(),
		agingTime:      agingTime,
		ctrlFunc:       ctrlFunc,
	}
}

func (f *FDB) doControl(param *ControlParam) error {
	if f.ctrlFunc != nil {
		return f.ctrlFunc(param)
	}

	err := fmt.Errorf("Control func is nil")
	log.Logger.Err("%v", err)
	return err
}

func (f *FDB) deleteNoLock(mac *MacAddress) {
	if e, ok := f.db[*mac]; ok {
		f.limitedEntries.Remove(e)
		delete(f.db, *mac)
	}
}

func (f *FDB) setAgingTime(d time.Duration) {
	f.lock.Lock()
	defer f.lock.Unlock()

	f.agingTime = d
}

// Public.

// Learn Learn entry.
func (f *FDB) Learn(mac *MacAddress, ip *net.IP) {
	f.lock.Lock()
	defer f.lock.Unlock()

	var entry *Entry
	if e, ok := f.db[*mac]; ok {
		entry = e.Value.(*Entry)
		// found.
		if !entry.RemoteIP.Equal(*ip) {
			entry.RemoteIP = *ip
		}
		// NOTE: Although it has already been deleted in Aging(),
		//       it is deleted for safety.
		f.limitedEntries.Remove(e)
		log.Logger.Debug(0, "FDB(VNI = %v): Learn(update): %v", f.vni, mac)
	} else {
		// not found.
		entry = newEntry(mac, ip)
		log.Logger.Debug(0, "FDB(VNI = %v): Learn(new): %v", f.vni, mac)
	}

	var lifeTime time.Time
	var e *list.Element
	if f.agingTime == 0 {
		/* unlimited entry. */
		e = &list.Element{
			Value: entry,
		}
	} else {
		/* limited entry. */
		lifeTime = time.Now().Add(f.agingTime)

		// NOTE: Even if entry already exists, recreate it.
		//       Because Can't be reused
		//       when limitedEntries.Remove() is executed in Aging().
		if f.limitedEntries.Len() == 0 {
			// no elements yet.
			e = f.limitedEntries.PushBack(entry)
		} else {
			// element already exists.
			for e1 := f.limitedEntries.Back(); e1 != nil; e1 = e1.Prev() {
				entry1 := e1.Value.(*Entry)
				if entry1.compareLifeTime(lifeTime) <= 0 {
					e = f.limitedEntries.InsertAfter(entry, e1)
					break
				}
			}
			if e == nil {
				e = f.limitedEntries.PushFront(entry)
			}
		}
	}

	f.db[*mac] = e
	entry.lifeTime = lifeTime

	log.Logger.Debug(0, "FDB(VNI = %v): Learn: %v", f.vni, entry)
}

// Delete Delete entry.
func (f *FDB) Delete(mac *MacAddress) {
	f.lock.Lock()
	defer f.lock.Unlock()

	f.deleteNoLock(mac)

	log.Logger.Debug(0, "FDB(VNI = %v): Delete: %v", f.vni, mac)
}

// Clear Clear entries.
func (f *FDB) Clear() {
	f.lock.Lock()
	defer f.lock.Unlock()

	for m := range f.db {
		f.deleteNoLock(&m)
	}

	log.Logger.Debug(0, "FDB(VNI = %v): Clear", f.vni)
}

// Aging Aging.
func (f *FDB) Aging() error {
	f.lock.Lock()
	defer f.lock.Unlock()

	now := time.Now()

	// limitedEntries is orders.
	for e := f.limitedEntries.Front(); e != nil; e = e.Next() {
		entry := e.Value.(*Entry)
		if entry.isExpiredLifeTime(now) {
			// send AGING msg.
			centry := Entry2CFDBEntry(entry)
			param := centry.NewControlParam(L2tunCmdAging)
			if err := f.doControl(param); err != nil {
				log.Logger.Err("%v", err)
				return err
			}

			f.limitedEntries.Remove(e)
			log.Logger.Debug(0, "FDB(VNI = %v): Aging: %v", f.vni, entry)
		} else {
			// entries is orders. It has not expired after this.
			return nil
		}
	}
	return nil
}
