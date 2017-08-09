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
	"bytes"
	"fmt"
	"github.com/lagopus/vsw/utils/notifier"
	"net"
	"sync"
)

type NudState int

const (
	NudStateNone       NudState = 0x00
	NudStateIncomplete          = 0x01
	NudStateReachable           = 0x02
	NudStateStale               = 0x04
	NudStateDelay               = 0x08
	NudStateProbe               = 0x10
	NudStateFailed              = 0x20
	NudStateNoArp               = 0x40
	NudStatePermanent           = 0x80
)

var nudStateStrings = map[NudState]string{
	NudStateNone:       "None",
	NudStateIncomplete: "Incomplete",
	NudStateReachable:  "Reachable",
	NudStateStale:      "Stale",
	NudStateDelay:      "Delay",
	NudStateProbe:      "Probe",
	NudStateFailed:     "Failed",
	NudStateNoArp:      "NoArp",
	NudStatePermanent:  "Permanent",
}

func (ns NudState) String() string { return nudStateStrings[ns] }

// NeighbourEntry
type Neighbour struct {
	Dst           net.IP
	LinkLocalAddr net.HardwareAddr
	State         NudState
}

type DstKey [16]byte

func (n Neighbour) String() string {
	return fmt.Sprintf("%v %v %v", n.Dst, n.LinkLocalAddr, n.State)
}

func genDstKey(ip net.IP) DstKey {
	var key DstKey
	copy(key[:], ip)
	return key
}

func (n Neighbour) dstKey() DstKey {
	return genDstKey(n.Dst)
}

type Neighbours struct {
	container interface{}
	entries   map[DstKey]Neighbour
	mutex     sync.RWMutex
}

func newNeighbours(container interface{}) *Neighbours {
	return &Neighbours{
		container: container,
		entries:   make(map[DstKey]Neighbour),
	}
}

func (n *Neighbours) AddEntry(entry Neighbour) bool {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	dstkey := entry.dstKey()

	nt := notifier.Add
	if oldEntry, exists := n.entries[dstkey]; exists {
		if bytes.Compare(oldEntry.LinkLocalAddr, entry.LinkLocalAddr) == 0 &&
			oldEntry.State == entry.State {
			return true // no changes
		}
		nt = notifier.Update
	}
	n.entries[dstkey] = entry
	noti.Notify(nt, n.container, entry)
	return true
}

func (n *Neighbours) DeleteEntry(dst net.IP) bool {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	dstkey := genDstKey(dst)
	entry, exists := n.entries[dstkey]
	if !exists {
		return false // doesn't exist
	}
	delete(n.entries, dstkey)
	noti.Notify(notifier.Delete, n.container, entry)
	return true
}

func (n *Neighbours) ListEntries() []Neighbour {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	list := make([]Neighbour, len(n.entries))
	i := 0
	for _, e := range n.entries {
		list[i] = e
		i++
	}
	return list
}
