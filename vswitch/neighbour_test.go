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
	"net"
	"testing"

	"github.com/lagopus/vsw/utils/notifier"
)

type testNeighClass struct {
	name string
	*Neighbours
}

func TestNeighbours(t *testing.T) {
	c := &testNeighClass{name: "test"}
	c.Neighbours = newNeighbours(c)

	ch := GetNotifier().Listen()
	defer GetNotifier().Close(ch)
	//	go listener(t, ch)

	mac, _ := net.ParseMAC("01:23:45:67:89:ab")
	entry := Neighbour{net.IPv4(192, 168, 1, 1), mac, NudStateReachable}
	c.AddEntry(entry)
	t.Log(c.ListEntries())

	// expect add
	if ok, noti := checkNoti(ch, notifier.Add, c, entry); !ok {
		t.Errorf("Got %v. Expected %v, %v, %v\n", noti, notifier.Add, c, entry)
	} else {
		t.Log("Notificaiton ok.")
	}

	// expect nop
	c.AddEntry(entry)
	if ok, noti := checkNoti(ch, notifier.Add, c, entry); ok {
		t.Errorf("Got %v. Expected timeout.", noti)
	} else {
		t.Log("Timeout. Ok.")
	}

	// expect update
	entry.State = NudStateStale
	c.AddEntry(entry)
	t.Log(c.ListEntries())

	if ok, noti := checkNoti(ch, notifier.Update, c, entry); !ok {
		t.Errorf("Got %v. Expected %v, %v, %v\n", noti, notifier.Update, c, entry)
	} else {
		t.Log("Notificaiton ok.")
	}

	// expect update again
	entry.LinkLocalAddr, _ = net.ParseMAC("fe:dc:ba:98:76:54")
	c.AddEntry(entry)
	t.Log(c.ListEntries())

	if ok, noti := checkNoti(ch, notifier.Update, c, entry); !ok {
		t.Errorf("Got %v. Expected %v, %v, %v\n", noti, notifier.Update, c, entry)
	} else {
		t.Log("Notificaiton ok.")
	}

	// expect to add more
	var entries = make([]Neighbour, 10)
	mac, _ = net.ParseMAC("01:23:45:67:89:ab")
	for n := 0; n < 10; n++ {
		entries[n] = Neighbour{net.IPv4(192, 168, 1, byte(n+2)), mac, NudStateReachable}
		c.AddEntry(entries[n])

		count := len(c.ListEntries())
		if count != n+2 {
			t.Errorf("# of entries doesn't match the expected number. (%d vs %d)", count, n+2)
		}

		if ok, noti := checkNoti(ch, notifier.Add, c, entries[n]); !ok {
			t.Errorf("Got %v. Expected %v, %v, %v\n", noti, notifier.Add, c, entries[n])
		} else {
			t.Log("Notificaiton ok.")
		}
	}
	t.Log(c.ListEntries())

	// delete all added
	for n := 0; n < 10; n++ {
		c.DeleteEntry(entries[n].Dst)

		count := len(c.ListEntries())
		if count != 10-n {
			t.Errorf("# of entries doesn't match the expected number. (%d vs %d)", count, 10-n)
		}

		if ok, noti := checkNoti(ch, notifier.Delete, c, entries[n]); !ok {
			t.Errorf("Got %v. Expected %v, %v, %v\n", noti, notifier.Add, c, entries[n])
		} else {
			t.Log("Notificaiton ok.")
		}
	}
	t.Log(c.ListEntries())

}
