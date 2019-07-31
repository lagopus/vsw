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

package vswitch

import (
	"fmt"
	"net"
	"testing"

	"github.com/lagopus/vsw/utils/notifier"
)

type testRtClass struct {
	name string
	*RoutingTable
}

func (r *testRtClass) routeEntryAdded(entry Route) {
	noti.Notify(notifier.Add, r, entry)
}

func (r *testRtClass) routeEntryDeleted(entry Route) {
	noti.Notify(notifier.Delete, r, entry)
}

func TestRouting(t *testing.T) {
	c := &testRtClass{name: "test"}
	c.RoutingTable = newRoutingTable(c)

	ch := GetNotifier().Listen()
	defer GetNotifier().Close(ch)
	//	go listener(t, ch)

	// expect to add
	var entries = make([]Route, 10)
	for n := 0; n < 10; n++ {
		gw, dst, _ := net.ParseCIDR(fmt.Sprintf("192.168.%d.1/24", n))
		entries[n] = Route{
			Dst:     dst,
			Gw:      gw,
			Metrics: 1,
			Scope:   RouteScopeHost,
		}

		c.AddEntry(entries[n])

		count := len(c.ListEntries())
		if count != n+1 {
			t.Errorf("# of entries doesn't match the expected number. (%d vs %d)", count, n+1)
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
		c.DeleteEntry(entries[n])

		count := len(c.ListEntries())
		if count != 9-n {
			t.Errorf("# of entries doesn't match the expected number. (%d vs %d)", count, 9-n)
		}

		if ok, noti := checkNoti(ch, notifier.Delete, c, entries[n]); !ok {
			t.Errorf("Got %v. Expected %v, %v, %v\n", noti, notifier.Add, c, entries[n])
		} else {
			t.Log("Notificaiton ok.")
		}
	}
	t.Log(c.ListEntries())
}

func TestRoutingMultipleNexthops(t *testing.T) {
	c := &testRtClass{name: "test"}
	c.RoutingTable = newRoutingTable(c)

	ch := GetNotifier().Listen()
	defer GetNotifier().Close(ch)

	// expect to add
	_, dst, _ := net.ParseCIDR("192.168.0.1/24")
	entry := Route{
		Dst:     dst,
		Metrics: 100,
		Scope:   RouteScopeSite,
		Nexthops: []*Nexthop{
			&Nexthop{&VIF{}, 10, nil},
			&Nexthop{&VIF{}, 20, nil},
			&Nexthop{&VIF{}, 30, nil},
		},
	}

	t.Logf("Adding entry: %v", entry)

	c.AddEntry(entry)

	if len(c.ListEntries()) == 0 {
		t.Fatalf("No entry found.")
	}

	if ok, noti := checkNoti(ch, notifier.Add, c, entry); !ok {
		t.Errorf("Got %v. Expected %v, %v, %v\n", noti, notifier.Add, c, entry)
	} else {
		t.Log("Notificaiton ok.")
	}

	t.Log(c.ListEntries())
}

func TestRoutingAddDelete(t *testing.T) {
	c := &testRtClass{name: "test"}
	c.RoutingTable = newRoutingTable(c)

	ch := GetNotifier().Listen()
	defer GetNotifier().Close(ch)

	gw, dst, _ := net.ParseCIDR("192.168.0.1/24")
	entry := Route{
		Dst:     dst,
		Metrics: 100,
		Scope:   RouteScopeSite,
	}

	t.Logf("Adding entry: %v", entry)

	if err := c.AddEntry(entry); err != nil {
		t.Fatalf("Adding entry failed: %v", err)
	}

	t.Logf("Adding entry succeeded.")

	entry.Metrics = 200
	entry.Gw = gw

	t.Logf("Adding entry: %v", entry)

	if err := c.AddEntry(entry); err != nil {
		t.Fatalf("Adding entry failed: %v", err)
	}

	t.Logf("Adding entry succeeded.")

	t.Logf("Adding entry again: %v", entry)

	if err := c.AddEntry(entry); err == nil {
		t.Fatalf("Adding entry succeeded. Should have failed.")
	}

	t.Logf("Adding entry failed. Good.")

	t.Log(c.ListEntries())

	entry.Gw = nil

	t.Logf("Deleting entry: %v", entry)

	if err := c.DeleteEntry(entry); err != nil {
		t.Fatalf("Deleting entry failed: %v", err)
	}

	t.Logf("Deleting entry succeeded.")

	t.Log(c.ListEntries())
}
