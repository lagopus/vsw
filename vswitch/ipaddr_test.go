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
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/lagopus/vsw/utils/notifier"
)

type testClass struct {
	name string
	*IPAddrs
}

func checkNoti(ch chan notifier.Notification, t notifier.Type, tgt interface{}, v interface{}) (bool, *notifier.Notification) {
	timeout := time.NewTicker(1 * time.Second)
	select {
	case n := <-ch:
		if n.Type != t || n.Target != tgt || !reflect.DeepEqual(n.Value, v) {
			return false, &n
		}
		return true, nil

	case <-timeout.C:
		timeout.Stop()
		return false, nil
	}
}

func listener(t *testing.T, ch chan notifier.Notification) {
	for noti := range ch {
		t.Log(noti)
	}
}

func TestIPAddr(t *testing.T) {
	type testIP struct {
		expect bool
		addr   IPAddr
	}

	ip := IPAddr{net.IPv4(192, 168, 1, 1), net.CIDRMask(24, 32)}
	target := []testIP{
		{true, IPAddr{net.IPv4(192, 168, 1, 1), net.CIDRMask(24, 32)}},
		{false, IPAddr{net.IPv4(192, 168, 1, 1), net.CIDRMask(32, 32)}},
		{false, IPAddr{net.IPv4(192, 168, 1, 2), net.CIDRMask(32, 32)}},
		{false, IPAddr{net.IPv4(192, 168, 1, 2), net.CIDRMask(30, 32)}},
	}

	for _, test := range target {
		if ip.Equal(test.addr) == test.expect {
			t.Logf("%v == %v: %v: ok\n", ip, test.addr, test.expect)
		} else {
			t.Errorf("Should return %v for %v == %v\n", test.expect, ip, test.addr)
		}
	}
}

func TestIPAddrParseCIDR(t *testing.T) {
	type tests struct {
		cidr   string
		result IPAddr
	}

	testCases := []tests{
		{
			cidr:   "0.0.0.0/0",
			result: IPAddr{[]byte{0, 0, 0, 0}, []byte{0, 0, 0, 0}},
		},
		{
			cidr:   "192.168.2.0/24",
			result: IPAddr{[]byte{192, 168, 2, 0}, []byte{0xff, 0xff, 0xff, 0}},
		},
	}

	for _, test := range testCases {
		t.Logf("ParseCIDR(\"%s\")", test.cidr)
		ip, err := ParseCIDR(test.cidr)
		if err != nil {
			t.Errorf("ParseCIDR failed: %v", err)
			continue
		}
		if !ip.Equal(test.result) {
			t.Errorf("Unexpected result: %v", ip)
			continue
		}
		t.Logf("Result: %v. ok.", ip)
	}
}

func TestIPAddrs(t *testing.T) {
	c := &testClass{name: "test"}
	c.IPAddrs = newIPAddrs(c)

	ch := GetNotifier().Listen()
	defer GetNotifier().Close(ch)

	//	go listener(t, ch)

	ipa := IPAddr{net.IPv4(192, 168, 1, 1), net.CIDRMask(24, 32)}
	c.AddIPAddr(ipa)
	t.Log(c.ListIPAddrs())

	if ok, noti := checkNoti(ch, notifier.Add, c, ipa); !ok {
		t.Errorf("Got %v. Expected %v, %v, %v\n", noti, notifier.Add, c, ipa)
	} else {
		t.Log("Notificaiton ok.")
	}

	ipa = IPAddr{net.IPv4(192, 168, 1, 1), net.CIDRMask(16, 32)}
	c.AddIPAddr(ipa)
	t.Log(c.ListIPAddrs())

	if ok, noti := checkNoti(ch, notifier.Update, c, ipa); !ok {
		t.Errorf("Got %v. Expected %v, %v, %v\n", noti, notifier.Update, c, ipa)
	} else {
		t.Log("Notificaiton ok.")
	}

	ipa2 := IPAddr{net.IPv4(192, 168, 1, 2), net.CIDRMask(32, 32)}
	c.AddIPAddr(ipa2)
	t.Log(c.ListIPAddrs())

	if ok, noti := checkNoti(ch, notifier.Add, c, ipa2); !ok {
		t.Errorf("Got %v. Expected %v, %v, %v\n", noti, notifier.Add, c, ipa2)
	} else {
		t.Log("Notificaiton ok.")
	}

	ipa3 := IPAddr{net.IPv4(192, 168, 1, 3), net.CIDRMask(32, 32)}
	c.AddIPAddr(ipa3)
	t.Log(c.ListIPAddrs())

	if ok, noti := checkNoti(ch, notifier.Add, c, ipa3); !ok {
		t.Errorf("Got %v. Expected %v, %v, %v\n", noti, notifier.Add, c, ipa3)
	} else {
		t.Log("Notificaiton ok.")
	}

	c.DeleteIPAddr(ipa2)
	t.Log(c.ListIPAddrs())

	if ok, noti := checkNoti(ch, notifier.Delete, c, ipa2); !ok {
		t.Errorf("Got %v. Expected %v, %v, %v\n", noti, notifier.Delete, c, ipa2)
	} else {
		t.Log("Notificaiton ok.")
	}
}
