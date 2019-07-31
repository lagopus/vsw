//
// Copyright 2019 Nippon Telegraph and Telephone Corporation.
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

import "testing"

func TestFiveTuple(t *testing.T) {
	// Expected results
	type tests struct {
		name    string
		prepare func(*FiveTuple)
		result  string
	}
	testCases := []tests{
		{
			"default",
			func(_ *FiveTuple) {},
			"SrcIP: 0.0.0.0/0, SrcPort: *, DstIP: 0.0.0.0/0, DstPort *, Proto: *",
		},
		{
			"source IP (192.168.1.0/24)",
			func(ft *FiveTuple) {
				ft.SrcIP = IPAddr{[]byte{192, 168, 1, 0}, []byte{0xff, 0xff, 0xff, 0}}
			},
			"SrcIP: 192.168.1.0/24, SrcPort: *, DstIP: 0.0.0.0/0, DstPort *, Proto: *",
		},
		{
			"source Port (single)",
			func(ft *FiveTuple) {
				ft.SrcPort.Start = 80
				ft.SrcPort.End = 0
			},
			"SrcIP: 192.168.1.0/24, SrcPort: 80, DstIP: 0.0.0.0/0, DstPort *, Proto: *",
		},
		{
			"source Port (range)",
			func(ft *FiveTuple) {
				ft.SrcPort.Start = 80
				ft.SrcPort.End = 89
			},
			"SrcIP: 192.168.1.0/24, SrcPort: 80-89, DstIP: 0.0.0.0/0, DstPort *, Proto: *",
		},
		{
			"source Port (any)",
			func(ft *FiveTuple) {
				ft.SrcPort.Start = 0
				ft.SrcPort.End = 0
			},
			"SrcIP: 192.168.1.0/24, SrcPort: *, DstIP: 0.0.0.0/0, DstPort *, Proto: *",
		},
		{
			"protocol (tcp)",
			func(ft *FiveTuple) {
				ft.Proto = IPP_TCP
			},
			"SrcIP: 192.168.1.0/24, SrcPort: *, DstIP: 0.0.0.0/0, DstPort *, Proto: TCP(6)",
		},
	}

	ft := NewFiveTuple()
	for _, test := range testCases {
		test.prepare(ft)
		s := ft.String()
		t.Logf("%s: %s", test.name, s)
		if s != test.result {
			t.Errorf("Unexpected result: Expected: %v", test.result)
			continue
		}
		t.Logf("Result: %v. ok", s)
	}
}
