//
// Copyright 2018 Nippon Telegraph and Telephone Corporation.
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
	"net"
	"testing"
	"time"
)

type saEvent int

const (
	invalidEvent saEvent = iota
	sadAdded
	sadUpdated
	sadDeleted
	spdAdded
	spdUpdated
	spdDeleted
	badVRF
)

func (e saEvent) String() string {
	s := map[saEvent]string{
		invalidEvent: "Invalid Event",
		sadAdded:     "sadAdded",
		sadUpdated:   "sadUpdated",
		sadDeleted:   "sadDeleted",
		spdAdded:     "spdAdded",
		spdUpdated:   "spdUpdated",
		spdDeleted:   "spdDeleted",
		badVRF:       "Bad VRF",
	}
	return s[e]
}

type saObserver struct {
	t    *testing.T
	sa   []SA
	sp   []SP
	vrf  *VRF
	rcvd chan saEvent
}

func (o *saObserver) sadEvent(vrf *VRF, sa SA, e saEvent) {
	if o.vrf == vrf {
		o.t.Logf("Got expected VRF")
		o.sa = append(o.sa, sa)
		o.rcvd <- e
	} else {
		o.rcvd <- badVRF
	}
}

func (o *saObserver) spdEvent(vrf *VRF, sp SP, e saEvent) {
	if o.vrf == vrf {
		o.sp = append(o.sp, sp)
		o.rcvd <- e
	} else {
		o.rcvd <- badVRF
	}
}

func (o *saObserver) SADEntryAdded(vrf *VRF, sa SA) {
	o.sadEvent(vrf, sa, sadAdded)
}

func (o *saObserver) SADEntryUpdated(vrf *VRF, sa SA) {
	o.sadEvent(vrf, sa, sadUpdated)
}

func (o *saObserver) SADEntryDeleted(vrf *VRF, sa SA) {
	o.sadEvent(vrf, sa, sadDeleted)
}

func (o *saObserver) SPDEntryAdded(vrf *VRF, sp SP) {
	o.spdEvent(vrf, sp, spdAdded)
}

func (o *saObserver) SPDEntryUpdated(vrf *VRF, sp SP) {
	o.spdEvent(vrf, sp, spdUpdated)
}

func (o *saObserver) SPDEntryDeleted(vrf *VRF, sp SP) {
	o.spdEvent(vrf, sp, spdDeleted)
}

func (o *saObserver) prepare(n int) {
	o.teardown()
	o.rcvd = make(chan saEvent, n)
}

func (o saObserver) wait(event saEvent) (matched bool, timeout bool) {
	timeout = false
	matched = false

	select {
	case e := <-o.rcvd:
		if event == e {
			o.t.Logf("Got expected event: %v", event)
			matched = true
			return
		}
		o.t.Fatalf("Unexpected event: %v expected, but got %v", event, e)
	case <-time.After(10 * time.Millisecond):
		o.t.Logf("Timeout")
		timeout = true
	}
	return
}

func (o *saObserver) wait2() (event saEvent, timeout bool) {
	event = invalidEvent
	timeout = false

	select {
	case event = <-o.rcvd:
		break
	case <-time.After(10 * time.Millisecond):
		o.t.Logf("Timeout")
		timeout = true
	}
	return
}

func (o *saObserver) teardown() {
	if o.rcvd != nil {
		close(o.rcvd)
	}
	o.sp = nil
	o.sa = nil
}

func TestSABasic(t *testing.T) {
	t.Logf("Creating new SADatabases")

	vrf := &VRF{}
	sadb := newSADatabases(vrf)
	o := &saObserver{t: t, vrf: vrf}
	if err := sadb.RegisterObserver(o); err != nil {
		t.Fatalf("Can't regsiter an observer: %v", err)
	}

	// SA
	sa := NewSA(1)
	sa.AuthKey = "abc"
	o.prepare(1)
	t.Logf("Adding new SAD entry.")
	sadb.AddSADEntry(sa)
	if m, _ := o.wait(sadAdded); !m {
		t.Fatalf("AddSADEntry() failed.")
	} else {
		if sa.Equal(o.sa[0]) {
			t.Logf("SA entry matched. Success.")
		} else {
			t.Fatalf("SA entry doesn't match.")
		}
	}

	o.prepare(1)
	t.Logf("Adding the same SAD entry twice.")
	sadb.AddSADEntry(sa)
	if _, to := o.wait(sadAdded); !to {
		t.Fatalf("Adding the same entry with AddSADEntry() shall be ignored")
	}
	t.Logf("Ignored. Success.")

	sa.AuthKey = "def"
	o.prepare(1)
	t.Logf("Updating the SAD entry.")
	sadb.AddSADEntry(sa)
	if m, _ := o.wait(sadUpdated); !m {
		t.Fatalf("Update with AddSADEntry() failed.")
	} else {
		if sa.Equal(o.sa[0]) {
			t.Logf("SA entry matched. Success.")
		} else {
			t.Fatalf("SA entry doesn't match:\nRECEIVED:  %v\nEXPECTED: %v.", o.sa[0], sa)
		}
	}

	o.prepare(1)
	t.Logf("Deleting the SAD entry.")
	sadb.DeleteSADEntry(sa.SPI)
	if m, _ := o.wait(sadDeleted); !m {
		t.Fatalf("DeleteSADEntry() failed.")
	} else {
		if sa.Equal(o.sa[0]) {
			t.Logf("SA entry matched. Success.")
		} else {
			t.Fatalf("SA entry doesn't match.")
		}
	}

	// SP
	sp := NewSP("sp1")

	defaultMask := net.CIDRMask(32, 32)
	if !bytes.Equal(sp.DstAddress.Mask, defaultMask) {
		t.Fatalf("Default network prefix for DstAddress not as expected: %v != %v",
			defaultMask, sp.DstAddress.Mask)
	}
	if !bytes.Equal(sp.SrcAddress.Mask, defaultMask) {
		t.Fatalf("Default network prefix for SrcAddress not as expected: %v != %v",
			defaultMask, sp.SrcAddress.Mask)
	}
	t.Logf("Default network prefix for SrcAddress and DstAddress are as expected.")

	if sp.DstPort != 0 {
		t.Fatalf("Default destination port shall be 0 for any; %v is set", sp.DstPort)
	}
	if sp.SrcPort != 0 {
		t.Fatalf("Default source port shall be 0 for any; %v is set", sp.SrcPort)
	}
	t.Logf("Default ports for DstPort and SrcPort are as expected.")

	if sp.UpperProtocol != IPP_ANY {
		t.Fatalf("Default upper protocol shall be IPP_ANY; %v is set", sp.UpperProtocol)
	}
	t.Logf("Default upper protocol is as expected; %v", sp.UpperProtocol)

	sp.SPI = 1
	o.prepare(1)
	t.Logf("Adding new SPD entry.")
	sadb.AddSPDEntry(sp)
	if m, _ := o.wait(spdAdded); !m {
		t.Fatalf("AddSPDEntry() failed.")
	} else {
		if sp.Equal(o.sp[0]) {
			t.Logf("SP entry matched. Success.")
		} else {
			t.Fatalf("SP entry doesn't match.")
		}
	}

	o.prepare(1)
	t.Logf("Adding the same SPD entry twice.")
	sadb.AddSPDEntry(sp)
	if _, to := o.wait(spdAdded); !to {
		t.Fatalf("Adding the same entry with AddSPDEntry() shall be ignored")
	}
	t.Logf("Ignored. Success.")

	sp.SPI = 100
	o.prepare(1)
	t.Logf("Updating the SPD entry.")
	sadb.AddSPDEntry(sp)
	if m, _ := o.wait(spdUpdated); !m {
		t.Fatalf("Update with AddSPDEntry() failed.")
	} else {
		if sp.Equal(o.sp[0]) {
			t.Logf("SP entry matched. Success.")
		} else {
			t.Fatalf("SP entry doesn't match.")
		}
	}

	o.prepare(1)
	t.Logf("Deleting the SAD entry.")
	sadb.DeleteSPDEntry(sp.Name)
	if m, _ := o.wait(spdDeleted); !m {
		t.Fatalf("DeleteSPDEntry() failed.")
	} else {
		if sp.Equal(o.sp[0]) {
			t.Logf("SP entry matched. Success.")
		} else {
			t.Fatalf("SP entry doesn't match.")
		}
	}

	o.teardown()
}

func checkSA(sas map[uint32]SA, sa SA) error {
	if e, ok := sas[sa.SPI]; ok {
		if !e.Equal(sa) {
			return fmt.Errorf("Entry for SPI=%d doesn't match", sa.SPI)
		}
		return nil
	}
	return fmt.Errorf("SPI=%d shouldn't be in SAD", sa.SPI)
}

func checkSP(sps map[string]SP, sp SP) error {
	if e, ok := sps[sp.Name]; ok {
		if !e.Equal(sp) {
			return fmt.Errorf("Entry for %v doesn't match", sp.Name)
		}
		return nil
	}
	return fmt.Errorf("%v shouldn't be in SPD", sp.Name)
}

func TestSAAdvanced(t *testing.T) {
	t.Logf("Creating new SADatabases")
	sadb := newSADatabases(nil)
	o := &saObserver{t: t}

	sas := make(map[uint32]SA)
	sps := make(map[string]SP)
	const N = 10

	// Create and install SA/SP entries
	t.Logf("Adding %d SA and SP entries each", N)
	for i := 1; i <= N; i++ {
		spi := uint32(i)
		sa := NewSA(spi)
		sadb.AddSADEntry(sa)
		sas[spi] = sa

		name := fmt.Sprintf("sp%d", i)
		sp := NewSP(name)
		sadb.AddSPDEntry(sp)
		sps[name] = sp
	}

	// Check if SAD/SPD are as expected
	t.Logf("Checking validity of SAD")
	sad := sadb.SAD()
	if len(sad) != N {
		t.Fatalf("SAD entry count doesn't match: %d expected. Got %d", N, len(sad))
	}
	for _, sa := range sad {
		if err := checkSA(sas, sa); err != nil {
			t.Fatalf("%v", err)
		}
	}
	t.Logf("All SAD looks good.")

	t.Logf("Checking validity of SPD")
	spd := sadb.SPD()
	if len(spd) != N {
		t.Fatalf("SPD entry count doesn't match: %d expected. Got %d", N, len(spd))
	}
	for _, sp := range spd {
		if err := checkSP(sps, sp); err != nil {
			t.Fatalf("%v", err)
		}
	}
	t.Logf("All SPD looks good.")

	// Check if we get SADEntryAdded and SPDEntryAdded for existing items
	o.prepare(N * 2)
	t.Logf("Registering observer now.")
	if err := sadb.RegisterObserver(o); err != nil {
		t.Fatalf("Can't regsiter an observer: %v", err)
	}

	sac := 0
	spc := 0
	for i := 0; i < N*2; i++ {
		event, timeout := o.wait2()
		if timeout {
			t.Fatalf("Timeout after %d events received.", i)
		}
		switch event {
		case sadAdded:
			sa := o.sa[sac]
			if err := checkSA(sas, sa); err != nil {
				t.Fatalf("sadAdded notified: %v", err)
			}
			t.Logf("Received SADEntryAdded for SPI=%d", sa.SPI)
			delete(sas, sa.SPI)
			sac++
		case spdAdded:
			sp := o.sp[spc]
			if err := checkSP(sps, sp); err != nil {
				t.Fatalf("spdAdded notified: %v", err)
			}
			t.Logf("Received SPDEntryAdded for %s", sp.Name)
			delete(sps, sp.Name)
			spc++
		default:
			t.Fatalf("Unexpected event %v received.", event)
		}
	}
	if len(sas) != 0 {
		t.Fatalf("Didn't get all SA entries (%d remained)", len(sas))
	}
	if len(sps) != 0 {
		t.Fatalf("Didn't get all SP entries (%d remained)", len(sps))
	}
	t.Logf("Got all events for SAD and SPD. Success.")

	o.teardown()
}
