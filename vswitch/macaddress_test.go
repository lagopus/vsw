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
	"math/rand"
	"testing"
	"time"
)

func testAllMACAddresses(t *testing.T) []macAddress {
	var macs []macAddress
	dups := make(map[uint16]struct{})
	for i := 0; i < 65536; i++ {
		mac, err := newMACAddress()
		if err != nil {
			t.Fatalf("newMACAddress failed after %d attempts: %v", i+1, err)
		}

		seq := uint16(mac[4])<<8 | uint16(mac[5])
		if _, found := dups[seq]; found {
			t.Fatalf("Duplicate MAC Address found; %v", mac)
		}
		dups[seq] = struct{}{}

		macs = append(macs, mac)
	}
	return macs
}

func TestMACAddress(t *testing.T) {
	// Create new mac (should succeed up to 65536)
	macs := testAllMACAddresses(t)
	t.Logf("Successively allocated 65536 MAC Address. No dups.")

	// The next one should fail
	mac, err := newMACAddress()
	if err == nil {
		t.Fatalf("newMACAddress didn't fail. Expected to fail; %v", mac)
	}
	t.Logf("Failed allocate 65537th MAC; Ok")

	// Free one MAC
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	seq := uint16(r.Uint32() & 0xffff)
	t.Logf("Freeing %x-th MAC; %#v", seq, macs[seq])
	macs[seq].free()
	macs[seq], err = newMACAddress()
	if err != nil {
		t.Fatalf("newMACAddress failed: %v", err)
	}
	t.Logf("Successively allocated %#v", macs[seq])

	// Free all mac then reallocate
	for _, mac := range macs {
		mac.free()
	}
	t.Logf("Freed all MAC")

	macs = testAllMACAddresses(t)
	t.Logf("Could reallocate upto 65536 mac address. No dups.")

	// Free all mac then reallocate
	for _, mac := range macs {
		mac.free()
	}
	t.Logf("Clean up ok")
}
