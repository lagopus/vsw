//
// Copyright 2018-2019 Nippon Telegraph and Telephone Corporation.
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
	"crypto/rand"
	"errors"
	"net"
	"sync"
)

// macManager generates unique MAC addresses to be used by RIF or Tunnel.
// The startegy is the following:
// - Upper 4 octets are unique random numbers with the following flags enabled:
//	- locally administrated (bit6 of the 1st octet = 1; OR 0x02)
//	- unicast (bit7 of the 1st octet = 0; AND 0xFE)
// - Lower 2 octets are sequencially assigned numbers starting from 0.
type macManager struct {
	lock   sync.Mutex
	prefix []byte
	seq    uint16
	used   map[uint16]struct{}
}

var macMgr *macManager

type macAddress net.HardwareAddr

// newMACAddress generates a unique MAC Address to be used by
// instances in Lagopus.
// Returns a unique MAC Address if succeeds. Otherwise, returns
// an error.
func newMACAddress() (macAddress, error) {
	macMgr.lock.Lock()
	defer macMgr.lock.Unlock()

	if len(macMgr.used) == 0x10000 {
		return nil, errors.New("Can't allocate MAC address anymore")
	}

	seq := macMgr.seq
	_, used := macMgr.used[seq]
	for used {
		seq++
		_, used = macMgr.used[seq]
	}

	hw := make([]byte, 6)
	copy(hw, macMgr.prefix)
	hw[4] = byte(seq >> 8) // upper 8bits of the sequence number
	hw[5] = byte(seq)      // lower 8bits of the sequence number

	macMgr.used[seq] = struct{}{}
	macMgr.seq = seq + 1

	return hw, nil
}

// free releases given macAddress allocated to the instance.
// This function must be called explicitly when the instance doesn't
// require assigned MAC address.
func (ma macAddress) free() {
	if !bytes.HasPrefix(ma, macMgr.prefix) {
		return
	}
	seq := uint16(ma[4])<<8 | uint16(ma[5])

	macMgr.lock.Lock()
	defer macMgr.lock.Unlock()

	if _, ok := macMgr.used[seq]; ok {
		delete(macMgr.used, seq)
	}
}

func init() {
	macMgr = &macManager{
		prefix: make([]byte, 4),
		used:   make(map[uint16]struct{}),
	}

	// Generate MAC Address prefix
	if _, err := rand.Read(macMgr.prefix); err != nil {
		logger.Panicf("Can't generate random number: %v", err)
	}
	macMgr.prefix[0] &= 0xfe
	macMgr.prefix[0] |= 0x02
}
