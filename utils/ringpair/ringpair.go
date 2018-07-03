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

package ringpair

import (
	"fmt"
	"github.com/lagopus/vsw/dpdk"
)

// RingPair represents a pair of DPDK rings.
type RingPair struct {
	// An array of 2 DPDK rings
	Rings [2]*dpdk.Ring

	// A configuration used to create this RingPair
	Config *Config
}

// Config represents a configuration of RingPair
type Config struct {
	// Prefix for names of 2 DPDK rings.
	// The names will be 'Prefix-rp0' and 'Prefix-rp1'.
	Prefix string

	// The sizes of each ring. Must be power of 2.
	// If 0 is given, the ring corresponds to it won't
	// be created.
	Counts [2]uint

	// Specify socket ID if NUMA constraints applies.
	// Otherwise pass dpdk.SOCKET_ID_ANY.
	SocketID int
}

var serial = 0

// Create creates a pair of DPDK rings.
// If nil is passed as an argument, the following default setting is
// used:
//
//	&Config{
//		Prefix: "ringpairN",
//		Counts: [2]uint{2, 2},
//		SocketID: dpdk.SOCKET_ID_ANY,
//	}
//
// where N in the Prefix is a serial number.
//
// Created rings are good for a single consumer/producer use case only.
//
// Returns RingPair on success, otherwise nil.
func Create(c *Config) *RingPair {
	if c == nil {
		c = &Config{
			Prefix:   fmt.Sprintf("ringpair%d", serial),
			Counts:   [2]uint{2, 2},
			SocketID: dpdk.SOCKET_ID_ANY,
		}
		serial++
	}

	rp := &RingPair{Config: c}

	for i := 0; i < 2; i++ {
		if c.Counts[i] > 0 {
			rp.Rings[i] = dpdk.RingCreate(fmt.Sprintf("%s-rp%d", c.Prefix, i),
				c.Counts[i], c.SocketID, dpdk.RING_F_SP_ENQ|dpdk.RING_F_SC_DEQ)

			if rp.Rings[i] == nil {
				if i == 1 {
					rp.Rings[0].Free()
				}
				return nil
			}
		}
	}

	return rp
}

// Free frees rings.
func (rp *RingPair) Free() {
	for _, ring := range rp.Rings {
		if ring != nil {
			ring.Free()
		}
	}
}
