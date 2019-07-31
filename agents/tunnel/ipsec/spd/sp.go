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

package spd

import (
	"fmt"
	"net"
	"time"

	"github.com/lagopus/vsw/modules/tunnel/ipsec"
)

// SPSelector Selector for SP.
type SPSelector struct {
	ipsec.CSPSelector                     // SPSelector in C.
	Direction         ipsec.DirectionType // Direction
}

// Modified Is Modified.
func (s *SPSelector) Modified(newS SPSelector) bool {
	return s.CSPSelector.Modified(newS.CSPSelector) ||
		(s.Direction != newS.Direction)
}

//SPStats stats for SP.
type SPStats struct {
	LifeTimeCurrent     time.Time // Lifetime - current
	LifeTimeByteCurrent uint64    // Lifetime - current (byte count), Unuse in SP (zero)
}

func newSPStats(stats *ipsec.CSPDStats) *SPStats {
	s := &SPStats{
		LifeTimeCurrent: stats.LifeTimeCurrent(),
	}
	return s
}

func (s *SPStats) String() string {
	return fmt.Sprintf("LifeTimeCurrent: %v", s.LifeTimeCurrent)
}

// SPValue Values for SP .
type SPValue struct {
	SPSelector                                  // Selector (inner)
	ipsec.CSPValue                              // SPValue in C.
	State            StateType                  // State (Uncompleted, Completed)
	Protocol         ipsec.SecurityProtocolType // Protocol (AH, ESP)
	Mode             ipsec.ModeType             // Mode (TRANSPORT, TUNNEL)
	Level            ipsec.LevelType            // Level (DEFAULT, USE, REQUIRE, UNIQUE)
	RequestID        uint32                     // RequestID (for 'struct sadb_x_ipsecrequest' in C)
	LocalEPIP        net.IPNet                  // Local(src) endpoint IP addr and mask
	RemoteEPIP       net.IPNet                  // Remote(dst) endpoint IP addr and mask
	LifeTimeHard     time.Time                  // Lifetime - hard
	LifeTimeSoft     time.Time                  // Lifetime - soft, Unuse in SP
	LifeTimeByteHard uint64                     // Lifetime - hard (byte count), Unuse in SP (zero)
	LifeTimeByteSoft uint64                     // Lifetime - soft (byte count), Unuse in SP (zero)
	SPStats                                     // Stats (Lifetime-Current, etc.)
}

// Copy copy.
func (v *SPValue) Copy() *SPValue {
	copyValue := *v
	return &copyValue
}

// SetSPStats Set stats.
func (v *SPValue) setSPStats(s *SPStats) {
	v.SPStats = *s
}

// isExpiredLifeTimeHard Is expired (LifeTime - Hard).
func (v *SPValue) isExpiredLifeTimeHard(now time.Time) bool {
	return !v.LifeTimeHard.IsZero() &&
		v.LifeTimeHard.UnixNano() <= now.UnixNano()
}
