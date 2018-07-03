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

package sad

import (
	"time"

	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/vswitch"
)

// SASelector Selector for SA.
type SASelector struct {
	VRFIndex vswitch.VRFIndex
	SPI      SPI
}

// SAValue Values in SAD.
type SAValue struct {
	ipsec.CSAValue                                 // SAValue in C.
	Protocol            ipsec.SecurityProtocolType // Security Protocol Identifier
	LifeTimeHard        time.Time                  // HARD lifetime (if 0, infinity)
	LifeTimeSoft        time.Time                  // SOFT lifetime (if 0, infinity)
	LifeTimeCurrent     time.Time                  // CURRENT lifetime
	LifeTimeByteHard    uint64                     // HARD lifetime (byte count) (if 0, infinity)
	LifeTimeByteSoft    uint64                     // SOFT lifetime (byte count) (if 0, infinity)
	LifeTimeByteCurrent uint64                     // CURRENT lifetime (byte count)
	State               SAState                    // state
	inStat              internalState              // internal state
}

func (sav *SAValue) isSoftExpired(now time.Time) bool {
	switch sav.inStat {
	case reserved, softExpired, hardExpired, deleting:
		return false
	case newing, updating:
		return false
	case valid:
		if (!sav.LifeTimeSoft.IsZero() && sav.LifeTimeSoft.Before(now)) ||
			(sav.LifeTimeByteSoft != 0 && sav.LifeTimeByteSoft < sav.LifeTimeByteCurrent) {
			return true
		}
	}
	return false
}

func (sav *SAValue) isHardExpired(now time.Time) bool {
	switch sav.inStat {
	case hardExpired, deleting:
		return false
	case reserved, newing, valid, updating, softExpired:
		if (!sav.LifeTimeHard.IsZero() && sav.LifeTimeHard.Before(now)) ||
			(sav.LifeTimeByteHard != 0 && sav.LifeTimeByteHard < sav.LifeTimeByteCurrent) {
			return true
		}
	}
	return false
}
