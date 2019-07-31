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

package sad

import (
	"net"

	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/modules/tunnel/log"
	"github.com/lagopus/vsw/vswitch"
)

// SadbExpireType SADB_EXPIRE type
type SadbExpireType uint8

// Soft or Hard
const (
	SoftLifetimeExpired SadbExpireType = iota
	HardLifetimeExpired
)

func (s SadbExpireType) String() string {
	switch s {
	case SoftLifetimeExpired:
		return "Soft"
	case HardLifetimeExpired:
		return "Hard"
	}
	return "unknown"
}

// SadbExpireFunc send SADB_EXPIRE message. if success, returns true
type SadbExpireFunc func(vswitch.VRFIndex, ipsec.DirectionType, SPI, *SAValue, SadbExpireType) bool

var _sadbExpire SadbExpireFunc

// RegisterSadbExpire Register SadbExpireFunc
func RegisterSadbExpire(f SadbExpireFunc) {
	_sadbExpire = f
}

// SadbExpire execute registered SadbExpireFunc
func SadbExpire(vrfIndex vswitch.VRFIndex, dir ipsec.DirectionType, spi SPI, sav *SAValue, kind SadbExpireType) bool {
	if _sadbExpire != nil {
		return _sadbExpire(vrfIndex, dir, spi, sav, kind)
	}
	log.Logger.Err("not send SADB_EXPIRE(%s) %s %d %+v (SadbExpireFunc not registered.)",
		kind.String(), dir.String(), spi, sav)
	return false
}

// memo: SADB_ACQUIRE is triggered by outbound packet only.

var _sadbAcquire ipsec.SadbAcquireFunc

// RegisterSadbAcquire Register SadbAcquireFunc
func RegisterSadbAcquire(f ipsec.SadbAcquireFunc) {
	_sadbAcquire = f
}

// SadbAcquire execute registered SadbAcquireFunc
func SadbAcquire(vrfIndex vswitch.VRFIndex, entryID uint32, src *net.IPNet, dst *net.IPNet) bool {
	if _sadbAcquire != nil {
		return _sadbAcquire(vrfIndex, entryID, src, dst)
	}
	log.Logger.Err("not send SADB_ACQUIRE id:%d src:%s dst:%s (SadbAcquireFunc not registered.)",
		entryID, *src, *dst)
	return false
}
