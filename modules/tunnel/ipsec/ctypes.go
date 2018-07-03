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

package ipsec

// #include <linux/ipsec.h>
// #include <netinet/ip.h>
// #include "ipsec.h"
import "C"

// PolicyType Policy.
type PolicyType uint16

const (
	// PolicyTypeDiscard DISCARD.
	PolicyTypeDiscard PolicyType = C.IPSEC_POLICY_DISCARD
	// PolicyTypeNone NONE
	PolicyTypeNone PolicyType = C.IPSEC_POLICY_NONE
	// PolicyTypeProtect PROTECT.
	PolicyTypeProtect PolicyType = C.IPSEC_POLICY_IPSEC
	// PolicyTypeEntrust ENTRUST
	PolicyTypeEntrust PolicyType = C.IPSEC_POLICY_ENTRUST
	// PolicyTypeBypass BYPASS.
	PolicyTypeBypass PolicyType = C.IPSEC_POLICY_BYPASS
)

// SecurityProtocolType Protocol.
type SecurityProtocolType uint8

const (
	// SecurityProtocolTypeUnspec Unspec
	SecurityProtocolTypeUnspec SecurityProtocolType = C.SADB_SATYPE_UNSPEC
	// SecurityProtocolTypeAH AH.
	SecurityProtocolTypeAH SecurityProtocolType = C.SADB_SATYPE_AH
	// SecurityProtocolTypeESP ESP.
	SecurityProtocolTypeESP SecurityProtocolType = C.SADB_SATYPE_ESP
)

// ModeType Mode.
type ModeType uint8

const (
	// ModeTypeAny ANY
	ModeTypeAny ModeType = C.IPSEC_MODE_ANY
	// ModeTypeTransport TRANSPORT.
	ModeTypeTransport ModeType = C.IPSEC_MODE_TRANSPORT
	// ModeTypeTunnel TUNNEL.
	ModeTypeTunnel ModeType = C.IPSEC_MODE_TUNNEL
	// ModeTypeBeet BEET
	ModeTypeBeet ModeType = C.IPSEC_MODE_BEET
)

// DirectionType Direction.
type DirectionType uint8

const (
	// DirectionTypeAny ANY
	DirectionTypeAny DirectionType = C.IPSEC_DIR_ANY
	// DirectionTypeIn IN
	DirectionTypeIn DirectionType = C.IPSEC_DIR_INBOUND
	// DirectionTypeOut OUT
	DirectionTypeOut DirectionType = C.IPSEC_DIR_OUTBOUND
	// DirectionTypeFwd FWD
	DirectionTypeFwd DirectionType = C.IPSEC_DIR_FWD
	// DirectionTypeMax MAX
	DirectionTypeMax DirectionType = C.IPSEC_DIR_MAX
	// DirectionTypeInvalid INVALID
	DirectionTypeInvalid DirectionType = C.IPSEC_DIR_INVALID
)

// String Get string.
func (dir DirectionType) String() string {
	var str string
	switch dir {
	case DirectionTypeAny:
		str = "ANY"
	case DirectionTypeIn:
		str = "IN"
	case DirectionTypeOut:
		str = "OUT"
	case DirectionTypeFwd:
		str = "FWD"
	case DirectionTypeMax:
		str = "MAX"
	case DirectionTypeInvalid:
		str = "INVALID"
	default:
		str = "UNKNOWN"
	}
	return str
}

// Role convert to enum ipsecvsw_queue_role_t
func (dir DirectionType) Role() C.ipsecvsw_queue_role_t {
	var d C.ipsecvsw_queue_role_t
	switch dir {
	case DirectionTypeIn:
		d = C.ipsecvsw_queue_role_inbound
	case DirectionTypeOut:
		d = C.ipsecvsw_queue_role_outbound
	default:
		d = C.ipsecvsw_queue_role_unknown
	}
	return d
}

// LevelType Level.
type LevelType uint8

const (
	// LevelTypeDefault DEFAULT
	LevelTypeDefault LevelType = C.IPSEC_LEVEL_DEFAULT
	// LevelTypeUse USE
	LevelTypeUse LevelType = C.IPSEC_LEVEL_USE
	// LevelTypeRequire REQUIRE
	LevelTypeRequire LevelType = C.IPSEC_LEVEL_REQUIRE
	// LevelTypeUnique UNIQUE
	LevelTypeUnique LevelType = C.IPSEC_LEVEL_UNIQUE
)

// UpperProtocolType Upper protocol.
type UpperProtocolType uint16

const (
	// UpperProtocolTypeAny ANY.
	UpperProtocolTypeAny UpperProtocolType = C.IPSEC_ULPROTO_ANY
)

// IPVersionType IP Version.
type IPVersionType uint8

const (
	// IPVersionType4 IPv4.
	IPVersionType4 IPVersionType = C.IPVERSION
	// IPVersionType6 IPv6.
	IPVersionType6 IPVersionType = C.IP6_VERSION
)

// LagopusResult lagopus_result_t.
type LagopusResult C.lagopus_result_t

const (
	// LagopusResultOK OK.
	LagopusResultOK LagopusResult = C.LAGOPUS_RESULT_OK
)

const (
	//EntryIDBits Bit of EntryID.
	EntryIDBits = C.SP_ENTRY_ID_BITS
	// EntryIDTinyMask Tiny Mask.
	EntryIDTinyMask = (1 << EntryIDBits) - 1
	// MaxVRFEntries Maximum entry number of VRF.
	MaxVRFEntries = C.VRF_MAX_ENTRY
	// MaxVIFEntries Maximum entry number of VIF.
	MaxVIFEntries = C.VIF_MAX_ENTRY
)
