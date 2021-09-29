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
// +build test

package receiver

import (
	"net"

	"github.com/lagopus/vsw/agents/tunnel/ipsec/spd"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
)

func addSP(direction ipsec.DirectionType,
	selector *spd.SPSelector, value *spd.SPValue) (uint32, error) {
	return 1, nil
}

func updateSP(direction ipsec.DirectionType,
	selector *spd.SPSelector, value *spd.SPValue) error {
	return nil
}

func deleteSP(direction ipsec.DirectionType, selector *spd.SPSelector) error {
	return nil
}

func findSP(direction ipsec.DirectionType,
	selector *spd.SPSelector) (*spd.SPValue, bool) {
	return &spd.SPValue{}, true
}

func findSPByEntryID(selector *spd.SPSelector, entryID uint32) (*spd.SPValue, bool) {
	return &spd.SPValue{
		SPSelector: spd.SPSelector{
			CSPSelector: ipsec.CSPSelector{
				LocalIP:  net.IPNet{IP: net.IPv4(8, 8, 8, 8)},
				RemoteIP: net.IPNet{IP: net.IPv4(8, 8, 8, 8)},
			},
		},
		Mode:       ipsec.ModeTypeTunnel,
		LocalEPIP:  net.IPNet{IP: net.IPv4(8, 8, 8, 8)},
		RemoteEPIP: net.IPNet{IP: net.IPv4(8, 8, 8, 8)},
	}, true
}

func setSPI(direction ipsec.DirectionType,
	selector *spd.SPSelector, spi uint32) error {
	return nil
}
