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
// +build !test

package receiver

import (
	"github.com/lagopus/vsw/agents/tunnel/ipsec/spd"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
)

var mgr *spd.Mgr

func init() {
	mgr = spd.GetMgr()
}

func addSP(direction ipsec.DirectionType,
	selector *spd.SPSelector, value *spd.SPValue) (uint32, error) {
	return mgr.AddSP(direction, selector, value)
}

func updateSP(direction ipsec.DirectionType,
	selector *spd.SPSelector, value *spd.SPValue) error {
	return mgr.UpdateSP(direction, selector, value)
}

func deleteSP(direction ipsec.DirectionType, selector *spd.SPSelector) error {
	return mgr.DeleteSP(direction, selector)
}

func findSP(direction ipsec.DirectionType,
	selector *spd.SPSelector) (*spd.SPValue, bool) {
	return mgr.FindSP(direction, selector)
}

func findSPByEntryID(selector *spd.SPSelector, entryID uint32) (*spd.SPValue, bool) {
	return mgr.FindSPByEntryID(selector, entryID)
}

func setSPI(direction ipsec.DirectionType,
	selector *spd.SPSelector, spi uint32) error {
	return mgr.SetSPI(direction, selector, spi)
}
