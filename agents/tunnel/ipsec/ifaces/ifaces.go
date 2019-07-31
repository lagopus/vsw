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

package ifaces

import (
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/vswitch"
)

type iface struct {
	ipsec.CIfaceValue
}

// newIface Cretate iface.
func newIface(vifIndex vswitch.VIFIndex) *iface {
	return &iface{
		CIfaceValue: ipsec.CIfaceValue{
			VIFIndex: vifIndex,
			TTL:      ipsec.DefaultTTL,
			TOS:      ipsec.DefaultTOS,
		},
	}
}

func (i *iface) setVRFIndex(vrfIndex *vswitch.VRFIndex) {
	i.VRFIndex = vrfIndex
}

func (i *iface) unsetVRFIndex() {
	i.VRFIndex = nil
}

func (i *iface) vrfIndex() *vswitch.VRFIndex {
	return i.VRFIndex
}

func (i *iface) setRings(direction ipsec.DirectionType, rings *ipsec.Rings) {
	i.Input = rings.Input(direction)
	i.Output = rings.Output(direction)
}

func (i *iface) unsetRings() {
	i.Input = nil
	i.Output = nil
}

func (i *iface) setTTL(ttl uint8) {
	i.TTL = ttl
}

func (i *iface) ttl() uint8 {
	return i.TTL
}

func (i *iface) setTOS(tos int8) {
	i.TOS = tos
}

func (i *iface) tos() int8 {
	return i.TOS
}
