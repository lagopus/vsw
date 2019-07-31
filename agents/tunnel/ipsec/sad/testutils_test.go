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
	"time"

	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/vswitch"
)

func dummySadbExpire(vrfIndex vswitch.VRFIndex, dir ipsec.DirectionType,
	spi SPI, sav *SAValue, kind SadbExpireType) bool {
	//log.Printf("not send SADB_EXPIRE[%s] (dummy) dir=%s spi=%d \n", kind, dir, spi)
	return true
}
func dummySadbAcquire(vrfIndex vswitch.VRFIndex, entryID uint32, src *net.IPNet, dst *net.IPNet) bool {
	//log.Printf("not send SADB_ACQUIRE (dummy) src=%s dst=%s\n", dir, src, dst)
	return true
}

func setupTest() {
	RegisterSadbExpire(dummySadbExpire)
	RegisterSadbAcquire(dummySadbAcquire)
}

func mkReqSA(sav *SAValue, stat internalState) *SAValue {
	retv := *sav
	retv.inStat = stat
	return &retv
}

func mkIP(str string) net.IP {
	return net.ParseIP(str)
}

func teardownTest() {
}

func clearSAD(mgr *Mgr) {
	for _, vrf := range mgr.vrfs {
		for k := range vrf.sad {
			delete(vrf.sad, k)
		}
	}
}

// mock CSAD.

type mockCSAD struct {
	ipsec.BaseCSAD
}

func (sad *mockCSAD) Push(entArr []ipsec.CSA) int {
	return 0
}

func (sad *mockCSAD) PullLifetime(spi ipsec.CSPI) (time.Time, uint64, error) {
	return time.Unix(0, 0), 0, nil
}

func (sad *mockCSAD) RegisterAcquireFunc(fn ipsec.SadbAcquireFunc) {
}

func (sad *mockCSAD) PullAcquired() (err error) {
	return nil
}

func (sad *mockCSAD) String() string {
	return "mockCSAD"
}
