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
	"fmt"

	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/vswitch"
)

// dummy CIfaceStats.
func newDummyStats() *ipsec.CIfaceStats {
	return &ipsec.CIfaceStats{}
}

// mock CIfaces.
type mockCIfaces struct {
	suite           *testIfaceMgrTestSuite
	countPushIfaces uint64
	countStats      uint64
}

func newMockCIfaces(suite *testIfaceMgrTestSuite) *mockCIfaces {
	return &mockCIfaces{
		suite: suite,
	}
}

func (i *mockCIfaces) PushIfaces(direction ipsec.DirectionType,
	array []ipsec.CIface) error {
	i.suite.Equal(ipsec.MaxVRFEntries, len(array))
	i.countPushIfaces++
	return nil
}

func (i *mockCIfaces) Stats(direction ipsec.DirectionType,
	index vswitch.VIFIndex) (*ipsec.CIfaceStats, error) {
	i.countStats++
	return newDummyStats(), nil
}

func (i *mockCIfaces) AllocArray() ([]ipsec.CIface, error) {
	return make([]ipsec.CIface, ipsec.MaxVRFEntries), nil
}

func (i *mockCIfaces) FreeArray(array []ipsec.CIface) {
}

func (i *mockCIfaces) SetCIface(ciface *ipsec.CIface, value *ipsec.CIfaceValue) {
}

func (i *mockCIfaces) String() string {
	return "mockCIfaces"
}

func (i *mockCIfaces) EqualCountPushIfaces(count uint64) {
	i.suite.Equal(count, i.countPushIfaces)
}

func (i *mockCIfaces) EqualCountStats(count uint64) {
	i.suite.Equal(count, i.countStats)
}

// mock for error.
type mockCIfacesErr struct {
	mockCIfaces
}

func newMockCIfacesErr(suite *testIfaceMgrTestSuite) *mockCIfacesErr {
	return &mockCIfacesErr{
		mockCIfaces: mockCIfaces{
			suite: suite,
		},
	}
}

func (i *mockCIfacesErr) PushIfaces(direction ipsec.DirectionType,
	array []ipsec.CIface) error {
	return fmt.Errorf("error")
}

func (i *mockCIfacesErr) Stats(direction ipsec.DirectionType,
	index vswitch.VIFIndex) (*ipsec.CIfaceStats, error) {
	return nil, fmt.Errorf("error")
}
