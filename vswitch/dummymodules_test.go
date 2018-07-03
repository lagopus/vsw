//
// Copyright 2018 Nippon Telegraph and Telephone Corporation.
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

package vswitch

const (
	DUMMY_TAP_MODULE = "tap"
)

type dummyTap struct{}

var testDT = &dummyTap{}

func newDummyTap(base *BaseInstance, priv interface{}) (Instance, error) {
	return testDT, nil
}

func (d *dummyTap) Enable() error {
	return nil
}

func (d *dummyTap) Disable() {
}

func (d *dummyTap) Free() {
}

func getDummyTap() *dummyTap {
	return testDT
}

func init() {
	if err := RegisterModule(DUMMY_TAP_MODULE, newDummyTap, nil, TypeOther); err != nil {
		panic(err)
	}
}
