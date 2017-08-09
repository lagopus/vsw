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

package dpdk

import (
	"fmt"
	"testing"
)

func HelloWorld(v interface{}) int {
	fmt.Printf("Hello World from Lcore %d: %v\n", LcoreId(), v)
	return 0
}

func TestLaunch(t *testing.T) {
	var slave uint = 0
	for slave < LcoreCount() {
		if slave != GetMasterLcore() {
			EalRemoteLaunchGoFunc(HelloWorld, [2]string{"arg1", "arg2"}, slave)
		} else {
			fmt.Printf("Skipping Master LCore=%d.\n", slave)
		}
		slave++
	}
	EalMpWaitLcore()
}
