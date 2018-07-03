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

package ocdc

import "testing"

// Start OpenConfigd without initial configuration.
// Should fail the followiong cases.
//    - Client couldn't receive a validate message of new configuration
//      after add it.
//    - Client couldn't receive a commit message of new configuration
//      after receive a validate message.
func TestWithoutInitConf(t *testing.T) {
	// start OpenConfigd
	ocd, err := startOcd("")
	if err != nil {
		t.Fatalf("Couldn't start OpenConfigd.: %v\n", err)
	}
	SetOcdServer("", uint16(2650))

	// start a client
	cli := &client{
		name:           "withoutInitConf-client",
		subscribePaths: subscribePaths,
		valResult:      true,
		confc:          make(chan *ConfigMessage),
		t:              t,
	}
	if err := cli.Start(); err != nil {
		ocd.Process.Kill()
		t.Fatalf("Couldn't start %v.: %v\n", cli.name, err)
	}

	// Add new configuration from cli
	if err := doSetCli(setNICmd); err != nil {
		cli.Stop()
		ocd.Process.Kill()
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		c := <-cli.confc
		if err := c.judgeConfResult(ConfigMode(i), expNI, false); err != nil {
			cli.Stop()
			ocd.Process.Kill()
			t.Fatal(err)
		}
	}

	// tear down
	cli.Stop()
	if err := ocd.Process.Kill(); err != nil {
		t.Fatal("Couldn't stop OpenConfigd.: %v\n", err)
	}

	t.Log("Client commited a new configuration, test passed.")
}
