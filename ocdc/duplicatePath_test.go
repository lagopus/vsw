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

// Create two clients that subscribe the same path.
// As OpenConfigd sends configurations for the number of times that
// the path was subscribed, ocdclient control so that the same path
// is not subscribed. Should fail if clients receive duplicate configuration.
func TestDuplicatePath(t *testing.T) {
	// start OpenConfigd
	ocd, err := startOcd("")
	if err != nil {
		t.Fatalf("Couldn't start OpenConfigd.: %v\n", err)
	}
	SetOcdServer("", uint16(2650))

	// start clients
	cli0 := &client{
		name:           "client0",
		subscribePaths: subscribePaths, // interfaces and network-instances
		valResult:      true,
		confc:          make(chan *ConfigMessage),
		t:              t,
	}
	cli1 := &client{
		name:           "client1",
		subscribePaths: [][]string{subscribePaths[1]}, // network-instances
		valResult:      true,
		confc:          make(chan *ConfigMessage),
		t:              t,
	}
	if err := cli0.Start(); err != nil {
		ocd.Process.Kill()
		t.Fatalf("Couldn't start %v: %v\n", cli0.name, err)
	}
	if err := cli1.Start(); err != nil {
		cli0.Stop()
		ocd.Process.Kill()
		t.Fatalf("Couldn't start %v: %v\n", cli1.name, err)
	}

	// Add new configuration from cli
	if err := doSetCli(setNICmd); err != nil {
		cli0.Stop()
		ocd.Process.Kill()
		t.Fatal(err)
	}
	rc := map[int]int{
		0: 0,
		1: 0,
	}
	for {
		select {
		case c := <-cli0.confc:
			if err := c.judgeConfResult(ConfigMode(rc[0]), expNI, true); err != nil {
				cli0.Stop()
				cli1.Stop()
				ocd.Process.Kill()
				t.Fatalf("%v: %v\n", cli0.name, err)
			}
			rc[0]++

		case c := <-cli1.confc:
			if err := c.judgeConfResult(ConfigMode(rc[1]), expNI, true); err != nil {
				cli0.Stop()
				cli1.Stop()
				ocd.Process.Kill()
				t.Fatalf("%v: %v\n", cli1.name, err)
			}
			rc[1]++
		}

		if (rc[0] == 2) && (rc[1] == 2) {
			break
		}
	}

	// tear down
	cli0.Stop()
	cli1.Stop()
	if err := ocd.Process.Kill(); err != nil {
		t.Fatal("Couldn't stop Openconfigd.: %v\n", err)
	}

	t.Log("Clients didn't receive duplicate path, test passed.")
}
