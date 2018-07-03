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

import (
	"testing"
	"time"
)

const TIMEOUT = 100

// Create a client that fail validation certainly.
// Should fail if the client receives a commit message
// after send validation failed.
func TestValidateFail(t *testing.T) {
	// start OpenConfigd
	ocd, err := startOcd("")
	if err != nil {
		t.Fatalf("Couldn't start OpenConfigd.: %v\n", err)
	}
	SetOcdServer("", uint16(2650))

	//start a client
	cli := &client{
		name:           "validateFail-client",
		subscribePaths: subscribePaths,
		valResult:      false,
		confc:          make(chan *ConfigMessage),
		t:              t,
	}
	if err := cli.Start(); err != nil {
		ocd.Process.Kill()
		t.Fatalf("Couldn't start %v: %v\n", cli.name, err)
	}

	// Add new configuration from cli
	if err := doSetCli(setNICmd); err != nil {
		cli.Stop()
		ocd.Process.Kill()
		t.Fatal(err)
	}
	// Validate
	c := <-cli.confc
	if err := c.judgeConfResult(CM_Validate, expNI, false); err != nil {
		cli.Stop()
		ocd.Process.Kill()
		t.Fatal(err)
	}
	// Commit
	select {
	case <-cli.confc:
		cli.Stop()
		ocd.Process.Kill()
		t.Fatalf("Received a commit message unexpectedly.\n")

	case <-time.After(TIMEOUT * time.Millisecond):
		t.Log("Didn't receive a commit message expectedly.")
	}

	// tear down
	cli.Stop()
	if err := ocd.Process.Kill(); err != nil {
		t.Fatal("Couldn't stop OpenConfigd.: %v", err)
	}

	t.Log("Client didn't receive a commit message after return validation failed, test passed.")
}
