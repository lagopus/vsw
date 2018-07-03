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

// Create a client without paths to subscribe.
// Should fail to create.
func TestCreateModWithoutPath(t *testing.T) {
	// start OpenConfigd
	ocd, err := startOcd("")
	if err != nil {
		t.Fatalf("Couldn't start OpenConfigd.: %v\n", err)
	}
	SetOcdServer("", uint16(2650))

	// start clients
	nilCli := &client{
		name:           "nilPath-client",
		subscribePaths: nil,
		t:              t,
	}
	if err := nilCli.Start(); err == nil {
		nilCli.Stop()
		ocd.Process.Kill()
		t.Fatal("%s: Client without paths been created unexpectedly.\n", nilCli.name)
	}
	t.Logf("%s couldn't start expectedly.\n", nilCli.name)

	make0Cli := &client{
		name:           "make0Path-client",
		subscribePaths: make([][]string, 0),
		t:              t,
	}
	if err := make0Cli.Start(); err == nil {
		make0Cli.Stop()
		ocd.Process.Kill()
		t.Fatal("%s: Client without paths been created unexpectedly.\n", make0Cli.name)
	}
	t.Logf("%s couldn't start expectedly.\n", make0Cli.name)

	// tear down
	if err := ocd.Process.Kill(); err != nil {
		t.Fatal("Couldn't stop OpenConfigd.: %v\n", err)
	}
	t.Log("Client without paths test passed.")
}
