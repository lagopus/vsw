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
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
)

type showResult struct {
	out string
	err error
}

// doShowIf executes a show command about Interface information.
func (cli *client) doShowIf(stat string, rc chan *showResult) {
	cmd := exec.Command("/usr/local/bin/cli")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		rc <- &showResult{
			err: fmt.Errorf("Couldn't connected to the cli's standard input.: %v", err),
		}
		return
	}

	io.WriteString(stdin, `
		source /etc/bash_completion.d/cli
		show interfaces interface if0 config `+stat+`
	`)
	stdin.Close()
	out, err := cmd.Output()
	if err != nil {
		rc <- &showResult{
			err: fmt.Errorf("Couldn't start cli.: %v", err),
		}
		return
	}

	rc <- &showResult{
		out: strings.TrimRight(string(out), "\n"),
	}
}

// judgeShowResult judges whether or not a show result has a match to the expected value.
func (cli *client) judgeShowResult(expCmd, expValue string, rc chan *showResult) error {
	for i := 0; i < 2; i++ {
		select {
		case recvCmd := <-cli.showc:
			if strings.Compare(expCmd, recvCmd) != 0 {
				return errors.New("show command is different from expected.")
			}

		case r := <-rc:
			if r.err != nil {
				return r.err
			}
			if strings.Compare(expValue, r.out) != 0 {
				return fmt.Errorf("show mtu failed: expect=%v result=%v", expValue, r.out)
			}
		}
	}
	return nil
}

// Register show commands and execute the command from cli.
// Should fail the fallowing cases.
//    - Received command is different from the registered command.
//    - Result of the command is different from the expected value.
func TestOcdcShow(t *testing.T) {
	var (
		// cmdSpec is show command specifications to register to an RPC server.
		// Should set mode to "exec".
		cmdSpec = `
[
	{
		"line": "show interfaces interface [WORD] config mtu",
		"mode": "exec",
		"helps": [
			"Show running system information",
			"Interface information",
			"Interface mtu"
		]
	},
	{
		"line": "show interfaces interface [WORD] config enabled",
		"mode": "exec",
		"helps": [
			"Show running system information",
			"Interface information",
			"Interface enabled"
		]
	}
]
`
		expMtuInit    = "1000"
		expMtu        = "1500"
		expEnabled    = "true"
		expCmdMtu     = "show interfaces interface if0 config mtu"
		expCmdEnabled = "show interfaces interface if0 config enabled"
	)

	// start OpenConfigd
	ocd, err := startOcd(confFile)
	if err != nil {
		t.Fatalf("Couldn't start OpenConfigd.: %v\n", err)
	}
	SetOcdServer("", uint16(2650))

	// start a client
	cli := &client{
		name:           "client0",
		showPort:       uint16(2651),
		cmdSpec:        cmdSpec,
		subscribePaths: subscribePaths,
		valResult:      true,
		confc:          make(chan *ConfigMessage),
		showc:          make(chan string),
		t:              t,
	}
	if err := cli.Start(); err != nil {
		ocd.Process.Kill()
		t.Fatalf("Couldn't start %v.: %v\n", cli.name, err)
	}

	// Receive initial configuration
	for i := 0; i < 2; i++ {
		c := <-cli.confc
		if err := c.judgeConfResult(ConfigMode(i), expIfInit, false); err != nil {
			cli.Stop()
			ocd.Process.Kill()
			t.Fatal(err)
		}
	}
	if !cli.ifEnabled || cli.mtu != 1000 || strings.Compare(cli.ifType, "ethernetCsmacd") != 0 {
		cli.Stop()
		ocd.Process.Kill()
		t.Fatal("Commit failed.\n")
	}
	// show mtu
	rc := make(chan *showResult)
	go cli.doShowIf("mtu", rc)
	if err := cli.judgeShowResult(expCmdMtu, expMtuInit, rc); err != nil {
		cli.Stop()
		ocd.Process.Kill()
		t.Fatal(err)
	}
	// show enabled
	go cli.doShowIf("enabled", rc)
	if err := cli.judgeShowResult(expCmdEnabled, expEnabled, rc); err != nil {
		cli.Stop()
		ocd.Process.Kill()
		t.Fatal(err)
	}

	// Add new configuration from cli
	if err := doSetCli(setIfCmd); err != nil {
		cli.Stop()
		ocd.Process.Kill()
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		c := <-cli.confc
		if err := c.judgeConfResult(ConfigMode(i), expIf, false); err != nil {
			cli.Stop()
			ocd.Process.Kill()
			t.Fatal(err)
		}
	}
	if cli.mtu != 1500 {
		cli.Stop()
		ocd.Process.Kill()
		t.Fatal("Commit failed.\n")
	}
	// show mtu
	go cli.doShowIf("mtu", rc)
	if err := cli.judgeShowResult(expCmdMtu, expMtu, rc); err != nil {
		cli.Stop()
		ocd.Process.Kill()
		t.Fatal(err)
	}

	// tear down
	cli.Stop()
	if err := ocd.Process.Kill(); err != nil {
		t.Fatal("Couldn't stop OpenConfigd.: %v\n", err)
	}

	t.Log("show command results is expected, show command test passed.")
}
