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

package ocdc

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

type client struct {
	subscribePaths [][]string
	subscriber     *Subscriber
	server         *Server
	showPort       uint16
	cmdSpec        string

	name      string
	mtu       uint16
	ifType    string
	ifEnabled bool
	niType    string
	niEnabled bool
	valResult bool // validation result
	confc     chan *ConfigMessage
	showc     chan string
	t         *testing.T
}

// Start starts a client. cmdSpec can be "" if a server doesn't start.
func (cli *client) Start() error {
	cli.t.Logf("Start %v.", cli.name)
	var err error
	// start ocdclient service
	if cli.subscriber, err = Subscribe(cli.subscribePaths); err != nil {
		return err
	}
	// start a server
	if cli.cmdSpec != "" {
		if cli.server, err = RegisterServer(cli.cmdSpec, cli.showPort); err != nil {
			return err
		}
	}

	// configuration
	go func() {
		for recvConf := range cli.subscriber.C {
			cli.t.Logf("%s:", cli.name)
			cli.confc <- recvConf // send result to a test
			for _, c := range recvConf.Configs {
				cli.t.Logf("%v\n", c.Path)
			}
			switch recvConf.Mode {
			case CM_Validate:
				cli.subscriber.RC <- cli.Validate()

			case CM_Commit:
				cli.Commit(recvConf.Configs)
				cli.subscriber.RC <- true
			}
		}
		cli.t.Logf("client confc is closed.")
	}()

	// show command
	// Only show handler has a server.
	if cli.server != nil {
		go func() {
			for reqShow := range cli.server.C {
				cli.showc <- reqShow // send result to a test
				cli.t.Logf("%v\n", reqShow)
				if strings.Contains(reqShow, "mtu") {
					cli.server.RC <- fmt.Sprintf("%d", cli.mtu)
				} else if strings.Contains(reqShow, "enabled") {
					cli.server.RC <- fmt.Sprintf("%v", cli.ifEnabled)
				}
			}
		}()
	}
	return nil
}

// Stop stops a client.
func (cli *client) Stop() {
	cli.t.Logf("Stop %v.", cli.name)
	cli.subscriber.Unsubscribe()

	if cli.server != nil {
		close(cli.server.C)
		cli.server.UnregisterServer()
	}
}

func (cli *client) Validate() bool {
	cli.t.Logf("Validate requested for %v.", cli.name)
	return cli.valResult
}

func (cli *client) Commit(confs []*Config) {
	cli.t.Logf("Commit requested for %v.", cli.name)

	for _, c := range confs {
		if len(c.Path) < 4 {
			continue
		}
		switch c.Path[0] {
		case "interfaces":
			switch c.Path[4] {
			case "type":
				cli.ifType = c.Path[5]

			case "mtu":
				mtu, _ := strconv.ParseUint(c.Path[5], 10, 16)
				cli.mtu = uint16(mtu)

			case "enabled":
				cli.ifEnabled, _ = strconv.ParseBool(c.Path[5])
			}

		case "network-instances":
			switch c.Path[4] {
			case "type":
				cli.niType = c.Path[5]
			case "enabled":
				cli.niEnabled, _ = strconv.ParseBool(c.Path[5])
			}
		}
	}
}

// judgeConfResult judges whether or not configuration results have a match to the expected values.
func (cm *ConfigMessage) judgeConfResult(mode ConfigMode, expects []string, dupTest bool) error {
	if cm.Mode != mode {
		return fmt.Errorf("Received a %v message unexpectedly.", mode)
	}

nextConfig:
	for _, result := range cm.Configs {
		r := strings.Join(result.Path, " ")
		for _, e := range expects {
			if r == e {
				continue nextConfig
			}
		}
		return fmt.Errorf("[%v] is different from expected.", r)
	}

	if dupTest {
		if err := judgeDuplicate(cm.Configs); err != nil {
			return err
		}
	}
	return nil
}

// judgeDuplicate judges whether or not confs doesn't have duplicate path.
func judgeDuplicate(confs []*Config) error {
	if len(confs) == 1 {
		return nil
	}

	dup := make(map[string]struct{})
	for _, conf := range confs {
		path := strings.Join(conf.Path, " ")
		if _, exists := dup[path]; exists {
			return errors.New("Received configs has duplicate path.")
		}
		dup[path] = struct{}{}
	}
	return nil
}

// startOcd starts OpenConfigd. file is a path of configuration file.
func startOcd(file string) (*exec.Cmd, error) {
	options := []string{
		"-2",
		"-c",
		file,
		"-z",
		"--yang-paths=modules:modules/interfaces:modules/vlan:modules/network-instance:modules/types",
		"lagopus-router.yang",
	}
	if file == "" {
		options = append(options[:1], options[3:]...) // Delete "-c file" option
	}

	ocd := exec.Command("openconfigd", options...)
	ocd.Dir = os.ExpandEnv("$GOPATH") + "/src/github.com/lagopus/vrouter-yang/yang"
	err := ocd.Start()
	if err != nil {
		return nil, err
	}
	time.Sleep(1 * time.Second) // Wait for starting OpenConfigd

	return ocd, nil
}

// doSetCli sets a new configuration from cli.
func doSetCli(cliCmd string) error {
	var (
		prefix = `
			source /etc/bash_completion.d/cli
			configure
			`
		suffix = `
			commit
			`
	)
	cmd := exec.Command("/usr/local/bin/cli")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("Couldn't connected to the cli's standard input.: %v", err)
	}

	line := prefix + cliCmd + suffix
	io.WriteString(stdin, line)
	stdin.Close()
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("Couldn't start cli.: %v", err)
	}
	return nil
}

const confFile = "/tmp/openconfigd.conf"

var (
	subscribePaths = [][]string{{"interfaces", "interface"}, {"network-instances", "network-instance"}}

	expIfInit = []string{
		"interfaces interface if0",
		"interfaces interface if0 config enabled true",
		"interfaces interface if0 config mtu 1000",
		"interfaces interface if0 config type ethernetCsmacd",
	}
	expIf = []string{
		"interfaces interface if0 config mtu 1000",
		"interfaces interface if0 config mtu 1500",
	}
	expNI = []string{
		"network-instances network-instance vsi0",
		"network-instances network-instance vsi0 config enabled true",
	}

	setNICmd = `set network-instances network-instance vsi0 config enabled true`
	setIfCmd = `set interfaces interface if0 config mtu 1500`
)

func TestMain(m *testing.M) {
	// Initial configuration file for OpenConfigd
	configure := []byte(`
interfaces {
	interface if0 {
		config {
			enabled true;
			mtu 1000;
			type ethernetCsmacd;
		}
	}
}
`)

	// Make configration file
	ioutil.WriteFile(confFile, configure, 0666)

	// Execute test
	rc := m.Run()

	// Tear down
	os.Remove(confFile)

	// Done
	os.Exit(rc)
}
