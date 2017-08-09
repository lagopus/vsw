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

package main

import (
	"flag"
	"github.com/lagopus/vsw/agents/config"
	_ "github.com/lagopus/vsw/agents/netlink"
	_ "github.com/lagopus/vsw/agents/vrrp"
	_ "github.com/lagopus/vsw/modules/bridge"
	_ "github.com/lagopus/vsw/modules/hostif"
	_ "github.com/lagopus/vsw/modules/l3"
	_ "github.com/lagopus/vsw/modules/tap"
	_ "github.com/lagopus/vsw/modules/vif"
	"github.com/lagopus/vsw/vswitch"
	"os"
	"os/signal"
	"syscall"
)

var log = vswitch.Logger

func initDpdk() {
	dc := &vswitch.DpdkConfig{
		CoreMask:      0xfe,
		MemoryChannel: 2,
	}

	if coreMask != 0 {
		dc.CoreMask = coreMask
	} else if coreList != "" {
		dc.CoreList = coreList
		dc.CoreMask = 0
	}
	if pmdPath != "" {
		dc.PmdPath = pmdPath
	}

	dc.Vdevs = flag.Args()

	if !vswitch.InitDpdk(dc) {
		log.Fatalf("DPDK initialization failed.\n")
	}
}

var quit = make(chan int)

func initSignalHandling() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		for sig := range c {
			log.Printf("signal: %v\n", sig)
			close(quit)
		}
	}()
}

func main() {
	flag.Parse()
	vswitch.EnableLog(logging)

	initDpdk()

	initSignalHandling()

	// Start DP Agents
	agents := vswitch.StartNamedAgents("Netlink Agent", "Config Agent", "vrrp")
	for _, agent := range agents {
		vswitch.Logger.Printf("Agent %v started.\n", agent)
	}

	// Wait for Config Agent to complete configuration
	if agent, err := vswitch.GetAgent("Config Agent"); err == nil {
		if c, ok := agent.(config.ConfigAgentAPI); ok {
			vswitch.Logger.Printf("Waiting for Config Agent to set up modules")
			c.Wait()
			vswitch.Logger.Printf("Ready to start")

		}
	} else {
		vswitch.Logger.Fatalf("error: %v", err)
	}

	// Start threads
	vswitch.Start()

	// Wait for signal
	<-quit

	// Tear down
	vswitch.Stop()

	// Wait...
	vswitch.Wait()

	// Stop Agents
	for _, agent := range agents {
		agent.Stop()
	}
}

var logging bool
var coreMask int
var coreList string
var pmdPath string

func init() {
	flag.BoolVar(&logging, "v", false, "verbose mode")
	flag.IntVar(&coreMask, "c", 0, "DPDK core mask")
	flag.StringVar(&coreList, "l", "", "DPDK core list")
	flag.StringVar(&pmdPath, "p", "", "DPDK PMD path")
}
