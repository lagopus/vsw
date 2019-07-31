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

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/lagopus/vsw/agents/config"
	_ "github.com/lagopus/vsw/agents/debugsh"
	_ "github.com/lagopus/vsw/agents/netlink"
	_ "github.com/lagopus/vsw/agents/tunnel/ipsec"
	_ "github.com/lagopus/vsw/modules/bridge"
	_ "github.com/lagopus/vsw/modules/ethdev"
	_ "github.com/lagopus/vsw/modules/hostif"
	_ "github.com/lagopus/vsw/modules/rif"
	_ "github.com/lagopus/vsw/modules/router"
	_ "github.com/lagopus/vsw/modules/tap"
	_ "github.com/lagopus/vsw/modules/tunnel"
	"github.com/lagopus/vsw/vswitch"
)

const defaultConfigPath = "/usr/local/etc/vsw.conf"

var log = vswitch.Logger
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

	if err := vswitch.Init(configPath); err != nil {
		fmt.Println(err)
		return
	}

	initSignalHandling()

	// Wait for signal
	<-quit

	vswitch.Deinit()
}

var configPath string

func init() {
	flag.StringVar(&configPath, "f", defaultConfigPath, "Config file")
}
