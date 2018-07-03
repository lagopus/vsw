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

package main

import (
	"flag"
	"fmt"
	_ "github.com/lagopus/vsw/modules/bridge"
	_ "github.com/lagopus/vsw/modules/ethdev"
	"github.com/lagopus/vsw/vswitch"
	"os"
	"os/signal"
	"syscall"
)

const defaultConfigPath = "/usr/local/etc/vsw.conf"

var log = vswitch.Logger

var quit = make(chan bool)

func initSignalHandling() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		for sig := range c {
			fmt.Printf("signal: %v\n", sig)
			quit <- true
		}
	}()
}

var settings = map[string]func() error{
	"l2_sample": l2_sample,
	//	"l3_sample1": l3_sample1,
	//	"l3_sample2": l3_sample2,
	//	"l3_sample3": l3_sample3,
}

func main() {
	flag.Parse()
	vswitch.EnableLog(logging)

	if err := vswitch.Init(configPath); err != nil {
		fmt.Println(err)
		return
	}

	initSignalHandling()

	f, ok := settings[setting]
	if !ok {
		fmt.Printf("Uknown setting: %s\n", setting)
	}

	done := make(chan bool)
	go func() {
		fmt.Printf("Starting: %v\n", setting)
		if err := f(); err != nil {
			fmt.Printf("error: %v\n", err)
			done <- true
			return
		}
		fmt.Printf("Ready\n")
		<-quit
		fmt.Printf("Quitting\n")
		done <- true
	}()

	fmt.Printf("Waiting...\n")
	<-done
	fmt.Printf("Done\n")
}

var configPath string
var logging bool
var setting string

func init() {
	flag.StringVar(&configPath, "f", defaultConfigPath, "Config file")
	flag.BoolVar(&logging, "v", false, "verbose mode")
	flag.StringVar(&setting, "s", "l2_sample", "VSW Setting (l2_sample or l3_sample[1-3]. Default: l2_sample)")
}
