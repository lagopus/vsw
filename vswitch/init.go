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

package vswitch

import (
	"fmt"

	"github.com/lagopus/vsw/vswitch/log"
)

type loggerConfig struct {
	Logging log.LogConfig
}

var logger *log.Logger
var Logger = log.DefaultLogger() // for backward compatibility

// Init initializes vswitch core. Init shall be called
// before instantiating VRF, VSI, or Interfaces.
// Only EnableLog maybe called before Init.
// ConfigPath is a path to the configuration file.
// Returns error on failure.
func Init(configPath string) error {
	if err := GetConfig().setPath(configPath); err != nil {
		return err
	}

	// Enable log after setting config path.
	logConfig := loggerConfig{log.DefaultLogConfig}

	if _, err := GetConfig().Decode(&logConfig); err != nil {
		return fmt.Errorf("Can't parse [logging]: %v", err)
	}

	if err := log.Init(&logConfig.Logging); err != nil {
		return err
	}

	// Open logger for the core
	l, err := log.New("core")
	if err != nil {
		return fmt.Errorf("Can't get logger for core: %v", err)
	}
	logger = l

	// Initialize DPDK first
	if err := initDpdk(); err != nil {
		return err
	}

	// Initialize agents
	initAgents()

	// Enable agents
	return enableAgents()
}

// Deinit cleans all held resource up.
func Deinit() {
	disableAgents()

	// TODO: implement deinit to ensure resources are all freed.
}
