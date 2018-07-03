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

package vswitch

// Init initializes vswitch core. Init shall be called
// before instantiating VRF, VSI, or Interfaces.
// Only EnableLog maybe called before Init.
// ConfigPath is a path to the configuration file.
// Returns error on failure.
func Init(configPath string) error {
	if err := GetConfig().setPath(configPath); err != nil {
		return err
	}
	return initDpdk()
}

// Deinit cleans all held resource up.
func Deinit() {
	// TODO: implement deinit to ensure resources are all freed.
}
