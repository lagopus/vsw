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

// Start starts vsw modules.
// Returns true if modules started successively.
func Start() bool {
	Logger.Printf("Starting modules.")
	for _, m := range modules {
		if !m.Start() {
			Logger.Printf("Module '%s' failed to start.", m.Name())
		}
	}
	return true
}

// Stop stops vsw modules.
// It doesn't wait for modules to actually stop.
// It just requests modules to stop.
// If needed call Wait() to wait for modules to stop.
func Stop() {
	Logger.Printf("Stopping modules.")
	for _, m := range modules {
		m.Stop()
	}
	return
}

// Wait watis for vsw modules to actually stop.
func Wait() {
	Logger.Printf("Waiting for modules to stop.")
	for _, m := range modules {
		m.Wait()
	}
	return
}
