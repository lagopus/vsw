//
// Copyright 2019 Nippon Telegraph and Telephone Corporation.
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
package debugsh

import (
	"fmt"
	"io"

	"github.com/reiver/go-telnet"
	"github.com/reiver/go-telnet/telsh"
)

var modules = make(map[string]ModuleFunc)
var validModules string

type ModuleFunc interface {
	ModuleShow(args ...string) (interface{}, error)
}

// RegisterModuleFunc registers a module with the given name
// to debugsh agent.
func RegisterModuleFunc(name string, mf ModuleFunc) error {
	if _, exists := modules[name]; exists {
		return fmt.Errorf("Module %s already registered.", name)
	}
	modules[name] = mf

	if validModules != "" {
		validModules += ", "
	}
	validModules += name

	return nil
}

func moduleHandler(stdin io.ReadCloser, stdout io.WriteCloser, stderr io.WriteCloser, args ...string) error {
	logger.Info("module: %v", args)

	if len(args) == 0 {
		outputErr(stdout, "valid modules are: %v", validModules)
		return nil
	}

	if m, ok := modules[args[0]]; ok {
		result, err := m.ModuleShow(args[1:]...)

		if err == nil {
			outputResult(stdout, result)
		} else {
			outputErr(stdout, "%v", err)
		}
	} else {
		outputErr(stdout, "unknown module: %s", args[0])
	}

	return nil
}

func moduleProducer(ctx telnet.Context, name string, args ...string) telsh.Handler {
	return telsh.PromoteHandlerFunc(moduleHandler, args...)
}
