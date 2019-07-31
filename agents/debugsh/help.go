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
	"io"

	"github.com/reiver/go-telnet"
	"github.com/reiver/go-telnet/telsh"
)

type help struct {
	Command string
	Text    string
}

var helps []help

func (h help) String() string {
	return h.Command + ": " + h.Text
}

func registerHelp(name string, text string) {
	helps = append(helps, help{name, text})
}

func helpHandler(stdin io.ReadCloser, stdout io.WriteCloser, stderr io.WriteCloser, args ...string) error {
	logger.Info("help: %v", args)

	if len(args) == 0 {
		outputResult(stdout, helps)
		return nil
	}

	return nil
}

func helpProducer(ctx telnet.Context, name string, args ...string) telsh.Handler {
	return telsh.PromoteHandlerFunc(helpHandler, args...)
}
