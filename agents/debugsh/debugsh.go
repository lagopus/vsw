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

	"github.com/lagopus/vsw/vswitch"
	"github.com/lagopus/vsw/vswitch/log"
	"github.com/reiver/go-telnet"
	"github.com/reiver/go-telnet/telsh"
)

const AgentName = "debugsh"

var logger = vswitch.Logger

/*
 * dshLogger supports telnet.Logger interface.
 */
type dshLogger struct {
	logger *log.Logger
}

func (d *dshLogger) Debug(args ...interface{}) {
	d.logger.Debug(0, "%v", args)
}

func (d *dshLogger) Debugf(s string, args ...interface{}) {
	d.logger.Debug(0, s, args...)
}

func (d *dshLogger) Error(args ...interface{}) {
	d.logger.Err("%v", args)
}

func (d *dshLogger) Errorf(s string, args ...interface{}) {
	d.logger.Err(s, args...)
}

func (d *dshLogger) Trace(args ...interface{}) {
	d.logger.Info("%v", args)
}

func (d *dshLogger) Tracef(s string, args ...interface{}) {
	d.logger.Info(s, args...)
}

func (d *dshLogger) Warn(args ...interface{}) {
	d.logger.Warning("%v", args)
}

func (d *dshLogger) Warnf(s string, args ...interface{}) {
	d.logger.Warning(s, args...)
}

func fprintf(w io.Writer, f string, args ...interface{}) {
	io.WriteString(w, fmt.Sprintf(f+"\r\n", args...))
}

// DebugShell agent
type DebugShell struct{}

type debugShellCommand struct {
	name     string
	producer telsh.ProducerFunc
	help     string
}

func (dsc debugShellCommand) String() string {
	return dsc.name + "\t" + dsc.help
}

var commands = []debugShellCommand{
	{"help", telsh.ProducerFunc(helpProducer), "Help."},
	{"show", telsh.ProducerFunc(showProducer), "Show vswitch status."},
	{"module", telsh.ProducerFunc(moduleProducer), "Debug module."},
}

func (d *DebugShell) Enable() error {
	logger.Debug(0, "Enabling")

	handler := telsh.NewShellHandler()

	for _, cmd := range commands {
		handler.Register(cmd.name, cmd.producer)
		registerHelp(cmd.name, cmd.help)
	}

	go func() {
		logger.Debug(0, "Launching telnet.")
		server := &telnet.Server{Addr: ":5555", Handler: handler, Logger: &dshLogger{logger}}
		if err := server.ListenAndServe(); err != nil {
			logger.Err("Can't launch telnet service: %v", err)
		}
	}()

	logger.Debug(0, "Enabled")
	return nil
}

func (d *DebugShell) Disable() {
	logger.Info("Can't disable debugsh once its started.")
}

func (d *DebugShell) String() string {
	return AgentName
}

func init() {
	if l, err := log.New(AgentName); err == nil {
		logger = l
	} else {
		logger.Fatalf("Can't create logger for %s: %v", err, AgentName)
	}

	dbgshInstance := &DebugShell{}

	vswitch.RegisterAgent(dbgshInstance)
}
