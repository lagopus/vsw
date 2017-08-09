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

/*
#include <stdbool.h>

extern void lagopus_verbose(bool);
*/
import "C"

import (
	"io"
	"io/ioutil"
	"log"
	"os"
)

// Logger is logging facility to be used by all entities in the router.
var Logger *log.Logger
var logWriter io.Writer

//export LoggerPrint
func LoggerPrint(cstr *C.char) {
	Logger.Print(C.GoString(cstr))
}

//export LoggerFatal
func LoggerFatal(cstr *C.char) {
	Logger.Fatal(C.GoString(cstr))
}

// EnableLog enables or disable logging.
func EnableLog(e bool) {
	if e {
		Logger.SetFlags(log.LstdFlags)
		Logger.SetOutput(logWriter)
	} else {
		Logger.SetFlags(0)
		Logger.SetOutput(ioutil.Discard)
	}
	C.lagopus_verbose(C.bool(e))
}

// SetLogOutput changes output of the log and enable logging, if not enabled.
// Default log output is standard out.
func SetLogOutput(w io.Writer) {
	logWriter = w
	EnableLog(true)
}

func init() {
	logWriter = os.Stdout
	Logger = log.New(logWriter, "", log.LstdFlags)
}
