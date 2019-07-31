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
// for testing only

package log

/*
#define DEBUG

#include <stdlib.h>
#include "../../include/logger.h"

static void test_vsw_printf(const char *s) {
        vsw_printf(s);
}

static int test_vsw_log_getid(const char *name) {
        return vsw_log_getid(name);
}

static const char *template = "[%s]: %s";

static void test_vsw_log_fatal(int id, const char *fmt) {
	vsw_msg_fatal(id, template, "fatal", fmt);
}

static void test_vsw_log_error(int id, const char *fmt) {
	vsw_msg_error(id, template, "err", fmt);
}

static void test_vsw_log_warning(int id, const char *fmt) {
	vsw_msg_warning(id, template, "warning", fmt);
}

static void test_vsw_log_info(int id, const char *fmt) {
	vsw_msg_info(id, template, "info", fmt);
}

static void test_vsw_log_debug(int id, int level, const char *fmt) {
	vsw_msg_debug(id, level, template, "debug", fmt);
}
*/
import "C"

import "unsafe"

// Test stub for logger C API.

func vsw_printf(s string) {
	cs := C.CString(s)
	defer C.free(unsafe.Pointer(cs))
	C.test_vsw_printf(cs)
}

func vsw_log_getid(n string) int {
	cn := C.CString(n)
	defer C.free(unsafe.Pointer(cn))
	return int(C.test_vsw_log_getid(cn))
}

func vsw_log_debug(id, level int, fmt string) {
	cft := C.CString(fmt)
	defer C.free(unsafe.Pointer(cft))
	C.test_vsw_log_debug(C.int(id), C.int(level), cft)
}

func vsw_log_emit(id int, t logType, fmt string) {
	cft := C.CString(fmt)
	defer C.free(unsafe.Pointer(cft))

	switch t {
	case tFatal:
		C.test_vsw_log_fatal(C.int(id), cft)
	case tErr:
		C.test_vsw_log_error(C.int(id), cft)
	case tWarning:
		C.test_vsw_log_warning(C.int(id), cft)
	case tInfo:
		C.test_vsw_log_info(C.int(id), cft)
	case tDebug:
		C.test_vsw_log_debug(C.int(id), 0, cft)
	}
}
