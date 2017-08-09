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

package dpdk

/*
#include <stdlib.h>
#include <rte_config.h>
#include <rte_launch.h>

extern int call_go_lcore_function(void *arg);
*/
import "C"

import (
	"unsafe"
)

type LcoreFunc *C.lcore_function_t
type LcoreGoFunc func(interface{}) int
type LcoreFuncData struct {
	fn  LcoreGoFunc
	arg interface{}
}

var serial = 0
var lcoreFuncs = make(map[int]*LcoreFuncData)

//export call_go_lcore_function
func call_go_lcore_function(cserial unsafe.Pointer) C.int {
	serial := int(*(*C.int)(cserial))
	if d := lcoreFuncs[serial]; d != nil {
		defer func() { lcoreFuncs[serial] = nil }()
		return C.int(d.fn(d.arg))
	}
	return 0
}

func EalRemoteLaunch(fn LcoreFunc, arg unsafe.Pointer, slave_id uint) int {
	return int(C.rte_eal_remote_launch(fn, arg, C.unsigned(slave_id)))
}

func EalRemoteLaunchGoFunc(fn LcoreGoFunc, arg interface{}, slave_id uint) int {
	lcoreFuncs[serial] = &LcoreFuncData{
		fn:  fn,
		arg: arg,
	}
	cserial := C.int(serial)
	serial++
	return int(EalRemoteLaunch((LcoreFunc)(C.call_go_lcore_function), unsafe.Pointer(&cserial), slave_id))
}

func EalWaitLcore(slave_id uint) int {
	return int(C.rte_eal_wait_lcore(C.unsigned(slave_id)))
}

func EalMpWaitLcore() {
	C.rte_eal_mp_wait_lcore()
}
