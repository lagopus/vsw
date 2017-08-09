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
#include <rte_malloc.h>
*/
import "C"

import "unsafe"

func toCtype(t string) *C.char {
	if t != "" {
		return C.CString(t)
	}
	return nil
}

func Malloc(t string, size uint64, align uint) unsafe.Pointer {
	return unsafe.Pointer(C.rte_malloc(toCtype(t), C.size_t(size), C.unsigned(align)))
}

func ZMalloc(t string, size uint64, align uint) unsafe.Pointer {
	return unsafe.Pointer(C.rte_zmalloc(toCtype(t), C.size_t(size), C.unsigned(align)))
}

func Free(ptr unsafe.Pointer) {
	C.rte_free(ptr)
}
