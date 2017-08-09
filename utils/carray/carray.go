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

package carray

/*
#include <stdio.h>
#include <string.h>
*/
import "C"

import "unsafe"

// Dup creates a copy of given memory. Normally, used to create
// a C array from Go slice, e.g.
//	data := []uint64{1, 2, 3}
//	length := C.sizeof_uint64_t * C.size_t(len(data))
//	carray := carray.Dup(unsafe.Pointer(&data[0]), length)
func Dup(src unsafe.Pointer, length int) unsafe.Pointer {
	if length == 0 {
		return nil
	}
	len := C.size_t(length)
	dst := C.malloc(len)
	C.memcpy(dst, src, len)
	return dst
}

// DupPointers creates an array of pointers from given slice.
// Src points to the first element in the slice. Count is a number
// of elements in the slice, i.e. number of pointers.
func DupPointers(src unsafe.Pointer, count int) unsafe.Pointer {
	len := C.sizeof_NULL * count
	return Dup(src, len)
}
