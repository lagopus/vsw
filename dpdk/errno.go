//
// Copyright 2018 Nippon Telegraph and Telephone Corporation.
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
#include <rte_errno.h>

int get_rte_errno() {
	return rte_errno;
}
*/
import "C"

import "syscall"

type Errno uintptr

func (e Errno) Error() string {
	switch e {
	case Errno(C.E_RTE_SECONDARY):
		return "Operation not allowed in secondary processes"
	case Errno(C.E_RTE_NO_CONFIG):
		return "Missing rte_config"
	}
	return syscall.Errno(e).Error()
}
