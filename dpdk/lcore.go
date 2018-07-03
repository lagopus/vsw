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
#include <rte_config.h>
#include <rte_lcore.h>
*/
import "C"

const MaxLcore = uint(C.RTE_MAX_LCORE)

func LcoreId() uint {
	return uint(C.rte_lcore_id())
}

func LcoreIsEnabled(lcore_id uint) bool {
	return C.rte_lcore_is_enabled(C.unsigned(lcore_id)) != 0
}

func GetMasterLcore() uint {
	return uint(C.rte_get_master_lcore())
}

func LcoreCount() uint {
	return uint(C.rte_lcore_count())
}

func LcoreToSocketId(lcore_id uint) uint {
	return uint(C.rte_lcore_to_socket_id(C.unsigned(lcore_id)))
}
