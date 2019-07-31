//
// Copyright 2017-2019 Nippon Telegraph and Telephone Corporation.
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

package vxlan

// #include "lagopus_apis.h"
// #include "eventq.h"
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/lagopus/vsw/modules/tunnel/log"
)

const (
	// MaxBatches MAX_BATCHES.
	MaxBatches uint64 = C.MAX_BATCHES
)

// CEventqEntry struct eventq_entry.
type CEventqEntry C.struct_eventq_entry

// CmdType Get cmd_type.
func (d *CEventqEntry) CmdType() L2tunCmd {
	return L2tunCmd(d.cmd_type)
}

// VNI Get vni.
func (d *CEventqEntry) VNI() VNI {
	return VNI(d.vni)
}

// FDBEntry Get fdb_entry.
func (d *CEventqEntry) FDBEntry() *CFDBEntry {
	entry := CFDBEntry(d.fdb_entry)
	return &entry
}

// GetEvents Call vxlan_get_events().
func GetEvents() ([]CEventqEntry, error) {
	var entries [MaxBatches]CEventqEntry
	var num uint64

	if ret := C.vxlan_get_events(
		(*C.struct_eventq_entry)(unsafe.Pointer(&entries[0])),
		(*C.size_t)(unsafe.Pointer(&num))); ret != C.LAGOPUS_RESULT_OK {
		err := fmt.Errorf("Fail vxlan_get_events(): %v", ret)
		log.Logger.Err("%v", err)
		return nil, err
	}

	return entries[:num], nil
}
