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

package ipsec

// #include "sa.h"
// #include "sad_go.h"
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/lagopus/vsw/vswitch"
)

// CSADOutbound For Outbound.
type CSADOutbound struct {
	BaseCSAD
}

// NewCSADOutbound New Outbound.
func NewCSADOutbound(vrfIndex vswitch.VRFIndex) *CSADOutbound {
	return &CSADOutbound{
		BaseCSAD: NewBaseCSAD(vrfIndex, DirectionTypeOut),
	}
}

// RegisterAcquireFunc Register AcquireFunc.
func (sad *CSADOutbound) RegisterAcquireFunc(fn SadbAcquireFunc) {
	sad.acquireFunc = fn
}

// PullAcquired Pull acquired. Only Outbound.
func (sad *CSADOutbound) PullAcquired() (err error) {
	// memo: SADB_ACQUIRE is triggered by outbound packet only.
	sad.setSaCtx()
	if sad.ctx != nil {
		acqPtr := C.get_acquires(sad.ctx)
		if acqPtr != nil {
			defer C.free(unsafe.Pointer(acqPtr))
			acquires := (*[1 << 30]C.struct_sadb_acquire)(unsafe.Pointer(acqPtr))[:C.IPSEC_SA_MAX_ENTRIES]
			for i := 0; i < C.IPSEC_SA_MAX_ENTRIES; i++ {
				acq := acquires[i]
				if uint32(acq.sp_entry_id) != 0 {
					ver := int(acq.ip_ver)
					entryID := uint32(acq.sp_entry_id)
					src := ipAddr2ipNet(ver, acq.src, nil) // mask is nil
					dst := ipAddr2ipNet(ver, acq.dst, nil) // mask is nil
					if sad.acquireFunc != nil {
						ret := sad.acquireFunc(sad.vrfIndex, entryID, &src, &dst)
						if ret == false {
							err = fmt.Errorf("Failed to send SADB_ACQUIRE: src=%s, dst=%s", src, dst)
						}
					} else {
						err = fmt.Errorf("Failed to not found acquireFunc: src=%s, dst=%s", src, dst)
					}
				}
			}
		}
	}
	return
}
