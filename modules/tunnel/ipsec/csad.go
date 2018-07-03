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

package ipsec

// #include "sa.h"
// #include "sad_go.h"
import "C"
import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/lagopus/vsw/vswitch"
)

// CSACtx struct sa_ctx.
type CSACtx *C.struct_sa_ctx

// CSPI spi.
type CSPI C.uint32_t

// SadbAcquireFunc send SADB_ACQUIRE message. if success, returns true
type SadbAcquireFunc func(vswitch.VRFIndex, uint32, *net.IPNet, *net.IPNet) bool

// SAD CSAD interface.
type SAD interface {
	Push(entArr []CSA) int
	PullLifetime(spi CSPI) (time.Time, uint64, error)
	PullAcquired() (err error)
	RegisterAcquireFunc(fn SadbAcquireFunc)
	String() string
}

// BaseCSAD Base SAD.
type BaseCSAD struct {
	ctx         *C.struct_sa_ctx
	dir         DirectionType
	vrfIndex    vswitch.VRFIndex
	acquireFunc SadbAcquireFunc
}

// NewBaseCSAD Create BaseCSAD.
func NewBaseCSAD(vrfIndex vswitch.VRFIndex, dir DirectionType) BaseCSAD {
	return BaseCSAD{
		vrfIndex: vrfIndex,
		dir:      dir,
	}
}

// Set ctx.
func (sad *BaseCSAD) setSaCtx() {
	if sad.ctx == nil {
		if m, err := module(sad.dir); err == nil {
			if m.cmodule != nil {
				sad.ctx = *C.ipsec_get_sad(m.cmodule, C.vrfindex_t(sad.vrfIndex))
				log.Printf("get SADB-%v sa_ctx(%v) => %p", sad.dir, m, sad.ctx)
			}
		}
	}
}

// Push Push sa.
func (sad *BaseCSAD) Push(entArr []CSA) int {
	var entPtr *C.struct_ipsec_sa
	var entLen C.size_t

	sad.setSaCtx()
	entLen = (C.size_t)(len(entArr))
	if entLen > 0 {
		entPtr = (*C.struct_ipsec_sa)(&entArr[0])
	}
	return int(C.sad_push(sad.ctx, entPtr, entLen, sad.dir.Role()))
}

// PullLifetime Pull lifetime.
func (sad *BaseCSAD) PullLifetime(spi CSPI) (time.Time, uint64, error) {
	var lifetime C.time_t
	var byte C.uint64_t
	var err error

	sad.setSaCtx()
	if C.load_sa_atomically(sad.ctx, C.uint32_t(spi), &lifetime, &byte) == false {
		err = fmt.Errorf("pull SA-%v(%d) failed", sad.dir, spi)
	}

	return time.Unix((int64)(lifetime), 0), uint64(byte), err
}

// String String.
func (sad *BaseCSAD) String() string {
	return fmt.Sprintf("dir: %v, ctx: %v", sad.dir, sad.ctx)
}
