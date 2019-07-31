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

// #include "module.h"
// #include "ipsec.h"
import "C"

// CParams Parameters for IPsec cmodule.
type CParams C.struct_ipsec_params

// NewCParams Create Params.
func NewCParams() CParams {
	return CParams{}
}

// SetRole Setb role.
func (ps *CParams) SetRole(direction DirectionType) {
	ps.role = direction.Role()
}

// SetCoreInfo Set core mask.
func (ps *CParams) SetCoreInfo(coreBind bool, imask, omask uint64) {
	ps.is_core_bind = C.bool(coreBind)
	ps.inbound_core_mask = C.uint64_t(imask)
	ps.outbound_core_mask = C.uint64_t(omask)
}
