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

// #include "ipsec.h"
import "C"
import "fmt"

// CPORT Port in C.
type CPORT C.uint8_t

// CMAC Mac addr in C.
type CMAC C.uint64_t

// AddIPsecAddEthaddr Add ethaddr for config.
func AddIPsecAddEthaddr(port CPORT, srcMac CMAC, dstMac CMAC) error {
	mac := &C.struct_ethaddr_info{
		src: C.uint64_t(srcMac),
		dst: C.uint64_t(dstMac),
	}
	if r := C.ipsec_add_ethaddr(C.uint8_t(port), mac); r != C.LAGOPUS_RESULT_OK {
		return fmt.Errorf("Can't set mac addr")
	}
	return nil
}
