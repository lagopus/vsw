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

package vswitch

import (
	"fmt"
	"io"
)

func Dump(w io.Writer) error {
	// VRF
	vrfs := GetAllVRF()
	io.WriteString(w, fmt.Sprintf("%d VRF(s)", len(vrfs)))
	for _, vrf := range vrfs {
		io.WriteString(w, vrf.Dump())
	}
	io.WriteString(w, "\n")

	// VIF
	for _, vif := range vifs {
		io.WriteString(w, vif.Dump()+"\n")
	}

	return nil
}
