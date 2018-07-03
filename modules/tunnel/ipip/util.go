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

package ipip

/*
#cgo CFLAGS: -I ${SRCDIR}/.. -I${SRCDIR}/../../../include -I/usr/local/include/dpdk -m64 -pthread -O3 -msse4.2
#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all -L/usr/local/lib -ldpdk

#include "ipip.h"
*/
import "C"

import (
	"net"
)

func ip2ipAddr(from net.IP) (to C.struct_ip_addr) {
	// struct ip_addr is seem to [16]byte in Go
	from4 := from.To4()
	if from4 != nil { // IPv4
		copy(to.ip[:], []byte{from4[3], from4[2], from4[1], from4[0]})
	} else { // IPv6
		copy(to.ip[:], from[:])
	}
	return
}
