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

// #cgo LDFLAGS: -llagopus_util -lnuma -Wl,-unresolved-symbols=ignore-in-object-files
// #cgo CFLAGS: -I ${SRCDIR} -I ${SRCDIR}/.. -I ${SRCDIR}/../hash -I ${SRCDIR}/../log -I /usr/local/include -I ${SRCDIR}/../../../include -D_GNU_SOURCE -m64 -pthread -O3 -msse4.2
import "C"
