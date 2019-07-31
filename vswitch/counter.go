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

package vswitch

/*
#include <stdlib.h>
#include <time.h>

#include "../include/counter.h"
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"time"
	"unsafe"
)

type Counter C.struct_vsw_counter

func (c *Counter) InOctets() uint64 {
	return uint64(c.in_octets)
}

func (c *Counter) InUnicastPkts() uint64 {
	return uint64(c.in_unicast_pkts)
}

func (c *Counter) InBroadcastPkts() uint64 {
	return uint64(c.in_broadcast_pkts)
}

func (c *Counter) InMulticastPkts() uint64 {
	return uint64(c.in_multicast_pkts)
}

func (c *Counter) InDiscards() uint64 {
	return uint64(c.in_discards)
}

func (c *Counter) InErrors() uint64 {
	return uint64(c.in_errors)
}

func (c *Counter) InUnknownProtos() uint32 {
	return uint32(c.in_unknown_protos)
}

func (c *Counter) OutOctets() uint64 {
	return uint64(c.out_octets)
}

func (c *Counter) OutUnicastPkts() uint64 {
	return uint64(c.out_unicast_pkts)
}

func (c *Counter) OutBroadcastPkts() uint64 {
	return uint64(c.out_broadcast_pkts)
}

func (c *Counter) OutMulticastPkts() uint64 {
	return uint64(c.out_multicast_pkts)
}

func (c *Counter) OutDiscards() uint64 {
	return uint64(c.out_discards)
}

func (c *Counter) OutErrors() uint64 {
	return uint64(c.out_errors)
}

func (c *Counter) LastClear() time.Time {
	return time.Unix(int64(c.last_clear), 0)
}

func (c *Counter) Free() {
	C.free(unsafe.Pointer(c))
}

func (c *Counter) Reset() {
	*c = Counter{last_clear: C.time(nil)}
}

func (c *Counter) String() string {
	return fmt.Sprintf("in:{%v, %v, %v, %v, %v, %v, %v} out:{%v, %v, %v, %v, %v, %v} last_clear: %v",
		c.in_octets, c.in_unicast_pkts, c.in_broadcast_pkts, c.in_multicast_pkts,
		c.in_discards, c.in_errors, c.in_unknown_protos,
		c.out_octets, c.out_unicast_pkts, c.out_broadcast_pkts, c.out_multicast_pkts,
		c.out_discards, c.out_errors,
		c.LastClear())
}

func (c *Counter) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"in-octets":          c.InOctets(),
		"in-unicast-pkts":    c.InUnicastPkts(),
		"in-broadcast-pkts":  c.InBroadcastPkts(),
		"in-multicast-pkts":  c.InMulticastPkts(),
		"in-discards":        c.InDiscards(),
		"in-errors":          c.InErrors(),
		"in-unknown-protos":  c.InUnknownProtos(),
		"out-octets":         c.OutOctets(),
		"out-unicast-pkts":   c.OutUnicastPkts(),
		"out-broadcast-pkts": c.OutBroadcastPkts(),
		"out-multicast-pkts": c.OutMulticastPkts(),
		"out-discards":       c.OutDiscards(),
		"out-errors":         c.OutErrors(),
		"last-clear":         c.LastClear(),
	}
	return json.Marshal(m)
}

func NewCounter() *Counter {
	c := (*Counter)(C.calloc(1, C.sizeof_struct_vsw_counter))
	c.Reset()
	return c
}
