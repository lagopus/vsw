//
// Copyright 2019 Nippon Telegraph and Telephone Corporation.
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
	"testing"
	"time"
)

func TestCounterNew(t *testing.T) {
	duration := 3 * time.Second

	c := NewCounter()
	c.out_errors = 100
	t.Logf("time: %v", c.LastClear())
	t.Logf("> %v", c)
	t.Logf("Sleep for %v seconds, then reset.", duration.Seconds())
	time.Sleep(duration)
	last := c.LastClear()
	c.Reset()
	t.Logf("> %v", c)
	t.Logf("time: %v", c.LastClear())

	s := c.LastClear().Sub(last)
	t.Logf("Time elapsed for %v seconds", s.Seconds())
	if s >= duration {
		t.Logf("ok")
	} else {
		t.Fatalf("failed")
	}

	c.Free()
}
