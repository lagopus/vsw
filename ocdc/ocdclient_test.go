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

package ocdc

import (
	"testing"
	"time"
)

// dumb.go
const name = "test-module"

var paths = [][]string{{"interfaces", "interface"}, {"network-instances", "network-instance"}}

type dumb struct {
	handle *Handle
	t      *testing.T
}

// Start start dumb, create dumb modules and subscribe it to openconfig.
func (d *dumb) Start() bool {
	d.t.Log("Start dumb module.")

	d.handle = Subscribe(name, paths)
	if d.handle == nil {
		d.t.Fatalf("Can't subscibe %v.\n", name)
		return false
	}

	go func() {
		for {
			c := <-d.handle.Parameter
			rc := true
			if c.Validate {
				rc = d.validate(c.Config)
			} else {
				d.commit(c.Config)
			}
			d.handle.Rc <- rc
		}
	}()

	return true
}

func (d *dumb) Stop() {
	// unsubscribe dumb module
	d.handle.Unsubscribe()
}

func (d *dumb) validate(conf []*Config) bool {
	d.t.Logf("Validate requested for %v:", d.handle.name)
	for _, c := range conf {
		d.t.Logf("%v: %v\n", c.Type, c.Path)
	}
	d.t.Log("Validation completed.")
	return true
}

func (d *dumb) commit(conf []*Config) {
	d.t.Logf("Commit requested for %v:", d.handle.name)
	for _, c := range conf {
		d.t.Logf("%v: %v\n", c.Type, c.Path)
	}
	d.t.Log("Commit completed.")
}

func TestOcdclient(t *testing.T) {
	dumb := &dumb{t: t}
	if !dumb.Start() {
		t.Fatalf("Can't start dumb module.\n")
	}

	time.Sleep(1 * time.Second)

	// Unsubscribe test
	t.Log("Unsubscribe dumb modules\n")
	dumb.Stop()
}
