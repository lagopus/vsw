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

package vswitch

import (
	"fmt"
	"testing"
)

type MyModule struct {
	ModuleService
}

func (m *MyModule) Start() bool {
	fmt.Printf("%s: Start()\n", m.Name())
	return true
}

func (m *MyModule) Stop() {
	fmt.Printf("%s: Stop()\n", m.Name())
}

func (m *MyModule) Wait() {
	fmt.Printf("%s: Wait()\n", m.Name())
}

func (m *MyModule) Control(cmd string, v interface{}) interface{} {
	rc := true
	fmt.Printf("%s: Control(%v, %v) -> %v\n", m.Name(), cmd, v, rc)
	return rc
}

func createMyModule(p *ModuleParam) (Module, error) {
	return &MyModule{NewModuleService(p)}, nil
}

const (
	TM = "testModule"
	M0 = "test0"
	M1 = "test1"
	TV = "testVIF"
	V0 = "vif0"
	V1 = "vif1"
)

func checkInputRing(t *testing.T, m Module, input bool, vif bool) {
	ir := (m.Input() != nil)
	vr := (m.VifInput() != nil)
	if ir == input && vr == vif {
		return
	}
	t.Errorf("Input(), VifInput() not properly created: %s: (%v, %v)\n", m.Name(), ir, vr)
}

var testModules = make(map[string]Module)

func createModule(t *testing.T, moduleName, name string) Module {
	m := newModule(moduleName, name, nil)
	if m == nil {
		t.Fatalf("Can't instantiate module: %s\n", name)
	}
	testModules[name] = m
	return m
}

func TestModuleBasic(t *testing.T) {
	// register
	if !RegisterModule(TM, createMyModule, nil, TypeOther) {
		t.Fatalf("Can't register module\n")
	}

	// register
	if !RegisterModule(TV, createMyModule, nil, TypeVif) {
		t.Fatalf("Can't register module\n")
	}

	// create
	m0 := createModule(t, TM, M0)
	m1 := createModule(t, TM, M1)
	v0 := createModule(t, TV, V0)
	v1 := createModule(t, TV, V1)

	// connection
	v0.Connect(m0, MATCH_ANY)
	v1.Connect(m0, MATCH_ANY)
	m0.Connect(v0, MATCH_OUT_VIF)
	m1.Connect(v1, MATCH_OUT_VIF)
	m0.Connect(m1, MATCH_ANY)

	// check input rings
	checkInputRing(t, m0, false, true)
	checkInputRing(t, m1, true, false)
	checkInputRing(t, v0, true, false)
	checkInputRing(t, v1, true, false)

	// Call
	for _, m := range testModules {
		m.Start()
	}
	for _, m := range testModules {
		m.Stop()
	}
	for _, m := range testModules {
		m.Wait()
	}
	for _, m := range testModules {
		m.Control(m.Name(), false)
	}
}
