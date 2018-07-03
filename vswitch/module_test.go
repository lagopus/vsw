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
	base    *BaseInstance
	str     string
	enabled bool
}

func (m *MyModule) Enable() error {
	fmt.Printf("%s: Enable()\n", m.base.Name())
	m.enabled = true
	return nil
}

func (m *MyModule) Disable() {
	fmt.Printf("%s: Disable()\n", m.base.Name())
	m.enabled = false
}

func (m *MyModule) Free() {
	fmt.Printf("%s: Free()\n", m.base.Name())
}

func newMyModule(base *BaseInstance, priv interface{}) (Instance, error) {
	if s, ok := priv.(string); ok {
		return &MyModule{base, s, false}, nil
	}
	return nil, fmt.Errorf("Invalid parameter passed: %v", priv)
}

const (
	TM  = "testModule"
	M0  = "test0"
	M1  = "test1"
	TV  = "testVIF"
	V0  = "vif0"
	V1  = "vif1"
	BM  = "testBridge"
	BM2 = "testBridge2"
	RM  = "testRouter"
	RM2 = "testRouter2"
	STR = "PRIVATE DATA"
)

var testModules = make(map[string]Instance)

func TestModuleRegistration(t *testing.T) {
	if err := RegisterModule(TM, newMyModule, nil, TypeOther); err != nil {
		t.Fatalf("Module registration failed: %v", err)
	}
	t.Logf("Module registartion succeeded: %s", TM)

	t.Logf("Try registering module with same name again.")
	if err := RegisterModule(TM, newMyModule, nil, TypeOther); err == nil {
		t.Fatalf("Module registered. Should fail.")
	} else {
		t.Logf("Module registartion failed. Success: %v", err)
	}
}

func TestModuleBasic(t *testing.T) {
	b, err := newInstance(TM, M0, STR)
	if err != nil {
		t.Fatalf("Instantiation failed: %v\n", err)
	}
	t.Logf("Module instantiation succeeded: %s", TM)

	if name := b.Name(); name != M0 {
		t.Fatalf("Module name mismatch: %s != %s", M0, name)
	}
	t.Logf("Module name matched.")

	if str := fmt.Sprintf("%v", b); str != M0 {
		t.Fatalf("Module stringer mismatch: %s != %s", M0, str)
	}
	t.Logf("Stringer matched.")

	if b.Input() == nil {
		t.Fatalf("No input ring")
	}
	t.Logf("Input ring created.")

	if b.isEnabled() {
		t.Fatalf("Module enabled before enabling")
	}

	if err := b.enable(); err != nil {
		t.Fatalf("Can't enable module: %v", err)
	}

	if !b.isEnabled() {
		t.Fatalf("Module disabled after enabling")
	}
	t.Logf("Module enabled")

	b.disable()

	if b.isEnabled() {
		t.Fatalf("Module still enabled after disabling")
	}
	t.Logf("Module disabled")

	b.free()
}
