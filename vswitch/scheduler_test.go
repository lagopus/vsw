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
	"testing"
	"time"

	"github.com/lagopus/vsw/vswitch/_test_runtime"
)

const (
	runtimeName  = "testing"
	instanceName = "testInstance"
	interval     = 1 * time.Millisecond
)

func TestSchedulerRuntime(t *testing.T) {
	ops, param := runtime.GetRuntimeParams(runtimeName)

	t.Logf("Creating new runtime")
	r, err := NewRuntime(2, runtimeName, LagopusRuntimeOps(ops), param)
	if err != nil {
		t.Fatalf("NewRuntime() failed: %v", err)
	}

	t.Logf("Registering an instance")
	ri := runtime.NewRuntimeInstance(instanceName, nil, nil)
	i, err := NewRuntimeInstance(LagopusInstance(ri))
	if err != nil {
		t.Fatalf("NewRuntimeInstance() failed: %v", err)
	}
	t.Logf("%v", i)

	if err := r.Register(i); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}
	t.Logf("%v", r.RuntimeInstances())

	if r.IsEnabled() {
		t.Fatalf("Runtime bad status: %v", r.IsEnabled())
	}

	if err := r.Enable(); err != nil {
		t.Fatalf("Runtime.Enable() failed: %v", err)
	}

	if i.IsEnabled() {
		t.Fatalf("RuntimeInstance bad status: %v", i.IsEnabled())
	}
	t.Logf("RuntimeInstance.IsEnabled(): %v", i.IsEnabled())

	if err := i.Enable(); err != nil {
		t.Fatalf("RuntimeInstance.Enable() failed: %v", err)
	}

	t.Logf("RuntimeInstance.IsEnabled(): %v", i.IsEnabled())
	time.Sleep(interval)

	if err := i.Disable(); err != nil {
		t.Fatalf("RuntimeInstance.Disable() failed: %v", err)
	}
	t.Logf("RuntimeInstance.IsEnabled(): %v", i.IsEnabled())

	if i.IsEnabled() {
		t.Fatalf("RuntimeInstance bad status: %v", i.IsEnabled())
	}

	time.Sleep(interval)

	i.Enable()

	time.Sleep(interval)

	i.Disable()

	if err := i.Unregister(); err != nil {
		t.Fatalf("RuntimeInstance.Unregister() failed: %v", err)
	}

	time.Sleep(interval)

	r.Disable()

	time.Sleep(interval)

	r.Terminate()
}
