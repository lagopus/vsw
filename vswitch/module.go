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
	"errors"
	"fmt"

	"github.com/lagopus/vsw/dpdk"
)

type InstanceFactory func(*BaseInstance, interface{}) (Instance, error)

// ModuleType is the type of the module
type ModuleType int

const (
	// Interface Module
	TypeInterface ModuleType = iota
	// Bridge Module
	TypeBridge
	// Router Module
	TypeRouter
	// Other than any type listed above
	TypeOther
)

var moduleTypeString = [...]string{
	TypeOther:     "Others",
	TypeInterface: "Interface",
	TypeBridge:    "Bridge", // XXX: Should OF bridge belongs to TypeBridge?
	TypeRouter:    "Router",
}

func (mt ModuleType) String() string { return moduleTypeString[mt] }

// BaseInstance is a base class of the module instance
type BaseInstance struct {
	name     string
	input    *dpdk.Ring // Default input ring.
	input2   *dpdk.Ring // Optional input ring. If non-nil, used for Inbound mbufs by VIF.
	rules    *Rules
	instance Instance
	enabled  bool
}

// RingParam defines a parameter for an input ring.
type RingParam struct {
	Count          uint // Number of mbufs to be queueable
	SocketId       int  // Memory Socket ID
	SecondaryInput bool // Set true to separate inbound and outbound rings. For TypeInterface only.
}

var defaultRingParam = RingParam{
	Count:          32,
	SocketId:       dpdk.SOCKET_ID_ANY,
	SecondaryInput: false,
}

// Instance defines basic interfaces that each instance shall comply to.
// There're also ModuleType specific interface that each ModuleType shall
// comply to, e.g. InterfaceInstance.
type Instance interface {
	Enable() error // Enable enables the instance
	Disable()      // Disable disables the instance
	Free()         // Free the instance.
}

var instanceFactories = make(map[string]InstanceFactory)
var ringParams = make(map[string]RingParam)
var moduleTypes = make(map[string]ModuleType)
var bridgeModuleName = ""
var routerModuleName = ""

// RegisterModule registers a module with the given name.
// Factory returns a module comply to Module interface.
// T is the type of the module to be registered.
// Returns error on failure.
// Intended to be called from modules' init.
func RegisterModule(moduleName string, factory InstanceFactory, rp *RingParam, t ModuleType) error {
	if factory == nil {
		return fmt.Errorf("No module factory for '%s' given", moduleName)
	}

	if t != TypeInterface && rp != nil && rp.SecondaryInput {
		return errors.New("Only TypeInterface may enable SecondaryInput of RingParam")
	}

	if instanceFactories[moduleName] != nil {
		return fmt.Errorf("'%s' already exists. ignoring.", moduleName)
	}

	switch t {
	case TypeBridge:
		if bridgeModuleName != "" {
			return fmt.Errorf("Bridge module already exists. (Existing bridge: %s)", bridgeModuleName)
		}
		bridgeModuleName = moduleName
	case TypeRouter:
		if routerModuleName != "" {
			return fmt.Errorf("Router module already exists. (Existing router: %s)", routerModuleName)
		}
		routerModuleName = moduleName
	default:
	}

	instanceFactories[moduleName] = factory
	if rp != nil {
		ringParams[moduleName] = *rp
	}

	moduleTypes[moduleName] = t
	return nil
}

// NewInstance creates a new instance of the moduleName.
// The created instance is identified with the given name, and must be unique.
// Priv is a module specific parameter passed to create an instance.
func newInstance(moduleName, name string, priv interface{}) (*BaseInstance, error) {
	factory, found := instanceFactories[moduleName]
	if !found {
		return nil, fmt.Errorf("Module '%s' doesn't exist.\n", moduleName)
	}

	rp, ok := ringParams[moduleName]
	if !ok {
		rp = defaultRingParam
	}

	bi := &BaseInstance{name: name}

	ringName := fmt.Sprintf("input-%s", name)
	bi.input = dpdk.RingCreate(ringName, rp.Count, rp.SocketId, dpdk.RING_F_SC_DEQ)
	if bi.input == nil {
		return nil, fmt.Errorf("Input ring creation faild for %s.\n", name)
	}

	if rp.SecondaryInput {
		ringName := fmt.Sprintf("input2-%s", name)
		bi.input2 = dpdk.RingCreate(ringName, rp.Count, rp.SocketId, dpdk.RING_F_SC_DEQ)
		if bi.input2 == nil {
			return nil, fmt.Errorf("Second input ring creation failed for %s", name)
		}
	}

	bi.rules = newRules()

	instance, err := factory(bi, priv)
	if err != nil {
		return nil, fmt.Errorf("Creating module '%s' with name '%s' failed: %v\n", moduleName, name, err)
	}
	bi.instance = instance

	return bi, nil
}

// newSubInstance creates a new subinstance that inherits input ring from the parent.
// This function is used to create a VIF from Interfaces.
func newSubInstance(parent *BaseInstance, name string) *BaseInstance {
	bi := &BaseInstance{
		name:     name,
		input:    parent.input,
		input2:   parent.input2,
		rules:    newRules(),
		enabled:  false,
		instance: parent.instance,
	}
	return bi
}

func (bi *BaseInstance) baseInstance() *BaseInstance {
	return bi
}

// connect connects output of the instance to the ring specified by dst.
// Rules to match shall be specified as well.
func (bi *BaseInstance) connect(dst *dpdk.Ring, match VswMatch, param interface{}) error {
	return bi.rules.add(match, param, dst)
}

// disconnect connects output ring of the instance to the given dst instance.
// Rules to match shall be specified.
func (bi *BaseInstance) disconnect(match VswMatch, param interface{}) error {
	return bi.rules.remove(match, param)
}

// Input returns input ring for the module
func (bi *BaseInstance) Input() *dpdk.Ring {
	return bi.input
}

// SecondaryInput returns secondary input ring for the module.
// If the module doesn't have one, nil is returned.
func (bi *BaseInstance) SecondaryInput() *dpdk.Ring {
	return bi.input2
}

// Rules returns output rule of the module.
func (bi *BaseInstance) Rules() *Rules {
	return bi.rules
}

// Name returns the name of this module instance.
func (bi *BaseInstance) Name() string {
	return bi.name
}

func (bi *BaseInstance) String() string {
	return bi.name
}

func (bi *BaseInstance) isEnabled() bool {
	return bi.enabled
}

func (bi *BaseInstance) enable() error {
	if !bi.enabled {
		if err := bi.instance.Enable(); err != nil {
			return err
		}
		bi.enabled = true
	}
	return nil
}

func (bi *BaseInstance) disable() {
	if bi.enabled {
		bi.instance.Disable()
		bi.enabled = false
	}
}

func (bi *BaseInstance) free() {
	if bi.enabled {
		bi.instance.Disable()
	}
	bi.instance.Free()
	bi.input.Free()
}
