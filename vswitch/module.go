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
	"github.com/lagopus/vsw/dpdk"
	"sync"
)

type ModuleFactory func(*ModuleParam) (Module, error)

// ModuleType is the type of the module
type ModuleType int

const (
	// Other than VIF or Bridge Modules
	TypeOther ModuleType = iota
	// VIF Module
	TypeVif
	// Bridge Module
	TypeBridge
)

var moduleTypeString = [...]string{
	TypeOther:  "Others",
	TypeVif:    "VIF",
	TypeBridge: "Bridge",
}

func (mt ModuleType) String() string { return moduleTypeString[mt] }

// ModuleParam is a set of parameters passed to the module factory.
type ModuleParam struct {
	t            ModuleType
	name         string
	vrf          *VrfInfo
	input        *dpdk.Ring // Non-VIFs send mbuf to this ring.
	vifInput     *dpdk.Ring // VIFs send mbuf to this ring.
	rules        *Rules
	vif          *Vif
	bridge       *BridgeInfo
	rp           RingParam // RingParam for input
	vrp          RingParam // RingParam for vifInput
	onceInput    sync.Once
	onceVifInput sync.Once
}

// RingParam defines a parameter for an input ring.
type RingParam struct {
	Count    uint // Number of mbufs to be queueable
	SocketId int  // Memory Socket ID
	Flags    uint // dpdk.RING_F_SP_ENQ and/or dpdk.RING_F_SC_DEQ
}

var defaultRingParam = RingParam{
	Count:    32,
	SocketId: dpdk.SOCKET_ID_ANY,
}

// Module defines the interface that each module shall comply to.
type Module interface {
	Start() bool                             // Start the packet processing. Return immediately.
	Stop()                                   // Request to stop the packet processing. Return immediately.
	Wait()                                   // Wait for the packet processing to stop. Block until stops.
	Control(string, interface{}) interface{} // Control the instance. Implementation dependent.
	ModuleService
}

// ModuleService defines internal API to support Module.
// Call NewModuleService() to create one for your module.
type ModuleService interface {
	Connect(Module, VswMatch, ...uint64) bool
	Type() ModuleType             // Type of this module
	Vrf() *VrfInfo                // VRF RD that this module belongs to.
	inputInternal() *dpdk.Ring    // internal
	Input() *dpdk.Ring            // Input Ring for this module.
	vifInputInternal() *dpdk.Ring // internal
	VifInput() *dpdk.Ring         // VIFs send mbuf to this ring.
	Rules() *Rules                // Rules for output.
	Vif() *Vif                    // Non-nil if this module is VIF.
	Bridge() *BridgeInfo          // Non-nil if the module is Bridge.
	Name() string                 // Name of the module instance.
	RingParam() RingParam         // Get DPDK Ring Parameter to be used for the Input()
	SetRingParam(RingParam)       // Set DPDK Ring Parameter to be used for the Input()
	VifRingParam() RingParam      // Get DPDK Ring Parameter to be used for the VifInput()
	SetVifRingParam(RingParam)    // Set DPDK Ring Parameter to be used for the VifInput()
}

type moduleService struct {
	*ModuleParam
}

var moduleFactories = make(map[string]ModuleFactory)
var modules []Module
var ringParams = make(map[string]RingParam)
var moduleTypes = make(map[string]ModuleType)

// RegisterModule registers a module with the given name.
// Factory returns a module comply to Module interface.
// T is the type of the module to be registered.
// Returns true on success, false on failure.
// Intended to be called from modules' init.
func RegisterModule(name string, factory ModuleFactory, rp *RingParam, t ModuleType) bool {
	if factory == nil {
		Logger.Printf("No module factory for '%s' given", name)
		return false
	}

	if moduleFactories[name] != nil {
		Logger.Printf("'%s' already exists. ignoring.\n", name)
		return false
	}

	moduleFactories[name] = factory
	if rp != nil {
		ringParams[name] = *rp
	}
	moduleTypes[name] = t
	Logger.Printf("'%s' registerd. (Type=%v)\n", name, t)
	return true
}

// NewModule creates a new module of the moduleName. The created module
// is idqntified with the given name, and must be unique.
func newModule(moduleName, name string, vrf *VrfInfo) Module {
	factory, found := moduleFactories[moduleName]
	if !found {
		Logger.Printf("Module '%s' doesn't exist.\n", moduleName)
		return nil
	}

	rp, ok := ringParams[name]
	if !ok {
		rp = defaultRingParam
	}
	rp.Flags = dpdk.RING_F_SC_DEQ

	// Create a parameter for the module
	modType := moduleTypes[moduleName]
	param := &ModuleParam{
		t:     modType,
		name:  name,
		vrf:   vrf,
		rp:    rp,
		vrp:   rp,
		rules: newRules(),
	}

	switch modType {
	case TypeVif:
		param.vif = newVif()
	case TypeBridge:
		param.bridge = newBridge()
	default:
		// nop
	}

	module, err := factory(param)
	if err != nil {
		Logger.Printf("Creating module '%s' with name '%s' failed.\n", moduleName, name)
		return nil
	}

	switch modType {
	case TypeVif:
		op, ok := module.(VifOp)
		if !ok {
			Logger.Fatalf("'%s' doesn't conform to VifModule interface!\n", moduleName)
			break
		}
		ms, _ := module.(ModuleService)
		param.vif.config(op, ms)

	default:
		// nop
	}

	modules = append(modules, module)

	return module
}

func NewModuleService(param *ModuleParam) ModuleService {
	return &moduleService{param}
}

// Connect connects output ring for the module instance to the given dst.
// Rules to match shall be specified.
// If the destination is VIF and MATCH_OUT_VIF is specified, it passes
// VIF index of the VIF module as a parameter automatically.
// Only modules that belongs to the same VRF may be connected.
// Returns true on success, and false on failure.
func (m *moduleService) Connect(dst Module, match VswMatch, param ...uint64) bool {
	if m.Vrf() != dst.Vrf() {
		return false
	}

	dstVif := dst.Vif()
	if match == MATCH_OUT_VIF && dstVif != nil {
		param = []uint64{uint64(dstVif.VifIndex())}
	}

	var dstInput *dpdk.Ring
	if m.Type() == TypeVif {
		dstInput = dst.vifInputInternal()
	} else {
		dstInput = dst.inputInternal()
	}

	m.Rules().add(match, param, dstInput)
	return true
}

// internal
func (m *moduleService) inputInternal() *dpdk.Ring {
	m.onceInput.Do(func() {
		// Create an input ring
		ringName := fmt.Sprintf("input-%s", m.Name())
		rp := m.RingParam()
		m.input = dpdk.RingCreate(ringName, rp.Count, rp.SocketId, rp.Flags)
		if m.input == nil {
			Logger.Printf("Input ring creation faild for %s.\n", m.Name())
		}
	})

	return m.input
}

// internal
func (m *moduleService) vifInputInternal() *dpdk.Ring {
	m.onceVifInput.Do(func() {
		// Create an input ring
		ringName := fmt.Sprintf("vif-input-%s", m.Name())
		rp := m.VifRingParam()
		m.vifInput = dpdk.RingCreate(ringName, rp.Count, rp.SocketId, rp.Flags)
		if m.vifInput == nil {
			Logger.Printf("Input ring creation faild for %s.\n", m.Name())
		}
	})

	return m.vifInput
}

// Input returns input ring for the module
func (m *moduleService) Input() *dpdk.Ring {
	return m.input
}

// VifInput returns input ring dedicated for VIF of the module.
func (m *moduleService) VifInput() *dpdk.Ring {
	return m.vifInput
}

// RingParam returns DPDK Ring Parameter to be used for the Input()
func (m *moduleService) RingParam() RingParam {
	return m.rp
}

// SetRingParam sets DPDK Ring Parameter to be used for the Input()
func (m *moduleService) SetRingParam(rp RingParam) {
	m.rp = rp
}

// VifRingParam returns DPDK Ring Parameter to be used for the VifInput()
func (m *moduleService) VifRingParam() RingParam {
	return m.vrp
}

// SetVifRingParam sets DPDK Ring Parameter to be used for the VifInput()
func (m *moduleService) SetVifRingParam(rp RingParam) {
	m.vrp = rp
}

// Vif returns VIF information of the module.
// If the module is not a VIF, then it returns nil.
func (m *moduleService) Vif() *Vif {
	return m.vif
}

// Rules returns output rule of the module.
func (m *moduleService) Rules() *Rules {
	return m.rules
}

// Name returns the name of this module instance.
func (m *moduleService) Name() string {
	return m.name
}

// Vrf returns a VRF that this modules belongs to.
func (m *moduleService) Vrf() *VrfInfo {
	return m.vrf
}

func (m *moduleService) Bridge() *BridgeInfo {
	return m.bridge
}

// Type returns the type of this module.
func (m *moduleService) Type() ModuleType {
	return m.t
}

func (m *moduleService) String() string {
	return m.name
}
