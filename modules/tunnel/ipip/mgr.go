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
	"container/list"
	"fmt"
	"sync"
	"unsafe"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/modules/tunnel"
	"github.com/lagopus/vsw/vswitch"
)

var log = vswitch.Logger
var mgr = newTunnelMgr()

type tunnelMgr struct {
	ifTable     map[uint16]*TunnelIF
	inboundRt   *vswitch.Runtime
	outboundRt  *vswitch.Runtime
	freeIndexes *list.List
	lock        sync.Mutex
}

func newTunnelMgr() *tunnelMgr {
	freeIndexes := list.New()
	for i := 1; i <= maxTunnels; i++ {
		freeIndexes.PushBack(uint16(i))
	}

	return &tunnelMgr{
		freeIndexes: freeIndexes,
		ifTable:     make(map[uint16]*TunnelIF, maxTunnels),
		inboundRt:   nil,
		outboundRt:  nil,
	}
}

func (t *tunnelMgr) addTunnelIF(name string, outbound *dpdk.Ring, inbound *dpdk.Ring) (*TunnelIF, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if len(t.ifTable) == maxTunnels {
		return nil, fmt.Errorf("tunnel interface is max")
	}

	index := (t.freeIndexes.Remove(t.freeIndexes.Front())).(uint16)

	iface := newTunnelIF(index, name, outbound, inbound)
	if iface == nil {
		return nil, fmt.Errorf("create TunnelIF failed")
	}

	t.ifTable[index] = iface

	return iface, nil
}

func (t *tunnelMgr) deleteTunnelIF(index uint16) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if _, ok := t.ifTable[index]; ok {
		delete(t.ifTable, index)
		t.freeIndexes.PushBack(uint16(index))
	}

	if len(t.ifTable) == 0 {
		if t.inboundRt != nil {
			t.inboundRt.Terminate()
			t.inboundRt = nil
		}

		if t.outboundRt != nil {
			t.outboundRt.Terminate()
			t.outboundRt = nil
		}
	}
}

func (t *tunnelMgr) inboundRuntime(config *tunnel.ModuleConfig) (*vswitch.Runtime, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.inboundRt != nil {
		return t.inboundRt, nil
	}

	inboundRt, err := t.newRuntime(config.InboundCore,
					fmt.Sprintf("%s-inbound", ModuleName),
					vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.ipip_inbound_runtime_ops)))
	if err != nil {
		return nil, err
	}

	t.inboundRt = inboundRt

	return inboundRt, nil
}

func (t *tunnelMgr) outboundRuntime(config *tunnel.ModuleConfig) (*vswitch.Runtime, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.outboundRt != nil {
		return t.outboundRt, nil
	}

	outboundRt, err := t.newRuntime(config.OutboundCore,
					fmt.Sprintf("%s-outbound", ModuleName),
					vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.ipip_outbound_runtime_ops)))
	if err != nil {
		return nil, err
	}

	t.outboundRt = outboundRt

	return outboundRt, nil
}

func (t *tunnelMgr) newRuntime(core uint, name string,
	ops vswitch.LagopusRuntimeOps) (*vswitch.Runtime, error) {
	rparam := C.struct_ipip_runtime_param{}

	rt, err := vswitch.NewRuntime(core, name, ops, unsafe.Pointer(&rparam))
	if err != nil {
		return nil, err
	}

	return rt, nil
}

func (t *tunnelMgr) newRuntimeInstance(instance vswitch.LagopusInstance) (*vswitch.RuntimeInstance, error) {
	rti, err := vswitch.NewRuntimeInstance(instance)
	if err != nil {
		return nil, err
	}

	return rti, nil
}

func (t *tunnelMgr) registerRuntimeInstance(rt *vswitch.Runtime, rti *vswitch.RuntimeInstance) error {
	if err := rt.Register(rti); err != nil {
		return err
	}

	return rt.Enable()
}

func (t *tunnelMgr) newTunnelModule(base *vswitch.BaseInstance,
	priv interface{}, config *tunnel.ModuleConfig) (tunnel.ConcreteIF, error) {
	if base == nil {
		return nil, fmt.Errorf("[%s] no base instance", ModuleName)
	} else if base.Input() == nil || base.SecondaryInput() == nil {
		return nil, fmt.Errorf("[%s] no input", ModuleName)
	}

	iface, ifErr := t.addTunnelIF(base.Name(), base.Input(), base.SecondaryInput())
	if ifErr != nil {
		return nil, fmt.Errorf("[%s] add instance failed: %v", ModuleName, ifErr)
	}

	inboundRt, inboundRtErr := t.inboundRuntime(config)
	if inboundRtErr != nil {
		iface.Free()
		return nil, fmt.Errorf("[%s] get inbound runtime failed: %v", ModuleName, inboundRtErr)
	}

	inboundInstance := (vswitch.LagopusInstance)(unsafe.Pointer(iface.inboundCiface))
	inboundRti, inboundRtiErr := t.newRuntimeInstance(inboundInstance)
	if inboundRtiErr != nil {
		iface.Free()
		return nil, fmt.Errorf("[%s] create inbound runtime instance failed: %v", ModuleName, inboundRtiErr)
	}

	if err := t.registerRuntimeInstance(inboundRt, inboundRti); err != nil {
		iface.Free()
		return nil, fmt.Errorf("[%s] register inbound runtime instance failed: %v", ModuleName, err)
	}

	iface.inboundRti = inboundRti

	outboundRt, outboundRtErr := t.outboundRuntime(config)
	if outboundRtErr != nil {
		iface.Free()
		return nil, fmt.Errorf("[%s] get outbound runtime failed: %v", ModuleName, outboundRtErr)
	}

	outboundInstance := (vswitch.LagopusInstance)(unsafe.Pointer(iface.outboundCiface))
	outboundRti, outboundRtiErr := t.newRuntimeInstance(outboundInstance)
	if outboundRtiErr != nil {
		iface.Free()
		return nil, fmt.Errorf("[%s] create outbound runtime instance failed: %v", ModuleName, outboundRtiErr)
	}

	if err := t.registerRuntimeInstance(outboundRt, outboundRti); err != nil {
		iface.Free()
		return nil, fmt.Errorf("[%s] register outbound runtime instance failed: %v", ModuleName, err)
	}

	iface.outboundRti = outboundRti

	log.Printf("[%s] TunnelIF                  : %v", ModuleName, iface)
	log.Printf("[%s] Inbound Runtime           : %v", ModuleName, inboundRt)
	log.Printf("[%s] Outbound Runtime          : %v", ModuleName, outboundRt)
	log.Printf("[%s] Inbound Runtime instance  : %v", ModuleName, inboundRti)
	log.Printf("[%s] Outbound Runtime instance : %v", ModuleName, outboundRti)

	return iface, nil
}
