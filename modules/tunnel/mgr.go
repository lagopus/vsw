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

package tunnel

/*
#include "ip_id.h"
*/
import "C"

import (
	"fmt"
	"sync"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/modules/tunnel/log"
	"github.com/lagopus/vsw/vswitch"
)

var mgr = newTunnelMgr()

type tunnelMgr struct {
	ifCount  uint16
	mgrTable map[ProtocolType]*concreteIFMgr
	lock     sync.Mutex
}

func newTunnelMgr() *tunnelMgr {
	return &tunnelMgr{
		ifCount:  0,
		mgrTable: make(map[ProtocolType]*concreteIFMgr),
	}
}

func (t *tunnelMgr) addTunnelModule(data *moduleData) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	if data == nil {
		return fmt.Errorf("invalid argument")
	}

	if t.mgrTable[data.protocol] != nil {
		return fmt.Errorf("already exists: %s", data.protocol)
	}

	t.mgrTable[data.protocol] = newConcreteIFMgr(data)

	return nil
}

func (t *tunnelMgr) newConcreteIF(accessor ifParamAccessor) (concreteIF, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if accessor == nil {
		return nil, fmt.Errorf("invalid argument")
	} else if t.ifCount == maxTunnels {
		return nil, fmt.Errorf("tunnel interface is max")
	}

	var err = fmt.Errorf("invalid protocol: %s", accessor.protocol())
	if concreteIFMgr, ok := t.mgrTable[accessor.protocol()]; ok {
		var iface concreteIF
		if iface, err = concreteIFMgr.newConcreteIF(accessor); err == nil {
			t.ifCount++
			return iface, nil
		}
	}

	return nil, err
}

func (t *tunnelMgr) deleteConcreteIF(protocol ProtocolType, name string) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	if concreteIFMgr, ok := t.mgrTable[protocol]; ok {
		concreteIFMgr.deleteConcreteIF(name)
		t.ifCount--
		return nil
	}

	return fmt.Errorf("invalid protocol: %s", protocol)
}

type concreteIFMgr struct {
	moduleData
	ifTable    map[string]concreteIF
	inboundRt  *vswitch.Runtime
	outboundRt *vswitch.Runtime
	lock       sync.Mutex
}

func newConcreteIFMgr(data *moduleData) *concreteIFMgr {
	return &concreteIFMgr{
		moduleData: moduleData{
			protocol:    data.protocol,
			factory:     data.factory,
			inboundOps:  data.inboundOps,
			outboundOps: data.outboundOps,
		},
		ifTable:    make(map[string]concreteIF, maxTunnels),
		inboundRt:  nil,
		outboundRt: nil,
	}
}

func (c *concreteIFMgr) newConcreteIF(accessor ifParamAccessor) (concreteIF, error) {
	if accessor == nil {
		return nil, fmt.Errorf("invalid argument")
	} else if accessor.outbound() == nil || accessor.inbound() == nil {
		return nil, fmt.Errorf("no input")
	} else if len(c.ifTable) == maxTunnels {
		return nil, fmt.Errorf("%s tunnel interface is max", c.protocol)
	}

	iface, ifErr := c.factory(accessor)
	if ifErr != nil {
		return nil, fmt.Errorf("create concreteIF failed: %v", ifErr)
	}

	if err := c.addConcreteIF(accessor.name(), iface); err != nil {
		return nil, fmt.Errorf("add concreteIF failed: %v", err)
	}

	log.Logger.Info("[%s] concrete Tunnel IF: %#v", accessor.name(), iface)

	if iface.inboundInstance() != nil {
		inboundRt, inboundRtErr := c.inboundRuntime(accessor.moduleConfig())
		if inboundRtErr != nil {
			iface.Free()
			return nil, fmt.Errorf("get inbound runtime failed: %v", inboundRtErr)
		}

		inboundRti, inboundRtiErr := vswitch.NewRuntimeInstance(iface.inboundInstance())
		if inboundRtiErr != nil {
			iface.Free()
			return nil, fmt.Errorf("create inbound runtime instance failed: %v", inboundRtiErr)
		}

		if err := c.registerRuntimeInstance(inboundRt, inboundRti); err != nil {
			iface.Free()
			return nil, fmt.Errorf("register inbound runtime instance failed: %v", err)
		}

		iface.setInboundRti(inboundRti)

		log.Logger.Info("[%s] Inbound Runtime: %#v", accessor.name(), inboundRt)
		log.Logger.Info("[%s] Inbound Runtime instance: %#v", accessor.name(), inboundRti)
	} else {
		log.Logger.Info("[%s] Inbound does not use runtime", accessor.name())
	}

	if iface.outboundInstance() != nil {
		outboundRt, outboundRtErr := c.outboundRuntime(accessor.moduleConfig())
		if outboundRtErr != nil {
			iface.Free()
			return nil, fmt.Errorf("get outbound runtime failed: %v", outboundRtErr)
		}

		outboundRti, outboundRtiErr := vswitch.NewRuntimeInstance(iface.outboundInstance())
		if outboundRtiErr != nil {
			iface.Free()
			return nil, fmt.Errorf("create outbound runtime instance failed: %v", outboundRtiErr)
		}

		if err := c.registerRuntimeInstance(outboundRt, outboundRti); err != nil {
			iface.Free()
			return nil, fmt.Errorf("register outbound runtime instance failed: %v", err)
		}

		iface.setOutboundRti(outboundRti)

		log.Logger.Info("[%s] Outbound Runtime: %#v", accessor.name(), outboundRt)
		log.Logger.Info("[%s] Outbound Runtime instance: %#v", accessor.name(), outboundRti)
	} else {
		log.Logger.Info("[%s] Outbound does not use runtime", accessor.name())
	}

	return iface, nil
}

func (c *concreteIFMgr) addConcreteIF(name string, iface concreteIF) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if len(name) == 0 || iface == nil {
		return fmt.Errorf("invalid argument")
	}

	c.ifTable[name] = iface

	return nil
}

func (c *concreteIFMgr) deleteConcreteIF(name string) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if _, ok := c.ifTable[name]; ok {
		delete(c.ifTable, name)
	}

	if len(c.ifTable) == 0 {
		if c.inboundRt != nil {
			c.inboundRt.Terminate()
			c.inboundRt = nil
		}

		if c.outboundRt != nil {
			c.outboundRt.Terminate()
			c.outboundRt = nil
		}
	}
}

func (c *concreteIFMgr) inboundRuntime(config *ModuleConfig) (*vswitch.Runtime, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.inboundRt == nil {
		if inboundRt, err := c.newRuntime(config.InboundCore,
			fmt.Sprintf("%s-inbound", c.protocol.String()),
			c.inboundOps); err == nil {
			c.inboundRt = inboundRt
		} else {
			return nil, err
		}
	}

	return c.inboundRt, nil
}

func (c *concreteIFMgr) outboundRuntime(config *ModuleConfig) (*vswitch.Runtime, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.outboundRt == nil {
		if outboundRt, err := c.newRuntime(config.OutboundCore,
			fmt.Sprintf("%s-outbound", c.protocol.String()),
			c.outboundOps); err == nil {
			c.outboundRt = outboundRt
		} else {
			return nil, err
		}
	}

	return c.outboundRt, nil
}

func (c *concreteIFMgr) newRuntime(core uint, name string,
	ops vswitch.LagopusRuntimeOps) (*vswitch.Runtime, error) {

	rt, err := vswitch.NewRuntime(core, name, ops, nil)
	if err != nil {
		return nil, err
	}

	return rt, nil
}

func (c *concreteIFMgr) registerRuntimeInstance(rt *vswitch.Runtime, rti *vswitch.RuntimeInstance) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if err := rt.Register(rti); err != nil {
		return err
	}

	return rt.Enable()
}

func registerTunnelModule(data *moduleData) error {
	if err := mgr.addTunnelModule(data); err != nil {
		return err
	}

	return nil
}

func newModule(base *vswitch.BaseInstance, priv interface{}) (vswitch.Instance, error) {
	log.Logger.Info("[%s] new Tunnel IF", base.Name())
	return newTunnelIF(base, priv), nil
}

func init() {
	C.ip_init_id()

	rp := &vswitch.RingParam{
		Count:          maxPktBurst,
		SocketId:       dpdk.SOCKET_ID_ANY,
		SecondaryInput: true,
	}

	if err := vswitch.RegisterModule(moduleName, newModule, rp, vswitch.TypeInterface); err != nil {
		log.Logger.Fatalf("Failed to register a %s module: %v", moduleName, err)
		return
	}
}
