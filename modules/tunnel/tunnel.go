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

package tunnel

// #include "ip_id.h"
import "C"

import (
	"fmt"
	"net"
	"sync"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/vswitch"
)

var log = vswitch.Logger
var factories = make(map[ProtocolType]ConcreteIFFactory)

// ConcreteIF Concrete interface.
type ConcreteIF interface {
	vswitch.Instance
	NewVIF(*vswitch.VIF) (vswitch.VIFInstance, error)
}

func newConcreteIF(w *WrapperIF, factory ConcreteIFFactory) (ConcreteIF, error) {
	if w == nil {
		return nil, fmt.Errorf("base tunnel interface is nil")
	}

	iface, err := factory(w.base, w.priv, w.config)
	if err != nil {
		return nil, fmt.Errorf("factory execution failed: %v", err)
	}

	return iface, nil
}

func getProtocolType(vif *vswitch.VIF) (ProtocolType, error) {
	proto := Unknown

	if vif == nil {
		return proto, fmt.Errorf("vif is nil")
	}

	tunnel := vif.Tunnel()
	if tunnel == nil {
		return proto, fmt.Errorf("tunnel is nil")
	}

	switch tunnel.EncapsMethod() {
	case vswitch.EncapsMethodDirect:
		switch tunnel.Security() {
		case vswitch.SecurityNone:
			proto = IPIP
		case vswitch.SecurityIPSec:
			proto = IPsec
		default:
			return proto, fmt.Errorf("invalid security: %d", tunnel.Security())
		}
	case vswitch.EncapsMethodGRE:
		proto = GRE
	default:
		return proto, fmt.Errorf("invalid encaps-method: %d", tunnel.EncapsMethod())
	}

	return proto, nil
}

// WrapperIF Wrapper interface.
type WrapperIF struct {
	base   *vswitch.BaseInstance
	priv   interface{}
	config *ModuleConfig
	iface  ConcreteIF
	mac    net.HardwareAddr
	mtu    vswitch.MTU
	state  interfaceState
	lock   sync.Mutex
}

func newWrapperIF(base *vswitch.BaseInstance, priv interface{}) *WrapperIF {
	return &WrapperIF{
		base:   base,
		priv:   priv,
		config: nil,
		iface:  nil,
		mac:    nil,
		mtu:    vswitch.DefaultMTU,
		state:  initialized,
	}
}

// Free Free for instance.
func (w *WrapperIF) Free() {
	w.lock.Lock()
	defer w.lock.Unlock()

	if w.iface == nil {
		w.state = freed
	} else {
		w.iface.Free()
	}
}

// Enable Enable for instance.
func (w *WrapperIF) Enable() error {
	w.lock.Lock()
	defer w.lock.Unlock()

	if w.iface == nil {
		if w.state != freed {
			w.state = enabled
		}
	} else {
		return w.iface.Enable()
	}

	return nil
}

// Disable Disable for instance.
func (w *WrapperIF) Disable() {
	w.lock.Lock()
	defer w.lock.Unlock()

	if w.iface == nil {
		if w.state != freed {
			w.state = disabled
		}
	} else {
		w.iface.Disable()
	}
}

// NewVIF Create VIF.
func (w *WrapperIF) NewVIF(vif *vswitch.VIF) (vswitch.VIFInstance, error) {
	w.lock.Lock()
	defer w.lock.Unlock()

	if vif == nil {
		return nil, fmt.Errorf("[%s] VIF is nil", ModuleName)
	}

	if w.iface == nil {
		var err error

		var proto ProtocolType
		if proto, err = getProtocolType(vif); err != nil {
			return nil, fmt.Errorf("[%s] get protocol type failed: %v", ModuleName, err)
		}
		log.Printf("[%s] protocol type: %s", ModuleName, proto.String())

		w.config = getModuleConfig(proto)
		log.Printf("[%s] config: %#v", ModuleName, w.config)

		var factory ConcreteIFFactory
		var ok bool
		if factory, ok = factories[proto]; !ok {
			return nil, fmt.Errorf("[%s] factory doesn't exist: %v", ModuleName, proto)
		}

		if w.iface, err = newConcreteIF(w, factory); err != nil {
			return nil, fmt.Errorf("[%s] create IF failed: %v", ModuleName, err)
		}

		switch w.state {
		case initialized:
			// do nothing.
		case enabled:
			if err = w.iface.Enable(); err != nil {
				return nil, fmt.Errorf("[%s] IF enable failed: %v", ModuleName, err)
			}
		case disabled:
			w.iface.Disable()
		case freed:
			w.iface.Free()
		default:
			return nil, fmt.Errorf("[%s] invalid IF state: %d", ModuleName, w.state)
		}
	}

	tvif, err := w.iface.NewVIF(vif)
	if err != nil {
		return nil, fmt.Errorf("[%s] create VIF failed: %v", ModuleName, err)
	}

	return tvif, nil
}

// MACAddress MACAddress.
func (w *WrapperIF) MACAddress() net.HardwareAddr {
	return w.mac
}

// SetMACAddress SetMACAddress.
func (w *WrapperIF) SetMACAddress(mac net.HardwareAddr) error {
	w.mac = mac
	return nil
}

// MTU MTU.
func (w *WrapperIF) MTU() vswitch.MTU {
	return w.mtu
}

// SetMTU SetMTU.
func (w *WrapperIF) SetMTU(mtu vswitch.MTU) error {
	w.mtu = mtu
	return nil
}

// InterfaceMode InterfaceMode.
func (w *WrapperIF) InterfaceMode() vswitch.VLANMode {
	return vswitch.AccessMode
}

// SetInterfaceMode SetInterfaceMode.
func (w *WrapperIF) SetInterfaceMode(mode vswitch.VLANMode) error {
	return fmt.Errorf("[%s] SetInterfaceMode unsupported", ModuleName)
}

// AddVID AddVID.
func (w *WrapperIF) AddVID(vid vswitch.VID) error {
	return fmt.Errorf("[%s] AddVID unsupported", ModuleName)
}

// DeleteVID DeleteVID.
func (w *WrapperIF) DeleteVID(vid vswitch.VID) error {
	return fmt.Errorf("[%s] DeleteVID unsupported", ModuleName)
}

// SetNativeVID SetNativeVID.
func (w *WrapperIF) SetNativeVID(vid vswitch.VID) error {
	return fmt.Errorf("[%s] SetNativeVID unsupported", ModuleName)
}

// RegisterConcreteIF Register TunnelIF factory.
func RegisterConcreteIF(protocolType ProtocolType, factory ConcreteIFFactory) error {
	if factory == nil {
		return fmt.Errorf("[%s] invalid argument", ModuleName)
	}

	if factories[protocolType] != nil {
		return fmt.Errorf("[%s] already exists: %d", ModuleName, protocolType)
	}

	factories[protocolType] = factory

	return nil
}

func newModule(base *vswitch.BaseInstance, priv interface{}) (vswitch.Instance, error) {
	return newWrapperIF(base, priv), nil
}

func init() {
	C.ip_init_id()

	rp := &vswitch.RingParam{
		Count:          MaxPktBurst,
		SocketId:       dpdk.SOCKET_ID_ANY,
		SecondaryInput: true,
	}

	if err := vswitch.RegisterModule(ModuleName, newModule, rp, vswitch.TypeInterface); err != nil {
		log.Fatalf("Failed to register a module '%s': %v", ModuleName, err)
		return
	}
}
