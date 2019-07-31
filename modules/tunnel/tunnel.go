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

import (
	"fmt"
	"net"
	"sync"

	"github.com/lagopus/vsw/modules/tunnel/log"
	"github.com/lagopus/vsw/vswitch"
)

type concreteIF interface {
	vswitch.Instance
	inboundInstance() vswitch.LagopusInstance
	outboundInstance() vswitch.LagopusInstance
	setInboundRti(*vswitch.RuntimeInstance)
	setOutboundRti(*vswitch.RuntimeInstance)
	interfaceMode() vswitch.VLANMode
	setInterfaceMode(vswitch.VLANMode) error
	setAddressType(vswitch.AddressFamily)
	setHopLimit(uint8)
	setLocalAddress(net.IP)
	setRemoteAddresses([]net.IP)
	setVNI(uint32)
	setL2TOS(uint8)
	newVIF(*vswitch.VIF) (vswitch.VIFInstance, error)
	updateCounter()
	resetCounter()
}

type tunnelIF struct {
	base       *vswitch.BaseInstance
	priv       interface{}
	moduleConf *ModuleConfig
	iface      concreteIF
	mac        net.HardwareAddr
	mtu        vswitch.MTU
	mode       vswitch.VLANMode
	state      interfaceState
	lock       sync.Mutex
}

func newTunnelIF(base *vswitch.BaseInstance, priv interface{}) *tunnelIF {
	return &tunnelIF{
		base:       base,
		priv:       priv,
		moduleConf: nil,
		iface:      nil,
		mac:        nil,
		mtu:        vswitch.DefaultMTU,
		mode:       vswitch.AccessMode,
		state:      initialized,
	}
}

//
// Instance interface
//

// Enable Enable for instance.
func (t *tunnelIF) Enable() error {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.iface == nil {
		if t.state != freed {
			t.state = enabled
		}
	} else {
		return t.iface.Enable()
	}

	return nil
}

// Disable Disable for instance.
func (t *tunnelIF) Disable() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.iface == nil {
		if t.state != freed {
			t.state = disabled
		}
	} else {
		t.iface.Disable()
	}
}

// Free Free for instance.
func (t *tunnelIF) Free() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.iface == nil {
		t.state = freed
	} else {
		t.iface.Free()
	}
}

//
// InterfaceInstance interface
//

// NewVIF Create VIF.
func (t *tunnelIF) NewVIF(vif *vswitch.VIF) (vswitch.VIFInstance, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	log.Logger.Info("[%s][%s] new Tunnel VIF: index=%d", t.base.Name(), vif.Name(), vif.Index())

	if vif == nil {
		return nil, fmt.Errorf("VIF is nil")
	}

	if t.iface == nil {
		var err error

		var proto ProtocolType
		if proto, err = getProtocolType(t.priv, vif); err != nil {
			return nil, fmt.Errorf("get protocol type failed: %v", err)
		}
		log.Logger.Info("[%s][%s] protocol: %s", t.base.Name(), vif.Name(), proto)

		if t.moduleConf, err = GetModuleConfig(proto); err != nil {
			return nil, fmt.Errorf("module config decode failed: %v", err)
		}
		log.Logger.Info("[%s][%s] module config: %#v", t.base.Name(), vif.Name(), t.moduleConf)

		accessor := newIfParam(proto, t)

		if t.iface, err = mgr.newConcreteIF(accessor); err != nil {
			return nil, fmt.Errorf("create IF failed: %v", err)
		}

		switch t.state {
		case initialized:
			// do nothing.
		case enabled:
			if err = t.iface.Enable(); err != nil {
				return nil, fmt.Errorf("IF enable failed: %v", err)
			}
		case disabled:
			t.iface.Disable()
		case freed:
			t.iface.Free()
		default:
			return nil, fmt.Errorf("invalid IF state: %d", t.state)
		}
	}

	tvif, err := t.iface.newVIF(vif)
	if err != nil {
		return nil, fmt.Errorf("create VIF failed: %v", err)
	}

	return tvif, nil
}

// MACAddress MACAddress.
func (t *tunnelIF) MACAddress() net.HardwareAddr {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.mac
}

// SetMACAddress SetMACAddress.
func (t *tunnelIF) SetMACAddress(mac net.HardwareAddr) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.mac = mac
	return nil
}

// MTU MTU.
func (t *tunnelIF) MTU() vswitch.MTU {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.mtu
}

// SetMTU SetMTU.
func (t *tunnelIF) SetMTU(mtu vswitch.MTU) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.mtu = mtu
	return nil
}

// InterfaceMode InterfaceMode.
func (t *tunnelIF) InterfaceMode() vswitch.VLANMode {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.iface != nil {
		return t.iface.interfaceMode()
	}

	return t.mode
}

// SetInterfaceMode SetInterfaceMode.
func (t *tunnelIF) SetInterfaceMode(mode vswitch.VLANMode) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.iface != nil {
		t.iface.setInterfaceMode(mode)
	}

	t.mode = mode

	return nil
}

// AddVID AddVID.
func (t *tunnelIF) AddVID(vid vswitch.VID) error {
	return nil
}

// DeleteVID DeleteVID.
func (t *tunnelIF) DeleteVID(vid vswitch.VID) error {
	return nil
}

// SetNativeVID SetNativeVID.
func (t *tunnelIF) SetNativeVID(vid vswitch.VID) error {
	// TODO: set native VID
	return nil
}

//
// CounterUpdater interface
//
func (t *tunnelIF) UpdateCounter() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.iface != nil {
		t.iface.updateCounter()
	}
}

func (t *tunnelIF) ResetCounter() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.iface != nil {
		t.iface.resetCounter()
	}
}

//
// L2TunnelNotify interface
//

// AddressTypeUpdated Update address type.
func (t *tunnelIF) AddressTypeUpdated(addressType vswitch.AddressFamily) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.iface != nil {
		t.iface.setAddressType(addressType)
	}
}

// HopLimitUpdated Update HopLimit.
func (t *tunnelIF) HopLimitUpdated(hopLimit uint8) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.iface != nil {
		t.iface.setHopLimit(hopLimit)
	}
}

// LocalAddressUpdated Update local IP addr.
func (t *tunnelIF) LocalAddressUpdated(localAddr net.IP) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.iface != nil {
		t.iface.setLocalAddress(localAddr)
	}
}

// RemoteAddressesUpdated Update remote IP addrs.
func (t *tunnelIF) RemoteAddressesUpdated(remoteAddrs []net.IP) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.iface != nil {
		t.iface.setRemoteAddresses(remoteAddrs)
	}
}

// VRFUpdated Update VRF.
func (t *tunnelIF) VRFUpdated(vrf *vswitch.VRF) {
	// do nothing.
}

// VNIUpdated Update VNI
func (t *tunnelIF) VNIUpdated(vni uint32) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.iface != nil {
		t.iface.setVNI(vni)
	}
}

// L2TOSUpdated Update TOS.
func (t *tunnelIF) L2TOSUpdated(tos uint8) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.iface != nil {
		t.iface.setL2TOS(tos)
	}
}

func getProtocolType(priv interface{}, vif *vswitch.VIF) (ProtocolType, error) {
	proto := Unknown

	if vif == nil {
		return proto, fmt.Errorf("vif is nil")
	}

	if l2tunnel, ok := priv.(*vswitch.L2Tunnel); ok {
		switch l2tunnel.EncapsMethod() {
		case vswitch.EncapsMethodGRE:
			proto = L2GRE
		case vswitch.EncapsMethodVxLAN:
			proto = VXLAN
		default:
			return proto, fmt.Errorf("invalid encaps-method: %d", l2tunnel.EncapsMethod())
		}
	} else {
		if l3tunnel := vif.Tunnel(); l3tunnel != nil {
			switch l3tunnel.EncapsMethod() {
			case vswitch.EncapsMethodDirect:
				switch l3tunnel.Security() {
				case vswitch.SecurityNone:
					proto = IPIP
				case vswitch.SecurityIPSec:
					proto = IPsec
				default:
					return proto, fmt.Errorf("invalid security: %d", l3tunnel.Security())
				}
			case vswitch.EncapsMethodGRE:
				proto = GRE
			default:
				return proto, fmt.Errorf("invalid encaps-method: %d", l3tunnel.EncapsMethod())
			}
		} else {
			return proto, fmt.Errorf("L3 tunnel is nil")
		}
	}

	return proto, nil
}
