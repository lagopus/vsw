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

	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/modules/tunnel/log"
	"github.com/lagopus/vsw/vswitch"
)

//
// Tunnel IF.
//

type ipsecTunnelIF struct {
	*ipsec.TunnelIF
}

func newIPsecTunnelIF(accessor ifParamAccessor) (*ipsecTunnelIF, error) {
	var i *ipsec.TunnelIF
	var err error

	mc := accessor.moduleConfig()
	if mc.CoreBind && (mc.InboundCoreMask == 0 ||
		mc.OutboundCoreMask == 0) {
		return nil, fmt.Errorf("[%s] Bad CPU core ID", moduleName)
	}

	params := ipsec.NewCParams()
	params.SetCoreInfo(mc.CoreBind,
		uint64(mc.InboundCoreMask),
		uint64(mc.OutboundCoreMask))
	if i, err = ipsec.NewTunnelIF(accessor.name(),
		accessor.counter(), params); err == nil {
		tif := &ipsecTunnelIF{
			TunnelIF: i,
		}
		return tif, nil
	}
	return nil, err
}

func (i *ipsecTunnelIF) inboundInstance() vswitch.LagopusInstance {
	// do nothing.
	return nil
}

func (i *ipsecTunnelIF) outboundInstance() vswitch.LagopusInstance {
	// do nothing.
	return nil
}

func (i *ipsecTunnelIF) setInboundRti(inboundRti *vswitch.RuntimeInstance) {
	// do nothing.
}

func (i *ipsecTunnelIF) setOutboundRti(outboundRti *vswitch.RuntimeInstance) {
	// do nothing.
}

func (i *ipsecTunnelIF) interfaceMode() vswitch.VLANMode {
	return vswitch.AccessMode
}

func (i *ipsecTunnelIF) setInterfaceMode(mode vswitch.VLANMode) error {
	return fmt.Errorf("[%s] SetInterfaceMode unsupported", moduleName)
}

func (i *ipsecTunnelIF) setAddressType(addressType vswitch.AddressFamily) {
	// do nothing.
}

func (i *ipsecTunnelIF) setHopLimit(hopLimit uint8) {
	// do nothing.
}

func (i *ipsecTunnelIF) setLocalAddress(localAddr net.IP) {
	// do nothing.
}

func (i *ipsecTunnelIF) setRemoteAddresses(remoteAddr []net.IP) {
	// do nothing.
}

func (i *ipsecTunnelIF) setVNI(vni uint32) {
	// do nothing.
}

func (i *ipsecTunnelIF) setL2TOS(tos uint8) {
	// do nothing.
}

func (i *ipsecTunnelIF) updateCounter() {
	i.UpdateCounter()
}

func (i *ipsecTunnelIF) resetCounter() {
	i.ResetCounter()
}

func (i *ipsecTunnelIF) newVIF(vif *vswitch.VIF) (vswitch.VIFInstance, error) {
	return i.NewVIF(vif)
}

func newIPsecConcreteIF(accessor ifParamAccessor) (concreteIF, error) {
	return newIPsecTunnelIF(accessor)
}

func init() {
	ipsecModuleData := &moduleData{
		protocol:    IPsec,
		factory:     newIPsecConcreteIF,
		inboundOps:  nil,
		outboundOps: nil,
	}

	if err := registerTunnelModule(ipsecModuleData); err != nil {
		log.Logger.Fatalf("[%s] Failed to register IPsec module: %v", moduleName, err)
	}
}
