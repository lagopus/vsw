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
#include "l3tun.h"
#include "ipip.h"
#include "gre.h"
*/
import "C"

import (
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/lagopus/vsw/modules/tunnel/log"
	"github.com/lagopus/vsw/vswitch"
)

type l3TunnelIF struct {
	protocol       ProtocolType
	name           string
	inboundCIface  *C.struct_l3tun_iface
	outboundCIface *C.struct_l3tun_iface
	inboundCname   *C.char
	outboundCname  *C.char
	inboundStats   *C.struct_tunnel_stats
	outboundStats  *C.struct_tunnel_stats
	inboundRti     *vswitch.RuntimeInstance
	outboundRti    *vswitch.RuntimeInstance
	counter        *C.struct_vsw_counter
	vif            *l3TunnelVIF
	enabled        bool
	lock           sync.Mutex
}

func newL3TunnelIF(accessor ifParamAccessor) *l3TunnelIF {
	inboundCIface := (*C.struct_l3tun_iface)(C.calloc(1, C.sizeof_struct_l3tun_iface))
	if inboundCIface == nil {
		return nil
	}

	outboundCIface := (*C.struct_l3tun_iface)(C.calloc(1, C.sizeof_struct_l3tun_iface))
	if outboundCIface == nil {
		C.free(unsafe.Pointer(inboundCIface))
		return nil
	}

	// free on <protocol>_unregister_iface
	inboundCname := C.CString(accessor.name())
	inboundStats := (*C.struct_tunnel_stats)(C.calloc(1, C.sizeof_struct_tunnel_stats))
	if inboundStats == nil {
		C.free(unsafe.Pointer(inboundCIface))
		C.free(unsafe.Pointer(outboundCIface))
		return nil
	}
	outboundCname := C.CString(accessor.name())
	outboundStats := (*C.struct_tunnel_stats)(C.calloc(1, C.sizeof_struct_tunnel_stats))
	if outboundStats == nil {
		C.free(unsafe.Pointer(inboundCIface))
		C.free(unsafe.Pointer(outboundCIface))
		C.free(unsafe.Pointer(inboundStats))
		return nil
	}

	iface := &l3TunnelIF{
		protocol:       accessor.protocol(),
		name:           accessor.name(),
		inboundCIface:  inboundCIface,
		outboundCIface: outboundCIface,
		inboundCname:   inboundCname,
		outboundCname:  outboundCname,
		inboundStats:   inboundStats,
		outboundStats:  outboundStats,
		inboundRti:     nil,
		outboundRti:    nil,
		counter:        (*C.struct_vsw_counter)(unsafe.Pointer(accessor.counter())),
		vif:            nil,
		enabled:        false,
	}

	inboundInput := accessor.inbound()
	outboundInput := accessor.outbound()

	iface.inboundCIface.base.name = inboundCname
	iface.inboundCIface.stats = inboundStats
	iface.inboundCIface.base.input = (*C.struct_rte_ring)(unsafe.Pointer(outboundInput))
	iface.inboundCIface.base.input2 = (*C.struct_rte_ring)(unsafe.Pointer(inboundInput))
	iface.inboundCIface.enabled = false

	iface.outboundCIface.base.name = outboundCname
	iface.outboundCIface.stats = outboundStats
	iface.outboundCIface.base.input = (*C.struct_rte_ring)(unsafe.Pointer(outboundInput))
	iface.outboundCIface.base.input2 = (*C.struct_rte_ring)(unsafe.Pointer(inboundInput))
	iface.outboundCIface.enabled = false

	return iface
}

// Free Free for instance.
func (l *l3TunnelIF) Free() {
	log.Logger.Info("[%s] Free called", l.name)

	if l.enabled {
		l.Disable()
	}

	if l.inboundRti != nil {
		l.inboundRti.Unregister()
		l.inboundRti = nil
	}

	if l.outboundRti != nil {
		l.outboundRti.Unregister()
		l.outboundRti = nil
	}

	if l.inboundCIface != nil {
		C.free(unsafe.Pointer(l.inboundCIface))
		l.inboundCIface = nil
	}

	if l.outboundCIface != nil {
		C.free(unsafe.Pointer(l.outboundCIface))
		l.outboundCIface = nil
	}

	l.inboundCname = nil
	l.outboundCname = nil

	mgr.deleteConcreteIF(l.protocol, l.name)

	return
}

// Enable Enable for instance.
func (l *l3TunnelIF) Enable() error {
	l.lock.Lock()
	defer l.lock.Unlock()

	log.Logger.Info("[%s] Enable called", l.name)

	if l.inboundRti == nil {
		err := fmt.Errorf("inbound runtime instance is nil")
		log.Logger.Err("[%s] %s", l.name, err)
		return err
	}

	if l.outboundRti == nil {
		err := fmt.Errorf("outbound runtime instance is nil")
		log.Logger.Err("[%s] %s", l.name, err)
		return err
	}

	if !l.enabled {
		if err := l.inboundRti.Enable(); err != nil {
			log.Logger.Err("[%s] inbound runtime instance enable failed: %v", l.name, err)
			return err
		}

		if err := l.outboundRti.Enable(); err != nil {
			log.Logger.Err("[%s] outbound runtime instance enable failed: %v", l.name, err)
			return err
		}

		l.enabled = true
	}

	return nil
}

// Disable Disable for instance.
func (l *l3TunnelIF) Disable() {
	l.lock.Lock()
	defer l.lock.Unlock()

	log.Logger.Info("[%s] Disable called", l.name)

	if l.inboundRti == nil || l.outboundRti == nil {
		return
	}

	if l.enabled {
		l.inboundRti.Disable()
		l.outboundRti.Disable()
		l.enabled = false
	}

	return
}

func (l *l3TunnelIF) inboundInstance() vswitch.LagopusInstance {
	return (vswitch.LagopusInstance)(unsafe.Pointer(l.inboundCIface))
}

func (l *l3TunnelIF) outboundInstance() vswitch.LagopusInstance {
	return (vswitch.LagopusInstance)(unsafe.Pointer(l.outboundCIface))
}

func (l *l3TunnelIF) setInboundRti(inboundRti *vswitch.RuntimeInstance) {
	l.inboundRti = inboundRti
}

func (l *l3TunnelIF) setOutboundRti(outboundRti *vswitch.RuntimeInstance) {
	l.outboundRti = outboundRti
}

func (l *l3TunnelIF) interfaceMode() vswitch.VLANMode {
	return vswitch.AccessMode
}

func (l *l3TunnelIF) setInterfaceMode(mode vswitch.VLANMode) error {
	return fmt.Errorf("[%s] SetInterfaceMode unsupported", l.name)
}

func (l *l3TunnelIF) setAddressType(addressType vswitch.AddressFamily) {
	// do nothing.
}

func (l *l3TunnelIF) setHopLimit(hopLimit uint8) {
	// do nothing.
}

func (l *l3TunnelIF) setLocalAddress(localAddr net.IP) {
	// do nothing.
}

func (l *l3TunnelIF) setRemoteAddresses(remoteAddr []net.IP) {
	// do nothing.
}

func (l *l3TunnelIF) setVNI(vni uint32) {
	// do nothing.
}

func (l *l3TunnelIF) setL2TOS(tos uint8) {
	// do nothing.
}

func (l *l3TunnelIF) newVIF(vif *vswitch.VIF) (vswitch.VIFInstance, error) {
	if vif == nil {
		return nil, fmt.Errorf("[%s] VIF is nil", l.name)
	}

	if l.vif != nil {
		return nil, fmt.Errorf("[%s] VIF %s already exists", l.name, vif.Name())
	}

	l.vif = newL3TunnelVIF(l, vif)

	return l.vif, nil
}

func (l *l3TunnelIF) updateCounter() {
	C.tunnel_update_counter(l.counter, l.inboundStats, l.outboundStats)
}

func (l *l3TunnelIF) resetCounter() {
	C.tunnel_reset_counter(l.counter, l.inboundStats, l.outboundStats)
}

func (l *l3TunnelIF) String() string {
	var str string
	str = fmt.Sprintf("Protocol: %s", l.protocol)
	str = fmt.Sprintf("%s, Name: %s", str, l.name)
	str = fmt.Sprintf("%s, Vif: %s", str, l.vif)
	return str
}

type l3TunnelVIF struct {
	iface   *l3TunnelIF
	vif     *vswitch.VIF
	counter *C.struct_vsw_counter
	enabled bool
	lock    sync.Mutex
}

func newL3TunnelVIF(iface *l3TunnelIF, vif *vswitch.VIF) *l3TunnelVIF {
	if iface == nil || vif == nil {
		return nil
	}

	return &l3TunnelVIF{
		iface:   iface,
		vif:     vif,
		counter: (*C.struct_vsw_counter)(unsafe.Pointer(vif.Counter())),
		enabled: false,
	}
}

// SetVRF Set VRF.
func (l *l3TunnelVIF) SetVRF(vrf *vswitch.VRF) {
	// do nothing.
}

// Free Free for VIF instance.
func (l *l3TunnelVIF) Free() {
	log.Logger.Info("[%s] Free called", l.vif.Name())

	if l.enabled {
		l.Disable()
	}

	l.iface.vif = nil
}

func (l *l3TunnelVIF) validate() error {
	if l.vif.Output() == nil {
		return fmt.Errorf("no inbound output")
	}

	if l.vif.Rules().Output(vswitch.MatchIPv4Dst) == nil {
		return fmt.Errorf("no outbound output")
	}

	tunnel := l.vif.Tunnel()

	if tunnel == nil {
		return fmt.Errorf("no tunnel")
	}

	if tunnel.LocalAddress() == nil {
		return fmt.Errorf("no local address")
	}

	if tunnel.RemoteAddresses() == nil || len(tunnel.RemoteAddresses()) == 0 {
		return fmt.Errorf("no remote address")
	}

	return nil
}

// Enable Enable for VIF instance.
func (l *l3TunnelVIF) Enable() error {
	l.lock.Lock()
	defer l.lock.Unlock()

	log.Logger.Info("[%s] Enable called", l.vif.Name())

	if !l.enabled {
		if err := l.validate(); err != nil {
			log.Logger.Err("[%s] validation failed: %v", l.vif.Name(), err)
			return err
		}

		tunnel := l.vif.Tunnel()
		addressType := tunnel.AddressType()
		localAddr := tunnel.LocalAddress()
		// IP in IP, GRE requires only one address.
		remoteAddr := tunnel.RemoteAddresses()[0]
		hopLimit := tunnel.HopLimit()
		tos := tunnel.TOS()
		inboudOutput := (*C.struct_rte_ring)(unsafe.Pointer(l.vif.Output()))
		outboudOutput := (*C.struct_rte_ring)(unsafe.Pointer(l.vif.Rules().Output(vswitch.MatchIPv4Dst)))

		cparam := createL3SetEnableCmdParam(addressType, localAddr, remoteAddr,
			hopLimit, tos, inboudOutput, outboudOutput)
		if err := l.doControl(cparam); err != nil {
			log.Logger.Err("[%s] Enable failed: %v", l.vif.Name(), err)
			return err
		}

		l.enabled = true
	}

	return nil
}

// Disable Disable for VIF instance.
func (l *l3TunnelVIF) Disable() {
	l.lock.Lock()
	defer l.lock.Unlock()

	log.Logger.Info("[%s] Disable called", l.vif.Name())

	if l.enabled {
		cparam := createL3SetDisableCmdParam()
		if err := l.doControl(cparam); err != nil {
			log.Logger.Err("[%s] Disable failed: %v", l.vif.Name(), err)
			return
		}

		l.enabled = false
	}
}

func (l *l3TunnelVIF) UpdateCounter() {
	// aggregate from interface counter
	C.tunnel_update_counter(l.counter, l.iface.inboundStats, l.iface.outboundStats)
}

func (l *l3TunnelVIF) ResetCounter() {
	// VIF does not have stats.
	C.tunnel_reset_counter(l.counter, nil, nil)
}

//
// L3TunnelNotify interface
//

// AddressTypeUpdated Update address type.
func (l *l3TunnelVIF) AddressTypeUpdated(addressType vswitch.AddressFamily) {
	cparam := createL3SetAddressTypeCmdParam(addressType)
	if err := l.doControl(cparam); err != nil {
		log.Logger.Err("[%s] update AddressType failed: %v", l.vif.Name(), err)
	}
}

// HopLimitUpdated Update HopLimit.
func (l *l3TunnelVIF) HopLimitUpdated(hopLimit uint8) {
	cparam := createL3SetHopLimitCmdParam(hopLimit)
	if err := l.doControl(cparam); err != nil {
		log.Logger.Err("[%s] update HopLimit failed: %v", l.vif.Name(), err)
	}
}

// LocalAddressUpdated Update local IP addr.
func (l *l3TunnelVIF) LocalAddressUpdated(localAddr net.IP) {
	if localAddr == nil {
		return
	}

	cparam := createL3SetLocalAddressCmdParam(localAddr)
	if err := l.doControl(cparam); err != nil {
		log.Logger.Err("[%s] update LocalAddress failed: %v", l.vif.Name(), err)
	}
}

// RemoteAddressesUpdated Update remote IP addr.
func (l *l3TunnelVIF) RemoteAddressesUpdated(remoteAddrs []net.IP) {
	if remoteAddrs == nil || len(remoteAddrs) == 0 {
		return
	}

	// IP in IP, GRE requires only one address.
	cparam := createL3SetRemoteAddressCmdParam(remoteAddrs[0])
	if err := l.doControl(cparam); err != nil {
		log.Logger.Err("[%s] update RemoteAddress failed: %v", l.vif.Name(), err)
	}
}

// VRFUpdated Update VRF.
func (l *l3TunnelVIF) VRFUpdated(vrf *vswitch.VRF) {
	// do nothing.
}

// SecurityUpdated Update security.
func (l *l3TunnelVIF) SecurityUpdated(security vswitch.Security) {
	// do nothing.
}

// L3TOSUpdated Update TOS.
func (l *l3TunnelVIF) L3TOSUpdated(tos int8) {
	cparam := createL3SetTOSCmdParam(tos)
	if err := l.doControl(cparam); err != nil {
		log.Logger.Err("[%s] update TOS failed: %v", l.vif.Name(), err)
	}
}

func (l *l3TunnelVIF) doControl(param *C.struct_l3tun_control_param) error {
	if param == nil {
		return fmt.Errorf("invalid args")
	}

	inboundErr := l.doControlInbound(param)
	if inboundErr != nil {
		return inboundErr
	}

	outboundErr := l.doControlOutbound(param)
	if outboundErr != nil {
		return outboundErr
	}

	return nil
}

func (l *l3TunnelVIF) doControlInbound(param *C.struct_l3tun_control_param) error {
	cparam := toL3CParam(param)
	if cparam == nil {
		return fmt.Errorf("inbound toL3CParam failed")
	}
	defer freeL3CParam(cparam)

	// premise: Control is synchronous call
	if rc, err := l.iface.inboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
		return fmt.Errorf("inbound cmd(%d) failed: %v", cparam.cmd, err)
	}
	return nil
}

func (l *l3TunnelVIF) doControlOutbound(param *C.struct_l3tun_control_param) error {
	cparam := toL3CParam(param)
	if cparam == nil {
		return fmt.Errorf("outbound toL3CParam failed")
	}
	defer freeL3CParam(cparam)

	// premise: Control is synchronous call
	if rc, err := l.iface.outboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
		return fmt.Errorf("inbound cmd(%d) failed: %v", cparam.cmd, err)
	}
	return nil
}

func (l *l3TunnelVIF) String() string {
	var str string
	str = fmt.Sprintf("%#v", l.vif)
	return str
}

func newL3ConcreteIF(accessor ifParamAccessor) (concreteIF, error) {
	return newL3TunnelIF(accessor), nil
}

func init() {
	moduleDataList := []*moduleData{
		&moduleData{
			protocol:    IPIP,
			factory:     newL3ConcreteIF,
			inboundOps:  vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.ipip_inbound_runtime_ops)),
			outboundOps: vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.ipip_outbound_runtime_ops)),
		},
		&moduleData{
			protocol:    GRE,
			factory:     newL3ConcreteIF,
			inboundOps:  vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.gre_inbound_runtime_ops)),
			outboundOps: vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.gre_outbound_runtime_ops)),
		},
	}

	for _, moduleData := range moduleDataList {
		if err := registerTunnelModule(moduleData); err != nil {
			log.Logger.Fatalf("Failed to register %s module: %v", moduleData.protocol, err)
		}
	}
}
