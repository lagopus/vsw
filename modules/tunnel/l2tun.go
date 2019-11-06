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
#include "l2tun.h"
#include "gre.h"
#include "vxlan.h"
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

type l2TunnelIF struct {
	protocol       ProtocolType
	name           string
	inboundCIface  *C.struct_l2tun_iface
	outboundCIface *C.struct_l2tun_iface
	inboundCname   *C.char
	outboundCname  *C.char
	inboundStats   *C.struct_tunnel_stats
	outboundStats  *C.struct_tunnel_stats
	inboundRti     *vswitch.RuntimeInstance
	outboundRti    *vswitch.RuntimeInstance
	mode           vswitch.VLANMode
	l2tunnel       *vswitch.L2Tunnel
	rules          *vswitch.Rules
	counter        *C.struct_vsw_counter
	vifs           map[string]*l2TunnelVIF
	enabled        bool
	lock           sync.Mutex
}

func newL2TunnelIF(accessor ifParamAccessor) *l2TunnelIF {
	inboundCIface := (*C.struct_l2tun_iface)(C.calloc(1, C.sizeof_struct_l2tun_iface))
	if inboundCIface == nil {
		return nil
	}

	outboundCIface := (*C.struct_l2tun_iface)(C.calloc(1, C.sizeof_struct_l2tun_iface))
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
	if inboundStats == nil {
		C.free(unsafe.Pointer(inboundCIface))
		C.free(unsafe.Pointer(outboundCIface))
		C.free(unsafe.Pointer(inboundStats))
		return nil
	}

	iface := &l2TunnelIF{
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
		mode:           accessor.interfaceMode(),
		l2tunnel:       accessor.l2tunnelConfig(),
		rules:          accessor.rules(),
		counter:        (*C.struct_vsw_counter)(unsafe.Pointer(accessor.counter())),
		vifs:           make(map[string]*l2TunnelVIF),
		enabled:        false,
	}

	moduleConfig := accessor.moduleConfig()

	inboundInput := accessor.inbound()
	outboundInput := accessor.outbound()

	iface.inboundCIface.base.name = inboundCname
	iface.inboundCIface.stats = inboundStats
	iface.inboundCIface.base.input = (*C.struct_rte_ring)(unsafe.Pointer(outboundInput))
	iface.inboundCIface.base.input2 = (*C.struct_rte_ring)(unsafe.Pointer(inboundInput))
	iface.inboundCIface.inbound = true
	iface.inboundCIface.inbound_core = C.uint32_t(moduleConfig.InboundCore)
	iface.inboundCIface.outbound_core = C.uint32_t(moduleConfig.OutboundCore)
	iface.inboundCIface.enabled = false

	iface.outboundCIface.base.name = outboundCname
	iface.outboundCIface.stats = outboundStats
	iface.outboundCIface.base.input = (*C.struct_rte_ring)(unsafe.Pointer(outboundInput))
	iface.outboundCIface.base.input2 = (*C.struct_rte_ring)(unsafe.Pointer(inboundInput))
	iface.outboundCIface.inbound = false
	iface.outboundCIface.inbound_core = C.uint32_t(moduleConfig.InboundCore)
	iface.outboundCIface.outbound_core = C.uint32_t(moduleConfig.OutboundCore)
	iface.outboundCIface.enabled = false

	return iface
}

//
// concreteIF interface
//

// Enable Enable for instance.
func (l *l2TunnelIF) Enable() error {
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
func (l *l2TunnelIF) Disable() {
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

// Free Free for instance.
func (l *l2TunnelIF) Free() {
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
	l.inboundStats = nil
	l.outboundCname = nil
	l.outboundStats = nil

	// free all VIF
	for _, l2vif := range l.vifs {
		l2vif.Free()
	}

	mgr.deleteConcreteIF(l.protocol, l.name)

	return
}

func (l *l2TunnelIF) deleteL2TunnelVIF(name string) {
	l.lock.Lock()
	defer l.lock.Unlock()

	if _, ok := l.vifs[name]; ok {
		delete(l.vifs, name)
	}
}

func (l *l2TunnelIF) inboundInstance() vswitch.LagopusInstance {
	return (vswitch.LagopusInstance)(unsafe.Pointer(l.inboundCIface))
}

func (l *l2TunnelIF) outboundInstance() vswitch.LagopusInstance {
	return (vswitch.LagopusInstance)(unsafe.Pointer(l.outboundCIface))
}

func (l *l2TunnelIF) setInboundRti(inboundRti *vswitch.RuntimeInstance) {
	l.inboundRti = inboundRti
}

func (l *l2TunnelIF) setOutboundRti(outboundRti *vswitch.RuntimeInstance) {
	l.outboundRti = outboundRti
}

func (l *l2TunnelIF) interfaceMode() vswitch.VLANMode {
	return l.mode
}

func (l *l2TunnelIF) setInterfaceMode(mode vswitch.VLANMode) error {
	cparam := createL2SetVLANModeCmdParam(mode)
	if err := l.doControl(cparam); err != nil {
		log.Logger.Err("[%s] update VLAN mode Failed: %v", l.name, err)
		return err
	}

	l.mode = mode

	return nil
}

func (l *l2TunnelIF) setAddressType(addressType vswitch.AddressFamily) {
	cparam := createL2SetAddressTypeCmdParam(addressType)
	if err := l.doControl(cparam); err != nil {
		log.Logger.Err("[%s] update AddressType Failed: %v", l.name, err)
	}
}

func (l *l2TunnelIF) setHopLimit(hopLimit uint8) {
	cparam := createL2SetHopLimitCmdParam(hopLimit)
	if err := l.doControl(cparam); err != nil {
		log.Logger.Err("[%s] update HopLimit Failed: %v", l.name, err)
	}
}

func (l *l2TunnelIF) setLocalAddress(localAddr net.IP) {
	if localAddr == nil {
		log.Logger.Err("[%s] local address is nil.", l.name)
		return
	}

	cparam := createL2SetLocalAddressCmdParam(localAddr)
	if err := l.doControl(cparam); err != nil {
		log.Logger.Err("[%s] update LocalAddress Failed: %v", l.name, err)
	}
}

func (l *l2TunnelIF) setRemoteAddresses(remoteAddrs []net.IP) {
	if remoteAddrs == nil {
		log.Logger.Err("[%s] remote address is nil.", l.name)
		return
	}

	switch l.protocol {
	case L2GRE:
		if len(remoteAddrs) != 1 {
			log.Logger.Err("[%s] invalid remote address: %v", l.name, remoteAddrs)
			return
		}

		cparam := createL2SetRemoteAddressesCmdParam(remoteAddrs)
		if err := l.doControl(cparam); err != nil {
			log.Logger.Err("[%s] update RemoteAddress Failed: %v", l.name, err)
		}
	case VXLAN:
		if len(remoteAddrs) < 1 {
			log.Logger.Err("[%s] invalid remote address: %v", l.name, remoteAddrs)
			return
		}

		cparam := createL2SetRemoteAddressesCmdParam(remoteAddrs)
		if err := l.doControl(cparam); err != nil {
			log.Logger.Err("[%s] update RemoteAddress Failed: %v", l.name, err)
		}
	default:
		log.Logger.Err("[%s] unsupport protocol: %v", l.name, l.protocol)
		return
	}
}

func (l *l2TunnelIF) setVNI(vni uint32) {
	cparam := createL2SetVNICmdParam(vni)
	if err := l.doControl(cparam); err != nil {
		log.Logger.Err("[%s] update VNI Failed: %v", l.name, err)
	}
}

func (l *l2TunnelIF) setL2TOS(tos uint8) {
	cparam := createL2SetTOSCmdParam(tos)
	if err := l.doControl(cparam); err != nil {
		log.Logger.Err("[%s] update TOS Failed: %v", l.name, err)
	}
}

func (l *l2TunnelIF) newVIF(vif *vswitch.VIF) (vswitch.VIFInstance, error) {
	if vif == nil {
		return nil, fmt.Errorf("[%s] VIF is nil", l.name)
	} else if _, ok := l.vifs[vif.Name()]; ok {
		return nil, fmt.Errorf("[%s] VIF %s already exists", l.name, vif.Name())
	}

	l2vif := newL2TunnelVIF(l, vif)

	l.vifs[vif.Name()] = l2vif

	return l2vif, nil
}

func (l *l2TunnelIF) updateCounter() {
	switch l.mode {
	case vswitch.AccessMode:
		C.tunnel_update_counter(l.counter, l.inboundStats, l.outboundStats)
	case vswitch.TrunkMode:
		C.l2tun_update_if_trunk_counter(l.counter, l.inboundStats, l.outboundStats)
	default:
		log.Logger.Warning("[%s] unsupport VLAN mode: %v", l.name, l.mode)
	}
}

func (l *l2TunnelIF) resetCounter() {
	C.tunnel_reset_counter(l.counter, l.inboundStats, l.outboundStats)
}

func (l *l2TunnelIF) doControl(param *C.struct_l2tun_control_param) error {
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

func (l *l2TunnelIF) doControlInbound(param *C.struct_l2tun_control_param) error {
	cparam := toL2CParam(param)
	if cparam == nil {
		return fmt.Errorf("inbound toL2CParam failed")
	}
	defer freeL2CParam(cparam)

	// premise: Control is synchronous call
	if rc, err := l.inboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
		return fmt.Errorf("inbound cmd(%d) failed: %v", cparam.cmd, err)
	}
	return nil
}

func (l *l2TunnelIF) doControlOutbound(param *C.struct_l2tun_control_param) error {
	cparam := toL2CParam(param)
	if cparam == nil {
		return fmt.Errorf("outbound toL2CParam failed")
	}
	defer freeL2CParam(cparam)

	// premise: Control is synchronous call
	if rc, err := l.outboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
		return fmt.Errorf("outbound cmd(%d) failed: %v", cparam.cmd, err)
	}
	return nil
}

func (l *l2TunnelIF) String() string {
	var str string
	str = fmt.Sprintf("Protocol: %s", l.protocol)
	str = fmt.Sprintf("%s, Name: %s", str, l.name)
	str = fmt.Sprintf("%s, Mode: %s", str, l.mode.String())
	for _, l2vif := range l.vifs {
		str = fmt.Sprintf("%s, Vif(%s): {%s}", str, l2vif.vif.Name(), l2vif.String())
	}
	return str
}

type l2TunnelVIF struct {
	iface         *l2TunnelIF
	vif           *vswitch.VIF
	inboundStats  *C.struct_tunnel_stats
	outboundStats *C.struct_tunnel_stats
	counter       *C.struct_vsw_counter
	enabled       bool
	lock          sync.Mutex
}

func newL2TunnelVIF(iface *l2TunnelIF, vif *vswitch.VIF) *l2TunnelVIF {
	if iface == nil || vif == nil {
		return nil
	}

	// free on <protocol>_unregister_iface
	inboundStats := (*C.struct_tunnel_stats)(C.calloc(1, C.sizeof_struct_tunnel_stats))
	outboundStats := (*C.struct_tunnel_stats)(C.calloc(1, C.sizeof_struct_tunnel_stats))

	return &l2TunnelVIF{
		iface:         iface,
		vif:           vif,
		inboundStats:  inboundStats,
		outboundStats: outboundStats,
		counter:       (*C.struct_vsw_counter)(unsafe.Pointer(vif.Counter())),
		enabled:       false,
	}
}

func (l *l2TunnelVIF) name() string {
	return l.vif.Name()
}

// SetVRF Set VRF.
func (l *l2TunnelVIF) SetVRF(vrf *vswitch.VRF) {
	// do nothing.
}

// Free Free for VIF instance.
func (l *l2TunnelVIF) Free() {
	log.Logger.Info("[%s] Free called", l.vif.Name())

	if l.enabled {
		l.Disable()
	}

	// delete from l2TunnelIF
	l.iface.deleteL2TunnelVIF(l.vif.Name())
}

func (l *l2TunnelVIF) validate() error {
	if l.vif.Output() == nil {
		return fmt.Errorf("no inbound output")
	}

	if l.iface.rules.Output(vswitch.MatchIPv4Dst) == nil {
		return fmt.Errorf("no outbound output")
	}

	tunnel := l.iface.l2tunnel

	if tunnel == nil {
		return fmt.Errorf("no tunnel")
	}

	if tunnel.LocalAddress() == nil {
		return fmt.Errorf("no local address")
	}

	if tunnel.RemoteAddresses() == nil {
		return fmt.Errorf("no remote addresses")
	}

	return nil
}

// Enable Enable for VIF instance.
func (l *l2TunnelVIF) Enable() error {
	l.lock.Lock()
	defer l.lock.Unlock()

	log.Logger.Info("[%s] Enable called", l.vif.Name())

	if !l.enabled {
		if err := l.validate(); err != nil {
			log.Logger.Err("[%s] validation failed: %v", l.vif.Name(), err)
			return err
		}

		tunnel := l.iface.l2tunnel
		index := l.vif.Index()
		addressType := tunnel.AddressType()
		localAddr := tunnel.LocalAddress()
		remoteAddrs := tunnel.RemoteAddresses()
		hopLimit := tunnel.HopLimit()
		tos := tunnel.TOS()
		inboudOutput := (*C.struct_rte_ring)(unsafe.Pointer(l.vif.Output()))
		outboudOutput := (*C.struct_rte_ring)(unsafe.Pointer(l.iface.rules.Output(vswitch.MatchIPv4Dst)))
		vid := l.vif.VID()
		mode := l.iface.mode
		vni := tunnel.VNI()
		inboundStats := l.inboundStats
		outboundStats := l.outboundStats

		var cparam *C.struct_l2tun_control_param
		switch l.iface.protocol {
		case L2GRE:
			if len(remoteAddrs) != 1 {
				err := fmt.Errorf("invalid remote address: %v", remoteAddrs)
				log.Logger.Err("[%s] %s", l.name(), err)
				return err
			}

			cparam = createL2SetEnableCmdParam(index, addressType, localAddr, remoteAddrs,
				hopLimit, tos, inboudOutput, outboudOutput, vid, mode, vni,
				inboundStats, outboundStats)
		case VXLAN:
			if len(remoteAddrs) < 1 {
				err := fmt.Errorf("invalid remote address: %v", remoteAddrs)
				log.Logger.Err("[%s] %s", l.name(), err)
				return err
			}

			cparam = createL2SetEnableCmdParam(index, addressType, localAddr, remoteAddrs,
				hopLimit, tos, inboudOutput, outboudOutput, vid, mode, vni,
				inboundStats, outboundStats)
		default:
			err := fmt.Errorf("unsupport protocol: %s", l.iface.protocol)
			log.Logger.Err("[%s] %s", l.name(), err)
			return err
		}

		if err := l.iface.doControl(cparam); err != nil {
			log.Logger.Err("[%s] Enable failed: %v", l.vif.Name(), err)
			return err
		}

		l.enabled = true
	}

	return nil
}

// Disable Disable for VIF instance.
func (l *l2TunnelVIF) Disable() {
	l.lock.Lock()
	defer l.lock.Unlock()

	log.Logger.Info("[%s] Disable called", l.vif.Name())

	if l.enabled {
		cparam := createL2SetDisableCmdParam(l.vif.Index(), l.vif.VID())

		if err := l.iface.doControl(cparam); err != nil {
			log.Logger.Err("[%s] Disable failed: %v", l.vif.Name(), err)
			return
		}

		l.enabled = false
	}
}

func (l *l2TunnelVIF) UpdateCounter() {
	switch l.iface.mode {
	case vswitch.AccessMode:
		// aggregate from interface counter
		C.l2tun_update_vif_counter(l.counter, l.iface.inboundStats, l.iface.outboundStats)
	case vswitch.TrunkMode:
		// aggregate from VIF counter
		C.l2tun_update_vif_counter(l.counter, l.inboundStats, l.outboundStats)
	default:
		log.Logger.Warning("[%s] unsupport VLAN mode: %v", l.vif.Name(), l.iface.mode)
	}
}

func (l *l2TunnelVIF) ResetCounter() {
	C.tunnel_reset_counter(l.counter, l.inboundStats, l.outboundStats)
}

func (l *l2TunnelVIF) String() string {
	var str string
	str = fmt.Sprintf("%#v", l.vif)
	return str
}

func newL2ConcreteIF(accessor ifParamAccessor) (concreteIF, error) {
	return newL2TunnelIF(accessor), nil
}

func init() {
	moduleDataList := []*moduleData{
		&moduleData{
			protocol:    L2GRE,
			factory:     newL2ConcreteIF,
			inboundOps:  vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.l2gre_inbound_runtime_ops)),
			outboundOps: vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.l2gre_outbound_runtime_ops)),
		},
		&moduleData{
			protocol:    VXLAN,
			factory:     newVXLANConcreteIF,
			inboundOps:  vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.vxlan_inbound_runtime_ops)),
			outboundOps: vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.vxlan_outbound_runtime_ops)),
		},
	}

	for _, moduleData := range moduleDataList {
		if err := registerTunnelModule(moduleData); err != nil {
			log.Logger.Fatalf("[Failed to register %s module: %v", moduleData.protocol, err)
		}
	}
}
