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
#cgo CFLAGS: -I ${SRCDIR}/.. -I${SRCDIR}/../../../include -I/usr/local/include/dpdk -m64 -O3 -msse4.2
#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all -L/usr/local/lib -ldpdk

#include "ipip.h"
*/
import "C"

import (
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/modules/tunnel"
	"github.com/lagopus/vsw/vswitch"
)

// TunnelIF IPIP Tunnel interface.
type TunnelIF struct {
	index          uint16
	name           string
	inboundCiface  *C.struct_ipip_iface
	outboundCiface *C.struct_ipip_iface
	cname          *C.char
	inboundRti     *vswitch.RuntimeInstance
	outboundRti    *vswitch.RuntimeInstance
	vif            *TunnelVIF
	enable         bool
	lock           sync.Mutex
}

func newTunnelIF(index uint16, name string,
	outbound *dpdk.Ring, inbound *dpdk.Ring) *TunnelIF {
	inboundCiface := (*C.struct_ipip_iface)(C.malloc(C.sizeof_struct_ipip_iface))
	if inboundCiface == nil {
		return nil
	}

	outboundCiface := (*C.struct_ipip_iface)(C.malloc(C.sizeof_struct_ipip_iface))
	if outboundCiface == nil {
		return nil
	}

	cname := C.CString(name)

	iface := &TunnelIF{
		index:          index,
		name:           name,
		inboundCiface:  inboundCiface,
		outboundCiface: outboundCiface,
		cname:          cname,
		inboundRti:     nil,
		outboundRti:    nil,
		vif:            nil,
		enable:         false,
	}

	iface.inboundCiface.base.name = cname
	iface.inboundCiface.base.input = (*C.struct_rte_ring)(unsafe.Pointer(outbound))
	iface.inboundCiface.base.input2 = (*C.struct_rte_ring)(unsafe.Pointer(inbound))
	iface.inboundCiface.index = C.uint16_t(index)
	iface.inboundCiface.enable = false

	iface.outboundCiface.base.name = cname
	iface.outboundCiface.base.input = (*C.struct_rte_ring)(unsafe.Pointer(outbound))
	iface.outboundCiface.base.input2 = (*C.struct_rte_ring)(unsafe.Pointer(inbound))
	iface.outboundCiface.index = C.uint16_t(index)
	iface.outboundCiface.enable = false

	return iface
}

// Free Free for instance.
func (t *TunnelIF) Free() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.enable {
		t.Disable()
	}

	if t.inboundRti != nil {
		t.inboundRti.Unregister()
	}

	if t.outboundRti != nil {
		t.outboundRti.Unregister()
	}

	if t.inboundCiface != nil {
		C.free(unsafe.Pointer(t.inboundCiface))
		t.inboundCiface = nil
	}

	if t.outboundCiface != nil {
		C.free(unsafe.Pointer(t.outboundCiface))
		t.outboundCiface = nil
	}

	if t.cname != nil {
		C.free(unsafe.Pointer(t.cname))
		t.cname = nil
	}

	mgr.deleteTunnelIF(t.index)

	return
}

// Enable Enable for instance.
func (t *TunnelIF) Enable() error {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.inboundRti == nil {
		return fmt.Errorf("[%s] inbound runtime instance is nil", ModuleName)
	}

	if t.outboundRti == nil {
		return fmt.Errorf("[%s] outbound runtime instance is nil", ModuleName)
	}

	if !t.enable {
		if err := t.inboundRti.Enable(); err != nil {
			return fmt.Errorf("[%s] inbound runtime instance enable failed: %v",
						ModuleName, err)
		}

		if err := t.outboundRti.Enable(); err != nil {
			return fmt.Errorf("[%s] outbound runtime instance enable failed: %v",
						ModuleName, err)
		}

		t.enable = true
	}

	return nil
}

// Disable Disable for instance.
func (t *TunnelIF) Disable() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.inboundRti == nil {
		return
	}

	if t.outboundRti == nil {
		return
	}

	if t.enable {
		t.inboundRti.Disable()
		t.outboundRti.Disable()
		t.enable = false
	}

	return
}

// NewVIF Create VIF.
func (t *TunnelIF) NewVIF(vif *vswitch.VIF) (vswitch.VIFInstance, error) {
	if vif == nil {
		return nil, fmt.Errorf("[%s] VIF is nil", ModuleName)
	}

	if t.vif != nil {
		return nil, fmt.Errorf("[%s] VIF %s already exists", ModuleName, vif.Name())
	}

	t.vif = newTunnelVIF(t, vif)

	return t.vif, nil
}

// TunnelVIF IPIP Tunnel VIF.
type TunnelVIF struct {
	iface  *TunnelIF
	vif    *vswitch.VIF
	enable bool
	lock   sync.Mutex
}

func newTunnelVIF(iface *TunnelIF, vif *vswitch.VIF) *TunnelVIF {
	if iface == nil || vif == nil {
		return nil
	}

	return &TunnelVIF{
		iface:  iface,
		vif:    vif,
		enable: false,
	}
}

// SetVRF Set VRF.
func (t *TunnelVIF) SetVRF(vrf *vswitch.VRF) {
	// do nothing.
}

// Free Free for VIF instance.
func (t *TunnelVIF) Free() {
	if t.enable {
		t.Disable()
	}
}

func (t *TunnelVIF) validate() error {
	if t.vif.Output() == nil {
		return fmt.Errorf("no output")
	}

	tunnel := t.vif.Tunnel()

	if tunnel == nil {
		return fmt.Errorf("no tunnel")
	}

	if tunnel.LocalAddress() == nil {
		return fmt.Errorf("no local address")
	}

	if tunnel.RemoteAddress() == nil {
		return fmt.Errorf("no remote address")
	}

	return nil
}

// Enable Enable for VIF instance.
func (t *TunnelVIF) Enable() error {
	t.lock.Lock()
	defer t.lock.Unlock()

	if !t.enable {
		if err := t.validate(); err != nil {
			return fmt.Errorf("[%s] validation failed: %v", ModuleName, err)
		}

		tunnel := t.vif.Tunnel()
		addressType := tunnel.AddressType()
		localAddr := tunnel.LocalAddress()
		remoteAddr := tunnel.RemoteAddress()
		hopLimit := tunnel.HopLimit()
		tos := tunnel.TOS()
		output := (*C.struct_rte_ring)(unsafe.Pointer(t.vif.Output()))
		enable := true

		cparam := t.newAllCmdParam(addressType, localAddr, remoteAddr,
			hopLimit, tos, enable, output)

		if rc, err := t.iface.inboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
			return fmt.Errorf("[%s] inbound all cmd Failed: %v", ModuleName, err)
		}

		if rc, err := t.iface.outboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
			return fmt.Errorf("[%s] outbound all cmd Failed: %v", ModuleName, err)
		}

		t.enable = true
	}

	return nil
}

// Disable Disable for VIF instance.
func (t *TunnelVIF) Disable() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.enable {
		cparam := t.newEnableCmdParam(false)

		if rc, err := t.iface.inboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
			log.Printf("[%s] inbound enable cmd Failed: %v", ModuleName, err)
		}

		if rc, err := t.iface.outboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
			log.Printf("[%s] outbound enable cmd Failed: %v", ModuleName, err)
		}

		t.enable = false
	}
}

// EncapsMethodUpdated Update encaps method.
func (t *TunnelVIF) EncapsMethodUpdated(encapMethod vswitch.EncapsMethod) {
	// do nothing.
}

// SecurityUpdated Update security.
func (t *TunnelVIF) SecurityUpdated(security vswitch.Security) {
	// do nothing.
}

// AddressTypeUpdated Update address type.
func (t *TunnelVIF) AddressTypeUpdated(addressType vswitch.AddressFamily) {
	cparam := t.newAddressTypeCmdParam(addressType)

	if rc, err := t.iface.inboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
		log.Printf("[%s] inbound address type cmd Failed: %v", ModuleName, err)
	}

	if rc, err := t.iface.outboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
		log.Printf("[%s] outbound address type cmd Failed: %v", ModuleName, err)
	}
}

// LocalAddressUpdated Update local IP addr.
func (t *TunnelVIF) LocalAddressUpdated(localAddr net.IP) {
	if localAddr == nil {
		return
	}

	cparam := t.newLocalAddressCmdParam(localAddr)

	if rc, err := t.iface.inboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
		log.Printf("[%s] inbound local address cmd Failed: %v", ModuleName, err)
	}

	if rc, err := t.iface.outboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
		log.Printf("[%s] outbound local address cmd Failed: %v", ModuleName, err)
	}
}

// RemoteAddressUpdated Update remote IP addr.
func (t *TunnelVIF) RemoteAddressUpdated(remoteAddr net.IP) {
	if remoteAddr == nil {
		return
	}

	cparam := t.newRemoteAddressCmdParam(remoteAddr)

	if rc, err := t.iface.inboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
		log.Printf("[%s] inbound remote address cmd Failed: %v", ModuleName, err)
	}

	if rc, err := t.iface.outboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
		log.Printf("[%s] outbound remote address cmd Failed: %v", ModuleName, err)
	}
}

// HopLimitUpdated Update HopLimit.
func (t *TunnelVIF) HopLimitUpdated(hopLimit uint8) {
	cparam := t.newHopLimitCmdParam(hopLimit)

	if rc, err := t.iface.inboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
		log.Printf("[%s] inbound hoplimit cmd Failed: %v", ModuleName, err)
	}

	if rc, err := t.iface.outboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
		log.Printf("[%s] outbound hoplimit cmd Failed: %v", ModuleName, err)
	}
}

// TOSUpdated Update TOS.
func (t *TunnelVIF) TOSUpdated(tos int8) {
	cparam := t.newTOSCmdParam(tos)

	if rc, err := t.iface.inboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
		log.Printf("[%s] inbound tos cmd Failed: %v", ModuleName, err)
	}

	if rc, err := t.iface.outboundRti.Control(unsafe.Pointer(cparam)); !rc || err != nil {
		log.Printf("[%s] outbound tos cmd Failed: %v", ModuleName, err)
	}
}

func (t *TunnelVIF) newAddressTypeCmdParam(addressType vswitch.AddressFamily) *C.struct_ipip_control_param {
	return &C.struct_ipip_control_param{
		cmd:          C.ipip_cmd_t(C.IPIP_CMD_SET_ADDRESS_TYPE),
		address_type: C.uint16_t(uint16(addressType)),
	}
}

func (t *TunnelVIF) newLocalAddressCmdParam(localAddr net.IP) *C.struct_ipip_control_param {
	return &C.struct_ipip_control_param{
		cmd:        C.ipip_cmd_t(C.IPIP_CMD_SET_LOCAL_ADDR),
		local_addr: ip2ipAddr(localAddr),
	}
}

func (t *TunnelVIF) newRemoteAddressCmdParam(remoteAddr net.IP) *C.struct_ipip_control_param {
	return &C.struct_ipip_control_param{
		cmd:         C.ipip_cmd_t(C.IPIP_CMD_SET_REMOTE_ADDR),
		remote_addr: ip2ipAddr(remoteAddr),
	}
}

func (t *TunnelVIF) newHopLimitCmdParam(hopLimit uint8) *C.struct_ipip_control_param {
	return &C.struct_ipip_control_param{
		cmd:       C.ipip_cmd_t(C.IPIP_CMD_SET_HOP_LIMIT),
		hop_limit: C.uint8_t(hopLimit),
	}
}

func (t *TunnelVIF) newTOSCmdParam(tos int8) *C.struct_ipip_control_param {
	return &C.struct_ipip_control_param{
		cmd: C.ipip_cmd_t(C.IPIP_CMD_SET_TOS),
		tos: C.int8_t(tos),
	}
}

func (t *TunnelVIF) newEnableCmdParam(enable bool) *C.struct_ipip_control_param {
	return &C.struct_ipip_control_param{
		cmd:    C.ipip_cmd_t(C.IPIP_CMD_SET_ENABLE),
		enable: C.bool(enable),
	}
}

func (t *TunnelVIF) newAllCmdParam(addressType vswitch.AddressFamily,
	localAddr net.IP, remoteAddr net.IP,
	hopLimit uint8, tos int8, enable bool,
	output *C.struct_rte_ring) *C.struct_ipip_control_param {
	return &C.struct_ipip_control_param{
		cmd:          C.ipip_cmd_t(C.IPIP_CMD_SET_ALL),
		address_type: C.uint16_t(uint16(addressType)),
		local_addr:   ip2ipAddr(localAddr),
		remote_addr:  ip2ipAddr(remoteAddr),
		hop_limit:    C.uint8_t(hopLimit),
		tos:          C.int8_t(tos),
		output:       output,
		enable:       C.bool(enable),
	}
}

func init() {
	if err := tunnel.RegisterConcreteIF(tunnel.IPIP, mgr.newTunnelModule); err != nil {
		log.Fatalf("Failed to register a module '%s': %v", ModuleName, err)
	}
}
