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

package ipsec

// #include <pthread.h>
// #include "ipsec.h"
// #include "module.h"
import "C"

import (
	"fmt"
	"log"
	"net"
	"sync"
	"unsafe"

	"github.com/lagopus/vsw/modules/tunnel"
	"github.com/lagopus/vsw/modules/tunnel/ipsec/tick"
	"github.com/lagopus/vsw/vswitch"
)

const (
	// ModuleName Name of IPsec module.
	ModuleName string = C.MODULE_NAME
)

var (
	ticker        *tick.Ticker
	tickerStarted sync.Once
	tickerStoped  sync.Once
	wg            sync.WaitGroup
	lock          sync.Mutex
	accessor      IfaceAccessor
	modules       = map[DirectionType]*Module{}
	directions    = []DirectionType{
		DirectionTypeOut,
		DirectionTypeIn,
	}
)

func init() {
	if err := tunnel.RegisterConcreteIF(tunnel.IPsec,
		newTunnelIF); err != nil {
		log.Fatalf("%v", err)
	}
}

// TunnelIF IPsec tunnel interface.
type TunnelIF struct {
	name      string
	tvif      *TunnelVIF
	lock      sync.Mutex
	isEnabled bool
}

// TunnelVIF IPsec tunnel VIF.
type TunnelVIF struct {
	tif       *TunnelIF
	vif       *VIF
	vrfIndex  vswitch.VRFIndex
	lock      sync.Mutex
	isEnabled bool
}

// Module module.
type Module struct {
	name      string
	running   bool
	cmodule   *C.struct_module
	direction DirectionType
	th        C.pthread_t
	done      chan int
}

func startTicker() {
	fn := func() {
		ticker = tick.GetTicker()
		ticker.Start(&wg)
	}
	tickerStarted.Do(fn)
}

func stopTicker() {
	fn := func() {
		ticker.Stop()
	}
	tickerStoped.Do(fn)
}

func moduleNoLock(direction DirectionType) (*Module, error) {
	// No lock.
	// Assume module locked.

	// already exists.
	if m, ok := modules[direction]; ok {
		return m, nil
	}

	// create Module.
	m := &Module{
		name:      fmt.Sprintf("%v-module", direction),
		running:   false,
		direction: direction,
		done:      make(chan int),
	}

	// name of ipsec module in C plane.
	mn := C.CString(ModuleName)
	defer C.free(unsafe.Pointer(mn))
	m.cmodule = C.module_create(mn)
	if m.cmodule == nil {
		return nil, fmt.Errorf("%v: Can't create cmodule", m)
	}

	params := &C.struct_ipsec_param{}
	params.role = m.direction.Role()

	if ret := C.ipsec_configure(m.cmodule,
		unsafe.Pointer(params)); ret != C.LAGOPUS_RESULT_OK {
		log.Fatalf("%v: Fail ipsec_configure(), %v.", m, ret)
	}

	modules[direction] = m

	return m, nil
}

func module(direction DirectionType) (*Module, error) {
	lock.Lock()
	defer lock.Unlock()

	return moduleNoLock(direction)
}

func newTunnelIF(base *vswitch.BaseInstance, priv interface{},
	config *tunnel.ModuleConfig) (tunnel.ConcreteIF, error) {
	lock.Lock()
	defer lock.Unlock()

	for _, direction := range directions {
		if _, err := moduleNoLock(direction); err != nil {
			return nil, err
		}
	}

	tif := &TunnelIF{
		name: base.Name(),
	}

	return tif, nil
}

func enable(i *TunnelIF, v *TunnelVIF) error {
	lock.Lock()
	defer lock.Unlock()

	if i == nil || v == nil {
		log.Printf("%v: TunnelIF or TunnelVIF is nil", i)
		// ignore.
		return nil
	}

	if i.isEnabled && v.isEnabled {
		log.Printf("%v: enable.", i)

		iiring := i.tvif.vif.Inbound()
		ioring := i.tvif.vif.Outbound()
		oring := i.tvif.vif.Output()
		// TODO: get input.

		if iiring == nil || ioring == nil || oring == nil {
			return fmt.Errorf("%v: input_inbound(%p) or input_outbound(%p) or output(%p) is nil",
				i, iiring, ioring, oring)
		}
		if accessor.SetRingFn != nil {
			rings := NewRings(iiring, ioring, oring)
			accessor.SetRingFn(i.tvif.vif.Index(), rings)
		} else {
			return fmt.Errorf("%v: setRingFn is nil", i)
		}

		for _, direction := range directions {
			modules[direction].start()
		}
	}
	return nil
}

func disable(i *TunnelIF, v *TunnelVIF) error {
	lock.Lock()
	defer lock.Unlock()

	if i == nil || v == nil {
		return fmt.Errorf("%v: TunnelIF or TunnelVIF is nil", i)
	}

	if (!i.isEnabled && v.isEnabled) || (i.isEnabled && !v.isEnabled) {
		log.Printf("%v: disable.", i)

		if accessor.UnsetRingFn != nil {
			accessor.UnsetRingFn(i.tvif.vif.Index())
		} else {
			return fmt.Errorf("%v: unsetRingFn is nil", i)
		}
	}
	return nil
}

// RegisterAccessor Set set/unset ring func.
func RegisterAccessor(a *IfaceAccessor) {
	lock.Lock()
	defer lock.Unlock()

	accessor = *a
}

// TunnelIF.

func (i *TunnelIF) disable() {
	// No lock.
	// Assume module locked.
	log.Printf("%v: Disable.", i)

	if !i.isEnabled {
		return
	}

	// Disable even if an error occurs.
	i.isEnabled = false
	if err := disable(i, i.tvif); err != nil {
		log.Printf("Error: %v", err)
		return
	}
}

// Free Free for TunnelIF.
func (i *TunnelIF) Free() {
	i.lock.Lock()
	defer i.lock.Unlock()

	i.disable()
	if i.tvif != nil {
		i.tvif.tif = nil
	}
	i.tvif = nil
}

// Enable Enable for TunnelIF.
func (i *TunnelIF) Enable() error {
	i.lock.Lock()
	defer i.lock.Unlock()

	log.Printf("%v: Enable.", i)

	if i.isEnabled {
		return nil
	}

	// Enable even if an error occurs.
	i.isEnabled = true
	err := enable(i, i.tvif)

	return err
}

// Disable Disable for TunnelIF.
func (i *TunnelIF) Disable() {
	i.lock.Lock()
	defer i.lock.Unlock()

	i.disable()
}

// NewVIF Create Tunnel VIF.
func (i *TunnelIF) NewVIF(vif *vswitch.VIF) (vswitch.VIFInstance, error) {
	i.lock.Lock()
	defer i.lock.Unlock()

	if vif == nil {
		return nil, fmt.Errorf("%v: Invalid args", i)
	}

	if vif.Index() >= MaxVIFEntries {
		return nil, fmt.Errorf("%v: Out of ragne vif index: %v", i, vif.Index())
	}

	if i.tvif != nil {
		return nil, fmt.Errorf("%v: already exists(%v)", i, vif.Name())
	}

	tvif := &TunnelVIF{
		tif: i,
		vif: &VIF{
			VIF: vif,
		},
	}
	i.tvif = tvif

	if t := tvif.vif.Tunnel(); t != nil {
		tvif.HopLimitUpdated(t.HopLimit())
		tvif.TOSUpdated(t.TOS())
	} else {
		return nil, fmt.Errorf("%v: vif.tunnel is nil", i)
	}

	return tvif, nil
}

// String Get name.
func (i *TunnelIF) String() string {
	return i.name
}

// Tunnel VIF.

func (v *TunnelVIF) disable() {
	// No lock.
	// Assume module locked.

	if !v.isEnabled {
		return
	}

	// Disable even if an error occurs.
	v.isEnabled = false
	if err := disable(v.tif, v); err != nil {
		log.Printf("Error: %v", err)
		return
	}
}

// Free Free for Tunnel VIF.
func (v *TunnelVIF) Free() {
	v.lock.Lock()
	defer v.lock.Unlock()

	v.disable()
	if v.tif != nil {
		v.tif.tvif = nil
	}
	v.tif = nil
}

// Enable Enable for Tunnel VIF.
func (v *TunnelVIF) Enable() error {
	v.lock.Lock()
	defer v.lock.Unlock()

	if v.isEnabled {
		return nil
	}

	// Enable even if an error occurs.
	v.isEnabled = true
	err := enable(v.tif, v)

	return err
}

// Disable Disable for Tunnel VIF.
func (v *TunnelVIF) Disable() {
	v.lock.Lock()
	defer v.lock.Unlock()

	v.disable()
}

// SetVRF Set VRF.
func (v *TunnelVIF) SetVRF(vrf *vswitch.VRF) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if vrf.Index() >= MaxVRFEntries {
		log.Fatalf("%v: Out of ragne vrf index: %v", v, vrf.Index())
	}

	v.vrfIndex = vrf.Index()
	if accessor.SetVRFIndexFn != nil {
		if v.tif != nil {
			accessor.SetVRFIndexFn(v.vif.Index(), v.vrfIndex)
		} else {
			log.Printf("%v: tunnel IF is nil", v)
		}
	} else {
		log.Printf("%v: setVRFIndexFn is nil", v)
	}
}

// HopLimitUpdated Update TTL.
func (v *TunnelVIF) HopLimitUpdated(ttl uint8) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if accessor.SetTTLFn != nil {
		if v.tif != nil {
			accessor.SetTTLFn(v.vif.Index(), ttl)
		} else {
			log.Printf("%v: tunnel IF is nil", v)
		}
	} else {
		log.Printf("%v: setTTLFn is nil", v)
	}
}

// TOSUpdated Update TOS.
func (v *TunnelVIF) TOSUpdated(tos int8) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if accessor.SetTOSFn != nil {
		if v.tif != nil {
			accessor.SetTOSFn(v.vif.Index(), tos)
		} else {
			log.Printf("%v: tunnel IF is nil", v)
		}
	} else {
		log.Printf("%v: setTOSFn is nil", v)
	}
}

// AddressTypeUpdated Update address type.
func (v *TunnelVIF) AddressTypeUpdated(family vswitch.AddressFamily) {
	// do nothing.
}

// EncapsMethodUpdated Update encaps method.
func (v *TunnelVIF) EncapsMethodUpdated(method vswitch.EncapsMethod) {
	// do nothing.
}

// LocalAddressUpdated Update local IP addr.
func (v *TunnelVIF) LocalAddressUpdated(ip net.IP) {
	// do nothing.
}

// RemoteAddressUpdated Update remote IP addr.
func (v *TunnelVIF) RemoteAddressUpdated(ip net.IP) {
	// do nothing.
}

// SecurityUpdated Update security.
func (v *TunnelVIF) SecurityUpdated(security vswitch.Security) {
	// do nothing.
}

// module.

//String Get name of module.
func (m *Module) String() string {
	return m.name
}

// Start.
func (m *Module) start() bool {
	// No lock.
	// Assume module locked.
	if !m.running {
		log.Printf("%v: Start.", m)
		m.running = true

		if C.pthread_create(&m.th, nil, (*[0]byte)(C.ipsec_mainloop),
			unsafe.Pointer(m.cmodule)) != 0 {
			log.Fatalf("%v: Fail pthread_create()", m)
		}

		startTicker()
	}

	return true
}

// Stop.
func (m *Module) stop() {
	// No lock.
	// Assume module locked.
	log.Printf("%v: Stop.", m)
	C.ipsec_stop(m.cmodule)
	stopTicker()
}

// Wait.
func (m *Module) wait() {
	// No lock.
	// Assume module locked.
	log.Printf("%v: Wait.", m)
	C.pthread_join(m.th, nil)
	wg.Wait()
	C.ipsec_unconfigure(m.cmodule)
	C.module_destroy(m.cmodule)
	m.running = false
}

// VIF Wrap vswitch.VIF
type VIF struct {
	*vswitch.VIF
}
