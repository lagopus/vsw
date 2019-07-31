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

package ipsec

// #include <pthread.h>
// #include "ipsec.h"
// #include "module.h"
import "C"

import (
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/lagopus/vsw/modules/tunnel/log"
	"github.com/lagopus/vsw/modules/tunnel/tick"
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
	accessor      Accessor
	modules       = map[DirectionType]*Module{}
	directions    = []DirectionType{
		DirectionTypeOut,
		DirectionTypeIn,
	}
)

// TunnelIF IPsec tunnel interface.
type TunnelIF struct {
	name      string
	tvif      *TunnelVIF
	counter   *C.struct_vsw_counter
	lock      sync.Mutex
	isEnabled bool
}

// TunnelVIF IPsec tunnel VIF.
type TunnelVIF struct {
	tif       *TunnelIF
	vif       *VIF
	vrf       *vswitch.VRF
	counter   *C.struct_vsw_counter
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

func init() {
	ticker = tick.NewTicker()
}

func startTicker() {
	fn := func() {
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

func moduleNoLock(direction DirectionType, params CParams) (*Module, error) {
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

	params.SetRole(m.direction)
	if ret := C.ipsec_configure(m.cmodule,
		unsafe.Pointer(&params)); ret != C.LAGOPUS_RESULT_OK {
		return nil, fmt.Errorf("%v: Fail ipsec_configure(), %s", m,
			C.GoString(C.lagopus_error_get_string(ret)))
	}

	modules[direction] = m

	return m, nil
}

func module(direction DirectionType) (*Module, error) {
	lock.Lock()
	defer lock.Unlock()

	if m, ok := modules[direction]; ok {
		return m, nil
	}
	return nil, fmt.Errorf("No found module: %v", direction)
}

// NewTunnelIF Create Tunnel IF.
func NewTunnelIF(name string, counter *vswitch.Counter,
	params CParams) (*TunnelIF, error) {
	lock.Lock()
	defer lock.Unlock()

	for _, direction := range directions {
		if _, err := moduleNoLock(direction, params); err != nil {
			return nil, err
		}
	}

	tif := &TunnelIF{
		name:    name,
		counter: (*C.struct_vsw_counter)(unsafe.Pointer(counter)),
	}

	return tif, nil
}

func enable(i *TunnelIF, v *TunnelVIF) error {
	lock.Lock()
	defer lock.Unlock()

	if i == nil || v == nil {
		log.Logger.Err("%v: TunnelIF or TunnelVIF is nil", i)
		// ignore.
		return nil
	}

	if i.isEnabled && v.isEnabled {
		log.Logger.Info("%v: enable.", i)

		inputInbound := i.tvif.vif.Inbound()
		inputOutbound := i.tvif.vif.Outbound()
		outputInbound := i.tvif.vif.Output()
		outputOutbound := i.tvif.vif.Rules().Output(vswitch.MatchIPv4Dst)

		if inputInbound == nil || inputOutbound == nil ||
			outputInbound == nil || outputOutbound == nil {
			return fmt.Errorf("%v: input_inbound(%p) or input_outbound(%p) or "+
				"output_Inbound(%p) is nil or output_outbound(%p) is nil",
				i, inputInbound, inputOutbound, outputInbound, outputOutbound)
		}
		rings := NewRings(inputInbound, inputOutbound, outputInbound, outputOutbound)
		accessor.SetRingFn(i.tvif.vif.Index(), rings)

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
		log.Logger.Info("%v: disable.", i)

		accessor.UnsetRingFn(i.tvif.vif.Index())
	}
	return nil
}

// RegisterAccessor Set set/unset ring func.
func RegisterAccessor(a *Accessor) {
	lock.Lock()
	defer lock.Unlock()

	accessor = *a
}

// GetTicker Get Ticker.
func GetTicker() *tick.Ticker {
	return ticker
}

//
// Tunnel IF.
//

func (i *TunnelIF) disable() {
	// No lock.
	// Assume module locked.
	log.Logger.Info("%v: Disable.", i)

	if !i.isEnabled {
		return
	}

	// Disable even if an error occurs.
	i.isEnabled = false
	if err := disable(i, i.tvif); err != nil {
		log.Logger.Err("%v", err)
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

	log.Logger.Info("%v: Enable.", i)

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

// UpdateCounter Update stats.
func (i *TunnelIF) UpdateCounter() {
	i.lock.Lock()
	defer i.lock.Unlock()

	log.Logger.Info("%v: UpdateCounter.", i)

	if i.tvif == nil {
		log.Logger.Err("%v: tvif is nil", i)
		return
	}

	i.tvif.UpdateCounter()
}

// ResetCounter Reset stats.
func (i *TunnelIF) ResetCounter() {
	i.lock.Lock()
	defer i.lock.Unlock()

	log.Logger.Info("%v: ResetCounter.", i)

	if i.tvif == nil {
		log.Logger.Err("%v: tvif is nil", i)
		return
	}

	i.tvif.ResetCounter()
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
		tif:     i,
		counter: (*C.struct_vsw_counter)(unsafe.Pointer(vif.Counter())),
		vif: &VIF{
			VIF: vif,
		},
	}
	i.tvif = tvif

	if t := tvif.vif.Tunnel(); t != nil {
		tvif.HopLimitUpdated(t.HopLimit())
		tvif.L3TOSUpdated(t.TOS())
	} else {
		return nil, fmt.Errorf("%v: vif.tunnel is nil", i)
	}

	return tvif, nil
}

// String Get name.
func (i *TunnelIF) String() string {
	return i.name
}

//
// Tunnel VIF.
//

func (v *TunnelVIF) disable() {
	// No lock.
	// Assume module locked.

	if !v.isEnabled {
		return
	}

	// Disable even if an error occurs.
	v.isEnabled = false
	if err := disable(v.tif, v); err != nil {
		log.Logger.Err("%v", err)
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

	if vrf == nil {
		// Unset VRF index.
		if v.vrf != nil {
			if err := accessor.UnsetVRFFn(v.vif.Index(), v.vrf); err != nil {
				log.Logger.Err("%v: Failed UnsetVRFFn(): %v", v, err)
				return
			}
			v.vrf = nil
		}
	} else {
		// Set VRF index.
		index := vrf.Index()
		if index >= MaxVRFEntries {
			log.Logger.Fatalf("%v: Out of ragne vrf index: %v", v, vrf.Index())
		}

		v.vrf = vrf
		if v.tif != nil {
			if err := accessor.SetVRFFn(v.vif.Index(), v.vrf); err != nil {
				log.Logger.Err("%v: Failed SetVRFFn(): %v", v, err)
				return
			}
		} else {
			log.Logger.Err("%v: tunnel IF is nil", v)
		}
	}
}

// HopLimitUpdated Update TTL.
func (v *TunnelVIF) HopLimitUpdated(ttl uint8) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if v.tif != nil {
		accessor.SetTTLFn(v.vif.Index(), ttl)
	} else {
		log.Logger.Err("%v: tunnel IF is nil", v)
	}
}

// L3TOSUpdated Update TOS.
func (v *TunnelVIF) L3TOSUpdated(tos int8) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if v.tif != nil {
		accessor.SetTOSFn(v.vif.Index(), tos)
	} else {
		log.Logger.Err("%v: tunnel IF is nil", v)
	}
}

// UpdateCounter Update stats.
func (v *TunnelVIF) UpdateCounter() {
	v.lock.Lock()
	defer v.lock.Unlock()

	if v.tif != nil {
		statsIn := accessor.StatsFn(v.vif.Index(), DirectionTypeIn)
		statsOut := accessor.StatsFn(v.vif.Index(), DirectionTypeOut)
		// NOTE: outbound stats doesn't have unknown_protos.
		//       So add unknown_protos to errors.
		statsOut.errors += C.uint64_t(statsOut.unknown_protos)
		sIn := (*C.struct_tunnel_stats)(unsafe.Pointer(statsIn))
		sOut := (*C.struct_tunnel_stats)(unsafe.Pointer(statsOut))
		C.tunnel_update_counter(v.tif.counter, sIn, sOut)
		C.tunnel_update_counter(v.counter, sIn, sOut)
	} else {
		log.Logger.Err("%v: tunnel IF is nil", v)
	}
}

// ResetCounter Reset stats.
func (v *TunnelVIF) ResetCounter() {
	v.lock.Lock()
	defer v.lock.Unlock()

	if v.tif != nil {
		accessor.ResetStatsFn(v.vif.Index(), DirectionTypeIn)
		accessor.ResetStatsFn(v.vif.Index(), DirectionTypeOut)
		C.tunnel_reset_counter(v.tif.counter, nil, nil)
		C.tunnel_reset_counter(v.counter, nil, nil)
	}
}

// AddressTypeUpdated Update address type.
func (v *TunnelVIF) AddressTypeUpdated(family vswitch.AddressFamily) {
	// do nothing.
}

// LocalAddressUpdated Update local IP addr.
func (v *TunnelVIF) LocalAddressUpdated(ip net.IP) {
	// do nothing.
}

// RemoteAddressesUpdated Update remote IP addr.
func (v *TunnelVIF) RemoteAddressesUpdated(ip []net.IP) {
	// do nothing.
}

// SecurityUpdated Update security.
func (v *TunnelVIF) SecurityUpdated(security vswitch.Security) {
	// do nothing.
}

// VRFUpdated Update VRF.
func (v *TunnelVIF) VRFUpdated(vrf *vswitch.VRF) {
	// do nothing.
}

//
// module.
//

//String Get name of module.
func (m *Module) String() string {
	return m.name
}

// Start.
func (m *Module) start() bool {
	// No lock.
	// Assume module locked.
	if !m.running {
		log.Logger.Info("%v: Start.", m)
		m.running = true

		if C.pthread_create(&m.th, nil, (*[0]byte)(C.ipsec_mainloop),
			unsafe.Pointer(m.cmodule)) != 0 {
			log.Logger.Fatalf("%v: Fail pthread_create()", m)
		}

		startTicker()
	}

	return true
}

// Stop.
func (m *Module) stop() {
	// No lock.
	// Assume module locked.
	log.Logger.Info("%v: Stop.", m)
	C.ipsec_stop(m.cmodule)
	stopTicker()
}

// Wait.
func (m *Module) wait() {
	// No lock.
	// Assume module locked.
	log.Logger.Info("%v: Wait.", m)
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
