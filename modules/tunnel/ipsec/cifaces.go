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

// #include "ipsec.h"
// #include "ifaces.h"
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/vswitch"
)

// Default.
const (
	// DefaultTTL
	DefaultTTL uint8 = C.DEFAULT_TTL
	// DefaultTOS
	DefaultTOS int8 = C.DEFAULT_TOS
)

// SetVRFIndexFunc Func of setVRFIndex.
type SetVRFIndexFunc func(vswitch.VIFIndex, vswitch.VRFIndex)

// SetRingFunc Func of setRing.
type SetRingFunc func(vswitch.VIFIndex, *Rings)

// UnsetRingFunc Func of unsetRing.
type UnsetRingFunc func(vswitch.VIFIndex)

// SetTTLFunc Func of setTTL.
type SetTTLFunc func(vswitch.VIFIndex, uint8)

// SetTOSFunc Func of setTOS.
type SetTOSFunc func(vswitch.VIFIndex, int8)

// IfaceAccessor Accessor of Iface.
type IfaceAccessor struct {
	SetVRFIndexFn SetVRFIndexFunc
	SetRingFn     SetRingFunc
	UnsetRingFn   UnsetRingFunc
	SetTTLFn      SetTTLFunc
	SetTOSFn      SetTOSFunc
}

// CIface struct iface.
type CIface C.struct_iface

// CIfaceValue Value of iface.
type CIfaceValue struct {
	VRFIndex vswitch.VRFIndex
	VIFIndex vswitch.VIFIndex
	Input    *dpdk.Ring
	Output   *dpdk.Ring
	TTL      uint8
	TOS      int8
}

// Iface CIfaces interface.
type Iface interface {
	PushIfaces(direction DirectionType, array []CIface) error
	AllocArray() ([]CIface, error)
	FreeArray(array []CIface)
	SetCIface(ciface *CIface, value *CIfaceValue)
	String() string
}

// BaseCIfaces

// BaseCIfaces Base Iface.
type BaseCIfaces struct {
	cifaces *C.struct_ifaces
}

func (i *BaseCIfaces) cModule(direction DirectionType) *Module {
	if m, err := module(direction); err == nil {
		return m
	}

	return nil
}

// Get cifaces.
func (i *BaseCIfaces) setModuleCIfaces(direction DirectionType) error {
	if i.cifaces == nil {
		if m := i.cModule(direction); m != nil {
			if cifaces := C.ipsec_get_ifaces(m.cmodule); cifaces != nil {
				i.cifaces = cifaces
				return nil
			}
			return fmt.Errorf("Not found iface")
		}
		return fmt.Errorf("Not found cmodule")
	}

	return nil
}

// PushIfaces Push to C plane."
func (i *BaseCIfaces) PushIfaces(direction DirectionType, array []CIface) error {
	if len(array) == 0 {
		return nil
	} else if len(array) > MaxVIFEntries {
		return fmt.Errorf("Out of range array")
	}

	if err := i.setModuleCIfaces(direction); err != nil {
		return err
	}

	p := (*C.struct_iface)(unsafe.Pointer(&array[0]))
	if ret := C.ifaces_push_config(i.cifaces, p, C.size_t(len(array))); ret != C.LAGOPUS_RESULT_OK {
		return fmt.Errorf("%v, Fail iface_set_queues(), %v", i, ret)
	}

	return nil
}

// AllocArray Alloc array of struct iface.
func (i *BaseCIfaces) AllocArray() ([]CIface, error) {
	if array := C.ifaces_alloc_array(C.size_t(MaxVIFEntries)); array != nil {
		return (*[1 << 30]CIface)(unsafe.Pointer(array))[:MaxVIFEntries:MaxVIFEntries], nil
	}
	return nil, fmt.Errorf("%v: Can't alloc array of ifaces", i)
}

// FreeArray Free array of struct iface.
func (i *BaseCIfaces) FreeArray(array []CIface) {
	C.ifaces_free_array((*C.struct_iface)((unsafe.Pointer(&array[0]))))
}

// SetCIface Set struct iface.
func (i *BaseCIfaces) SetCIface(ciface *CIface, value *CIfaceValue) {
	a := (*C.struct_iface)((unsafe.Pointer(ciface)))
	ci := C.struct_iface{
		vrf_index: C.vrfindex_t(value.VRFIndex),
		vif_index: C.vifindex_t(value.VIFIndex),
		ttl:       C.uint8_t(value.TTL),
		tos:       C.int8_t(value.TOS),
	}
	if value.Input != nil {
		ci.input = (*C.struct_rte_ring)(unsafe.Pointer(value.Input))
	}
	if value.Output != nil {
		ci.output = (*C.struct_rte_ring)(unsafe.Pointer(value.Output))
	}

	*a = ci
}

// CIfaces

// CIfaces CIfaces.
type CIfaces struct {
	BaseCIfaces
}

// NewCIfaces Create CIfaces.
func NewCIfaces() *CIfaces {
	return &CIfaces{}
}

// String String.
func (i *CIfaces) String() string {
	return "CIfaces"
}

// Rings.

// Rings Input/Output rings.
type Rings struct {
	inputInbound  *dpdk.Ring
	inputOutbound *dpdk.Ring
	output        *dpdk.Ring
}

// NewRings Create Rings.
func NewRings(inputInbound *dpdk.Ring, inputOutbound *dpdk.Ring,
	output *dpdk.Ring) *Rings {
	return &Rings{
		inputInbound:  inputInbound,
		inputOutbound: inputOutbound,
		output:        output,
	}
}

// Input Get input ring.
func (rs *Rings) Input(direction DirectionType) *dpdk.Ring {
	if direction == DirectionTypeIn {
		return rs.inputInbound
	}
	return rs.inputOutbound
}

// Output Get output ring.
func (rs *Rings) Output() *dpdk.Ring {
	return rs.output
}

// String String.
func (rs *Rings) String() string {
	return fmt.Sprintf("inputInbound: %p, inputOutbound, %p, output: %p",
		rs.inputInbound, rs.inputOutbound, rs.output)
}
