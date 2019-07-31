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

import (
	"fmt"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/vswitch"
)

// SetVRFFunc Func of setVRF.
type SetVRFFunc func(vswitch.VIFIndex, *vswitch.VRF) error

// UnsetVRFFunc Func of unsetVRF.
type UnsetVRFFunc func(vswitch.VIFIndex, *vswitch.VRF) error

// SetRingFunc Func of setRing.
type SetRingFunc func(vswitch.VIFIndex, *Rings)

// UnsetRingFunc Func of unsetRing.
type UnsetRingFunc func(vswitch.VIFIndex)

// SetTTLFunc Func of setTTL.
type SetTTLFunc func(vswitch.VIFIndex, uint8)

// SetTOSFunc Func of setTOS.
type SetTOSFunc func(vswitch.VIFIndex, int8)

// StatsFunc Func of stats.
type StatsFunc func(vswitch.VIFIndex, DirectionType) *CIfaceStats

// ResetStatsFunc Func of ResetStats.
type ResetStatsFunc func(vswitch.VIFIndex, DirectionType)

// Accessor Accessor of agent.
type Accessor struct {
	SetVRFFn     SetVRFFunc
	UnsetVRFFn   UnsetVRFFunc
	SetRingFn    SetRingFunc
	UnsetRingFn  UnsetRingFunc
	SetTTLFn     SetTTLFunc
	SetTOSFn     SetTOSFunc
	StatsFn      StatsFunc
	ResetStatsFn ResetStatsFunc
}

// Rings.

// Rings Input/Output rings.
type Rings struct {
	inputInbound   *dpdk.Ring
	inputOutbound  *dpdk.Ring
	outputInbound  *dpdk.Ring
	outputOutbound *dpdk.Ring
}

// NewRings Create Rings.
func NewRings(inputInbound *dpdk.Ring, inputOutbound *dpdk.Ring,
	outputInbound *dpdk.Ring, outputOutbound *dpdk.Ring) *Rings {
	return &Rings{
		inputInbound:   inputInbound,
		inputOutbound:  inputOutbound,
		outputInbound:  outputInbound,
		outputOutbound: outputOutbound,
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
func (rs *Rings) Output(direction DirectionType) *dpdk.Ring {
	if direction == DirectionTypeIn {
		return rs.outputInbound
	}
	return rs.outputOutbound
}

// String String.
func (rs *Rings) String() string {
	return fmt.Sprintf(
		"inputInbound: %p, inputOutbound, %p, outputInbound: %p outputOutbound: %p",
		rs.inputInbound, rs.inputOutbound, rs.outputInbound, rs.outputOutbound)
}
