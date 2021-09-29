//
// Copyright 2019 Nippon Telegraph and Telephone Corporation.
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
package router

/*

#include "router.h"
#include "router_common.h"

*/
import "C"

import (
	"errors"
	"fmt"

	"github.com/lagopus/vsw/agents/debugsh"
	"github.com/lagopus/vsw/vswitch"
)

type routerServiceStat struct {
	Running bool `json:"running"`
	RefCnt  uint `json:"reference_count"`
}

func routerList(rs *routerService) []string {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	var routers []string
	for _, r := range rs.routers {
		routers = append(routers, r.base.Name())
	}

	return routers
}

func routerDebugStat(rs *routerService, args ...string) (interface{}, error) {
	return &routerServiceStat{rs.running, rs.refcnt}, nil
}

func routerDebugList(rs *routerService, args ...string) (interface{}, error) {
	return routerList(rs), nil
}

type routerInfo struct {
	Name         string            `json:"name"`
	VRFIndex     vswitch.VRFIndex  `json:"vrf-index"`
	ControlCount uint              `json:"control_count"`
	ControlError uint              `json:"control_error"`
	RouterRing   []*routerRingInfo `json:"output_ring"`
}

type routerRingInfo struct {
	Name    string `json:"ring_name"`
	RefCnt  uint   `json:"ref_cnt"`
	Count   uint   `json:"current_count"`
	Sent    uint64 `json:"sent"`
	Dropped uint64 `json:"dropped"`
}

type routerNeighborCacheInfo struct {
	Address   string `json:"address"`
	HWAddress string `json:"hw-address"`
	Interface string `json:"interface"`
	Valid     bool   `json:"valid"`
	Used      bool   `json:"used"`
}

func routerShowStat(rs *routerService, args ...string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("Usage: show 'router_name' (%v)", routerList(rs))
	}

	ri := rs.getRouterInstance(args[0])
	if ri == nil {
		return nil, errors.New("No such router: " + args[0])
	}

	// Returns basic router status info
	rinfo := &routerInfo{ri.base.Name(), ri.vrfidx, ri.ctrls, ri.ctrlsErr, nil}

	for i := 0; i < int(ri.param.rr_count); i++ {
		rr := ri.param.rrp[i]
		rri := &routerRingInfo{
			Name:    C.GoString(&rr.ring.name[0]),
			RefCnt:  uint(rr.rc),
			Count:   uint(rr.count),
			Sent:    uint64(rr.sent),
			Dropped: uint64(rr.dropped),
		}
		rinfo.RouterRing = append(rinfo.RouterRing, rri)
	}

	return rinfo, nil
}

func routerShowNeighbor(rs *routerService, args ...string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("Usage: neigh 'router_name' (%v)", routerList(rs))
	}

	ri := rs.getRouterInstance(args[0])
	if ri == nil {
		return nil, errors.New("No such router: " + args[0])
	}

	// Returns neighbor cache
	var ncinfo []*routerNeighborCacheInfo
	ri.mutex.Lock()
	for vif, nc := range ri.neighborCaches {
		iface := vif.Name()
		for _, entry := range nc {
			if !entry.valid && !entry.used {
				continue
			}

			addr := fmt.Sprintf("%d.%d.%d.%d",
				(entry.addr>>24)&0xff, (entry.addr>>16)&0xff,
				(entry.addr>>8)&0xff, entry.addr&0xff)

			hwaddr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				entry.mac_addr.addr_bytes[0], entry.mac_addr.addr_bytes[1],
				entry.mac_addr.addr_bytes[2], entry.mac_addr.addr_bytes[3],
				entry.mac_addr.addr_bytes[4], entry.mac_addr.addr_bytes[5])

			info := &routerNeighborCacheInfo{
				Address:   addr,
				HWAddress: hwaddr,
				Interface: iface,
				Used:      bool(entry.used),
				Valid:     bool(entry.valid),
			}

			ncinfo = append(ncinfo, info)
		}
	}
	ri.mutex.Unlock()

	return ncinfo, nil

}

type debugCmdFn func(rs *routerService, args ...string) (interface{}, error)

type routerDebugCmd struct {
	help string
	fn   debugCmdFn
}

var routerDebugHelp []string

var routerCmds = map[string]routerDebugCmd{
	"stat":  {"show status of router service", routerDebugStat},
	"list":  {"list router instances", routerDebugList},
	"show":  {"show status of the specified router", routerShowStat},
	"neigh": {"show neighbor cache of the specified router", routerShowNeighbor},
}

func (rs *routerService) ModuleShow(args ...string) (interface{}, error) {
	if len(args) == 0 {
		return routerDebugHelp, nil
	}

	if cmd, ok := routerCmds[args[0]]; ok {
		return cmd.fn(rs, args[1:]...)
	}

	return nil, errors.New("No such command: " + args[0])
}

func (rs *routerService) registerDebugsh() error {
	for cmd, rc := range routerCmds {
		routerDebugHelp = append(routerDebugHelp, cmd+": "+rc.help)
	}
	return debugsh.RegisterModuleFunc(moduleName, debugsh.ModuleFunc(rs))
}
