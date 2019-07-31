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
)

type routerServiceStat struct {
	Running bool `json:"running"`
	RefCnt  uint `json:"reference_count"`
}

func routerDebugStat(rs *routerService, args ...string) (interface{}, error) {
	return &routerServiceStat{rs.running, rs.refcnt}, nil
}

func routerDebugList(rs *routerService, args ...string) (interface{}, error) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	var routers []string
	for _, r := range rs.routers {
		routers = append(routers, r.base.Name())
	}

	return routers, nil
}

type routerInfo struct {
	Name         string            `json:"name"`
	VRFIndex     uint64            `json:"vrf-index"`
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

func routerShowStat(rs *routerService, args ...string) (interface{}, error) {
	if len(args) == 0 {
		routers, _ := routerDebugList(rs)
		return nil, fmt.Errorf("Usage: show <router> (router(s): %v)", routers)
	}

	for _, r := range rs.routers {
		if r.base.Name() != args[0] {
			continue
		}

		ri := &routerInfo{r.base.Name(), r.vrfidx, r.ctrls, r.ctrlsErr, nil}
		ctx := r.param.ctx

		for i := 0; i < int(ctx.rr_count); i++ {
			rr := ctx.rrp[i]
			rri := &routerRingInfo{
				Name:    C.GoString(&rr.ring.name[0]),
				RefCnt:  uint(rr.rc),
				Count:   uint(rr.count),
				Sent:    uint64(rr.sent),
				Dropped: uint64(rr.dropped),
			}
			ri.RouterRing = append(ri.RouterRing, rri)
		}

		return ri, nil
	}

	return nil, errors.New("No such router: " + args[0])
}

type debugCmdFn func(rs *routerService, args ...string) (interface{}, error)

type routerDebugCmd struct {
	help string
	fn   debugCmdFn
}

var routerDebugHelp []string

var routerCmds = map[string]routerDebugCmd{
	"stat": {"show status of router service", routerDebugStat},
	"list": {"list router instances", routerDebugList},
	"show": {"show status of the specified router", routerShowStat},
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
