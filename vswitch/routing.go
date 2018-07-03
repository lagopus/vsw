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

package vswitch

import (
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/lagopus/vsw/utils/notifier"
)

type RouteScope uint8

const (
	RouteScopeUniverse RouteScope = syscall.RT_SCOPE_UNIVERSE
	RouteScopeSite     RouteScope = syscall.RT_SCOPE_SITE
	RouteScopeLink     RouteScope = syscall.RT_SCOPE_LINK
	RouteScopeHost     RouteScope = syscall.RT_SCOPE_HOST
	RouteScopeNowhere  RouteScope = syscall.RT_SCOPE_NOWHERE
)

var routeScopeStrings = map[RouteScope]string{
	RouteScopeUniverse: "Universe",
	RouteScopeSite:     "Site",
	RouteScopeLink:     "Link",
	RouteScopeHost:     "Host",
	RouteScopeNowhere:  "No Where",
}

func (rs RouteScope) String() string { return routeScopeStrings[rs] }

type Route struct {
	Dst      *net.IPNet
	Src      net.IP
	Gw       net.IP
	Metrics  int
	VIFIndex VIFIndex
	Scope    RouteScope
}

func (r Route) String() string {
	return fmt.Sprintf("Dst:%v Src:%v Gw:%v Metrics:%d Scope:%v VIF:%d",
		r.Dst, r.Src, r.Gw, r.Metrics, r.Scope, r.VIFIndex)
}

// RoutingTable
type RoutingTable struct {
	container interface{}
	entries   map[string]Route
	mutex     sync.RWMutex
}

func newRoutingTable(container interface{}) *RoutingTable {
	return &RoutingTable{
		container: container,
		entries:   make(map[string]Route),
	}
}

func (rt *RoutingTable) AddEntry(entry Route) bool {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	rt.entries[entry.String()] = entry

	noti.Notify(notifier.Add, rt.container, entry)

	return true
}

func (rt *RoutingTable) DeleteEntry(entry Route) bool {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	key := entry.String()
	if _, exists := rt.entries[key]; !exists {
		return false
	}
	delete(rt.entries, key)

	noti.Notify(notifier.Delete, rt.container, entry)

	return true
}

func (rt *RoutingTable) ListEntries() []Route {
	rt.mutex.RLock()
	defer rt.mutex.RUnlock()

	list := make([]Route, len(rt.entries))
	i := 0
	for _, e := range rt.entries {
		list[i] = e
		i++
	}

	return list
}
