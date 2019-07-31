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

package vswitch

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"syscall"
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

type RouteType uint8

type Nexthop struct {
	Dev    OutputDevice
	Weight int
	Gw     net.IP
}

func (n *Nexthop) String() string {
	return fmt.Sprintf("{Dev:%v Weight:%d Gw:%v}", n.Dev, n.Weight, n.Gw)
}

func (n *Nexthop) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"dev":    n.Dev,
		"weight": n.Weight,
		"gw":     n.Gw,
	}
	return json.Marshal(m)
}

// Route represents a routing entry.
type Route struct {
	Dst      *net.IPNet   // Destination
	Src      net.IP       // Source
	Gw       net.IP       // Gateway. Valid for a single nexthop only.
	Nexthops []*Nexthop   // An array of Nexthops. Length is zero for single nexthop.
	Metrics  int          // Metric
	Dev      OutputDevice // OutputDevice. Valid for a single nexthop only.
	Scope    RouteScope   // Scope
	Type     RouteType    // Type
}

func (r Route) String() string {
	if len(r.Nexthops) == 0 {
		return fmt.Sprintf("{Dst:%v Src:%v Gw:%v Metrics:%d Scope:%v Dev:%v}",
			r.Dst, r.Src, r.Gw, r.Metrics, r.Scope, r.Dev)
	}
	return fmt.Sprintf("{Dst:%v Src:%v Gw:%v Metrics:%d Scope:%v}",
		r.Dst, r.Src, r.Nexthops, r.Metrics, r.Scope)
}

func (r *Route) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"destination": &IPAddr{r.Dst.IP, r.Dst.Mask},
		"source":      r.Src,
		"metric":      r.Metrics,
		"scope":       r.Scope,
		"type":        r.Type,
	}

	if len(r.Nexthops) == 0 {
		m["gw"] = r.Gw
		m["dev"] = r.Dev
	} else {
		m["nexthops"] = r.Nexthops
	}

	return json.Marshal(m)
}

func (r *Route) hash() string {
	return fmt.Sprintf("%v-%d", r.Dst, r.Metrics)
}

func (r *Route) normalize() {
	if len(r.Nexthops) > 1 {
		sort.Slice(r.Nexthops, func(i, j int) bool {
			return r.Nexthops[i].Weight > r.Nexthops[j].Weight
		})
	}
}

type routingTableObserver interface {
	routeEntryAdded(entry Route)
	routeEntryDeleted(entry Route)
}

// RoutingTable
type RoutingTable struct {
	observer routingTableObserver
	entries  map[string]Route
	mutex    sync.RWMutex
}

func newRoutingTable(observer routingTableObserver) *RoutingTable {
	return &RoutingTable{
		observer: observer,
		entries:  make(map[string]Route),
	}
}

func (rt *RoutingTable) AddEntry(entry Route) error {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	key := entry.hash()
	if _, exists := rt.entries[key]; exists {
		return errors.New("Duplicated routing entry.")
	}

	entry.normalize()

	rt.entries[key] = entry

	rt.observer.routeEntryAdded(entry)

	return nil
}

func (rt *RoutingTable) DeleteEntry(entry Route) error {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	key := entry.hash()

	if _, exists := rt.entries[key]; !exists {
		return errors.New("No routing entry found.")
	}
	delete(rt.entries, key)

	rt.observer.routeEntryDeleted(entry)

	return nil
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
