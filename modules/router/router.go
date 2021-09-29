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

package router

/*
#cgo CFLAGS: -I${SRCDIR}/../../include -m64 -pthread -O3 -msse4.2
#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all

#include "router_common.h"

*/
import "C"

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"sync"
	"unsafe"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/notifier"
	"github.com/lagopus/vsw/vswitch"
	vlog "github.com/lagopus/vsw/vswitch/log"
)

const (
	moduleName        = "router"
	maxRouterRequests = 1024

	// maxRouterNamesize defines the max namesize of a router instance.
	// The name is used to create DPDK instances, thus should be small
	// enough to meet the limit enforced by DPDK.
	maxRouterNamesize = 12
)

type RouterInstance struct {
	base           *vswitch.BaseInstance
	service        *routerService
	vrfidx         vswitch.VRFIndex
	instance       *vswitch.RuntimeInstance
	param          *C.struct_router_instance
	enabled        bool
	mtu            vswitch.MTU
	neighborCaches map[*vswitch.VIF][]C.struct_neighbor
	arpResolver    *arpResolver
	tap            *dpdk.Ring
	addrsCount     uint
	notifyRule     chan notifier.Notification
	pbr            map[string]int
	ctrls          uint
	ctrlsErr       uint
	mutex          sync.Mutex
}

/*
 * Each informations are managed by VRF.
 */

// Backend Manager
type routerService struct {
	runtime   *vswitch.Runtime
	mutex     sync.Mutex
	terminate chan struct{}
	routers   map[vswitch.VRFIndex]*RouterInstance
	running   bool
	refcnt    uint
	notify    chan notifier.Notification // receive routing informations
}

// internal purpose only
var log = vswitch.Logger
var rs *routerService
var mutex sync.Mutex
var mempool *dpdk.MemPool

// TOML config
type routerConfigSection struct {
	Router routerConfig
}

type routerConfig struct {
	SlaveCore     uint   `toml:"core"`
	RRProcessMode string `toml:"rr_process_mode"`
}

var config routerConfig
var defaultConfig = routerConfig{
	SlaveCore:     2,
	RRProcessMode: recordRouteDisable,
}

const (
	recordRouteDisable = "disable"
	recordRouteIgnore  = "ignore"
	recordRouteEnable  = "enable"
)

var recordRouteProcessMode = map[string]C.rr_process_mode_t{
	recordRouteDisable: C.RECORDROUTE_DISABLE,
	recordRouteIgnore:  C.RECORDROUTE_IGNORE,
	recordRouteEnable:  C.RECORDROUTE_ENABLE,
}

//Match rule parameter
type routerMatchParam struct {
	Ring       *dpdk.Ring
	Index      int
	Priority   int
	SrcAddr    net.IP
	SrcMask    net.IPMask
	DstAddr    net.IP
	DstMask    net.IPMask
	SrcPort    uint16
	SrcPortEnd uint16
	DstPort    uint16
	DstPortEnd uint16
	VNI        uint32
	Proto      vswitch.IPProto
	Interface  vswitch.VIFIndex
}

func (m C.struct_ether_addr) equal(n *C.struct_ether_addr) bool {
	for i := 0; i < C.ETHER_ADDR_LEN; i++ {
		if m.addr_bytes[i] != n.addr_bytes[i] {
			return false
		}
	}
	return true
}

func createStructEtherAddr(m net.HardwareAddr) C.struct_ether_addr {
	r := C.struct_ether_addr{}
	for i := 0; i < C.ETHER_ADDR_LEN; i++ {
		r.addr_bytes[i] = C.uint8_t(m[i])
	}
	return r
}

func (n *C.struct_neighbor_entry) equal(m *C.struct_neighbor_entry) bool {
	return n.ifindex == m.ifindex && n.mac.equal(&m.mac)
}

// --- router module manager --- //

func getRouterService() (*routerService, error) {
	mutex.Lock()
	defer mutex.Unlock()

	if rs != nil {
		rs.refcnt++
		return rs, nil
	}

	param := (*C.struct_router_runtime_param)(C.calloc(1, C.sizeof_struct_router_runtime_param))
	mempool = vswitch.GetDpdkResource().Mempool
	param.pool = (*C.struct_rte_mempool)(unsafe.Pointer(mempool))

	ops := vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.router_runtime_ops))
	log.Printf("call NewRuntime with slave core(%v)\n", config.SlaveCore)
	rt, err := vswitch.NewRuntime(config.SlaveCore, moduleName, ops, unsafe.Pointer(param))
	if err != nil {
		return nil, err
	}
	if err := rt.Enable(); err != nil {
		return nil, err
	}

	rs = &routerService{
		runtime:   rt,
		terminate: make(chan struct{}),
		routers:   make(map[vswitch.VRFIndex]*RouterInstance),
		refcnt:    1,
	}

	// register to debugsh
	rs.registerDebugsh()

	// Start Router Service
	rs.start()

	return rs, nil
}

func (s *routerService) free() {
	mutex.Lock()
	defer mutex.Unlock()

	s.refcnt--
	if s.refcnt == 0 {
		s.stop()
		s.runtime.Terminate()
		rs = nil
	}
}

func (s *routerService) registerRouter(r *RouterInstance) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.routers[r.vrfidx]; exists {
		return fmt.Errorf("RouterID %v already registered", r.vrfidx)
	}

	s.routers[r.vrfidx] = r

	return nil
}

func (s *routerService) unregisterRouter(r *RouterInstance) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.routers, r.vrfidx)

}

func (s *routerService) getRouterInstance(name string) *RouterInstance {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, r := range s.routers {
		if r.base.Name() == name {
			return r
		}
	}

	return nil
}

func (s *routerService) getRouterByIndex(index vswitch.VRFIndex) *RouterInstance {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.routers[index]
}

func (s *routerService) start() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.notify = vswitch.GetNotifier().Listen()
	s.running = true

	// listen to receive routing informations.
	go s.listen()
}

func (s *routerService) stop() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	vswitch.GetNotifier().Close(s.notify)
	s.running = false
}

func (s *routerService) listen() {
	for notify := range s.notify {
		switch target := notify.Target.(type) {
		case *vswitch.VIF:
			// The VIF is not associated with any VRF. Ignore.
			if target.VRF() == nil {
				continue
			}

			// Get the router associated with the VIF.
			router := s.getRouterByIndex(target.VRF().Index())
			if router == nil {
				continue
			}

			switch val := notify.Value.(type) {
			case nil:
				log.Printf("RS:[nil]")

			case vswitch.MTU:
				log.Printf("RS:[MTU] mtu(%v)", val)
				if err := router.procInterfaceMTU(notify.Type, target.Index(), val); err != nil {
					log.Err("RS: procInterfaceMTU failed: %v", err)
				}

			case vswitch.IPAddr:
				log.Printf("RS:[IPAddr] vif: %v, val: %v\n", target, val)
				if err := router.procInterfaceIpEntry(notify.Type, target.Index(), val); err != nil {
					log.Err("RS: procInterfaceIpEntry failed: %v", err)
				}

			case bool:
				log.Printf("RS:[VIF enabled] %v", val)

			default:
				log.Err("RS: VIF(%v) not supported %v", target, val)
			}

		case *vswitch.VRF:
			// Get the router of the given VRF.
			router := s.getRouterByIndex(target.Index())
			if router == nil {
				continue
			}

			switch val := notify.Value.(type) {
			case nil:
				//TODO: VRF created and deleted.
				log.Printf("RS:[VRF] vrf(%v) type(%v)",
					target.Name(), notify.Type)

			case vswitch.Route:
				// Route added and deleted.
				if err := router.procRouteEntry(notify.Type, val); err != nil {
					log.Err("RS: procRouteEntry failed: %v", err)
				}

			case *vswitch.VIF:
				//TODO: VIF added to vrf.
				log.Printf("RS:[VIF] vrf(%v) type(%v) vif(%v)",
					target.Name(), notify.Type, val.Name())

			case *vswitch.PBREntry:
				if err := router.procPBREntry(notify.Type, val); err != nil {
					log.Err("RS: procPBREntry failed: %v", err)
				}

			default:
				log.Err("RS: VRF(%v) not supported %v", target, val)
			}

		default:
			log.Err("RS: not supported target %v", notify)
		}
	}
}

func (r *RouterInstance) setRuleEntry(ring *dpdk.Ring, rule C.struct_rule) *C.struct_router_rule {
	info := (*C.struct_router_rule)(unsafe.Pointer(&r.param.p[0]))
	*info = C.struct_router_rule{}
	info.ring = (*C.struct_rte_ring)(unsafe.Pointer(ring))
	info.rule = rule
	return info
}

func (r *RouterInstance) listenRules() {
	for n := range r.notifyRule {
		rule, ok := n.Value.(vswitch.Rule)
		if !ok {
			log.Err("Unknown value received (Expecting vswitch.Rule): %v", reflect.TypeOf(n.Value))
			continue
		}

		r.mutex.Lock()
		switch rule.Match {
		case vswitch.MatchAny:
			// Default Output (The same as Output())

		case vswitch.MatchIPv4DstSelf:
			// to Tap module
			if err := r.control(ROUTER_CMD_CONFIG_TAP, unsafe.Pointer(rule.Ring)); err != nil {
				log.Printf("Config ring failed: %v", err)
			}
			r.tap = rule.Ring

		case vswitch.MatchIPv4DstInVIF:
			val, ok := rule.Param.(*vswitch.ScopedAddress)
			if !ok {
				r.mutex.Unlock()
				continue
			}
			crule := C.struct_rule{
				in_vif: C.vifindex_t(val.VIF().Index()),
				dstip:  ipv4toCuint32(val.Address()),
				proto:  C.uint8_t(vswitch.IPP_ANY),
			}
			info := r.setRuleEntry(rule.Ring, crule)

			cmd := ROUTER_CMD_RULE_ADD
			if n.Type == notifier.Delete {
				cmd = ROUTER_CMD_RULE_DELETE
			}

			if err := r.control(cmd, unsafe.Pointer(info)); err == nil {
				log.Info("Config MatchIPv4DstInVIF rule succeeded (%v): %#v", n.Type, crule)
			} else {
				log.Err("Config MatchIPv4DstInVIF rule failed (%v): %#v: %v", n.Type, crule, err)
			}

		case vswitch.Match5Tuple:
			val, ok := rule.Param.(*vswitch.FiveTuple)
			if !ok {
				log.Err("Unknown value received (Expecting *vswitch.FiveTyple): %v",
					reflect.TypeOf(rule.Param))
				r.mutex.Unlock()
				continue
			}

			crule := C.struct_rule{
				in_vif:  C.vifindex_t(C.VIF_INVALID_INDEX),
				srcip:   ipv4toCuint32(val.SrcIP.IP),
				dstip:   ipv4toCuint32(val.DstIP.IP),
				dstport: C.uint16_t(val.DstPort.Start),
				proto:   C.uint8_t(val.Proto),
			}
			info := r.setRuleEntry(rule.Ring, crule)

			cmd := ROUTER_CMD_RULE_ADD
			if n.Type == notifier.Delete {
				cmd = ROUTER_CMD_RULE_DELETE
			}

			if err := r.control(cmd, unsafe.Pointer(info)); err == nil {
				log.Info("Config 5-tuple rule succeeded (%v): %#v", n.Type, crule)
			} else {
				log.Err("Config 5-tuple rule failed (%v): %#v: %v", n.Type, crule, err)
			}

		case vswitch.MatchVxLAN:
			val, ok := rule.Param.(*vswitch.VxLAN)
			if !ok {
				log.Err("Unknown value received (Expecting *vswitch.VxLAN): %v",
					reflect.TypeOf(rule.Param))
				r.mutex.Unlock()
				continue
			}

			crule := C.struct_rule{
				in_vif:  C.vifindex_t(C.VIF_INVALID_INDEX),
				srcip:   ipv4toCuint32(val.Src),
				dstip:   ipv4toCuint32(val.Dst),
				dstport: C.uint16_t(val.DstPort),
				proto:   C.uint8_t(vswitch.IPP_UDP),
				vni:     C.uint32_t(val.VNI),
			}
			info := r.setRuleEntry(rule.Ring, crule)

			cmd := ROUTER_CMD_RULE_ADD
			if n.Type == notifier.Delete {
				cmd = ROUTER_CMD_RULE_DELETE
			}

			if err := r.control(cmd, unsafe.Pointer(info)); err == nil {
				log.Info("Config VxLAN rule succeeded (%v): %#v", n.Type, crule)
			} else {
				log.Err("Config VxLAN rule failed (%v): %#v: %v", n.Type, crule, err)
			}
		}
		r.mutex.Unlock()
	}
}

func loadConfig() {
	// Get configuration
	c := routerConfigSection{defaultConfig}
	vswitch.GetConfig().Decode(&c)
	config = c.Router
}

var once sync.Once

var routerCount int
var routerCountMutex sync.Mutex

func newRouterInstance(base *vswitch.BaseInstance, priv interface{}) (vswitch.Instance, error) {
	routerCountMutex.Lock()
	defer routerCountMutex.Unlock()

	once.Do(loadConfig)

	vrf, ok := priv.(*vswitch.VRF)
	if !ok {
		return nil, errors.New("VRF is invalid.")
	}

	s, err := getRouterService()
	if err != nil {
		return nil, err
	}

	if routerCount == C.ROUTER_MAX_ROUTERS {
		return nil, errors.New("Router instance exceeded the limit.")
	}
	routerCount++

	r := &RouterInstance{
		base:           base,
		service:        s,
		vrfidx:         vrf.Index(),
		enabled:        false,
		mtu:            vswitch.DefaultMTU,
		neighborCaches: make(map[*vswitch.VIF][]C.struct_neighbor),
		notifyRule:     base.Rules().Notifier().Listen(),
	}

	// r.param
	r.param = (*C.struct_router_instance)(C.calloc(1, C.sizeof_struct_router_instance))
	// check name
	if len(base.Name()) > maxRouterNamesize {
		return nil, fmt.Errorf("Invalid router name(too long).")
	}
	r.param.base.name = C.CString(base.Name())
	r.param.base.input = (*C.struct_rte_ring)(unsafe.Pointer(base.Input()))
	r.param.router_id = C.vrfindex_t(r.vrfidx)

	if mode, ok := recordRouteProcessMode[config.RRProcessMode]; ok {
		r.param.rr_mode = mode
	} else {
		log.Warning("Invalid value in rr_process_mode (%s), disabled", config.RRProcessMode)
		r.param.rr_mode = C.RECORDROUTE_DISABLE
	}

	ri, err := vswitch.NewRuntimeInstance((vswitch.LagopusInstance)(unsafe.Pointer(r.param)))
	if err != nil {
		r.Free()
		return nil, fmt.Errorf("Can't create a new instance: %v", err)
	}

	if err := s.runtime.Register(ri); err != nil {
		r.Free()
		return nil, fmt.Errorf("Can't register the instance: %v", err)
	}

	r.instance = ri

	if err := s.registerRouter(r); err != nil {
		return nil, err
	}

	// create ARP resolver
	r.arpResolver = newARPResolver(r)
	r.arpResolver.start()

	// listen to receive rules.
	go r.listenRules()

	return r, nil
}

func (r *RouterInstance) Free() {
	routerCountMutex.Lock()
	defer routerCountMutex.Unlock()

	r.service.unregisterRouter(r)

	if r.instance != nil {
		r.instance.Unregister()
	}

	r.arpResolver.stop()

	r.service.free()

	C.free(unsafe.Pointer(r.param.base.name))
	C.free(unsafe.Pointer(r.param))

	r.service = nil
	r.base = nil

	routerCount--
}

func (r *RouterInstance) Enable() error {
	if !r.enabled {
		if err := r.instance.Enable(); err != nil {
			return err
		}
		r.enabled = true
	}

	return nil
}

func (r *RouterInstance) Disable() {
	if r.enabled {
		r.instance.Disable()
		r.enabled = false
	}
}

// for listen
func (r *RouterInstance) procPBREntry(cmdType notifier.Type, pbr *vswitch.PBREntry) error {
	if len(pbr.NextHops) > C.ROUTER_MAX_PBR_NEXTHOPS {
		return fmt.Errorf("PBR Nexthops exceeded the limit; max %d entries", C.ROUTER_MAX_PBR_NEXTHOPS)
	}

	smask, _ := pbr.SrcIP.Mask.Size()
	dmask, _ := pbr.DstIP.Mask.Size()

	r.mutex.Lock()
	defer r.mutex.Unlock()

	pe := (*C.struct_pbr_entry)(unsafe.Pointer(&r.param.p[0]))
	pe.priority = C.uint(pbr.Priority)

	if pbr.InputVIF != nil {
		pe.in_vif = C.vifindex_t(pbr.InputVIF.Index())
	} else {
		pe.in_vif = C.vifindex_t(C.VIF_INVALID_INDEX)
	}

	pe.src_addr = ipv4toCuint32(pbr.SrcIP.IP)
	pe.src_mask = C.uint8_t(smask)
	pe.dst_addr = ipv4toCuint32(pbr.DstIP.IP)
	pe.dst_mask = C.uint8_t(dmask)
	pe.src_port.from = C.uint16_t(pbr.SrcPort.Start)
	pe.src_port.to = C.uint16_t(pbr.SrcPort.End)
	pe.dst_port.from = C.uint16_t(pbr.DstPort.Start)
	pe.dst_port.to = C.uint16_t(pbr.DstPort.End)
	pe.protocol = C.uint8_t(pbr.Proto)
	pe.pass = C.bool(pbr.Pass)
	pe.nexthop_count = C.uint8_t(len(pbr.NextHops))

	if pe.nexthop_count > 0 {
		var nhs []*vswitch.Nexthop
		for _, nh := range pbr.NextHops {
			nhs = append(nhs, nh)
		}

		// sort NextHops by Weight
		sort.Slice(nhs, func(i, j int) bool {
			return nhs[i].Weight > nhs[j].Weight
		})

		penh := (*C.struct_pbr_entry_nh)(unsafe.Pointer(pe))

		for i, nh := range nhs {
			if nh.Dev != nil {
				penh.nexthops[i].out_vif = C.vifindex_t(nh.Dev.VIFIndex())
			} else {
				penh.nexthops[i].out_vif = C.VIF_INVALID_INDEX
			}
			penh.nexthops[i].gw = ipv4toCuint32(nh.Gw)
			penh.nexthops[i].weight = C.uint32_t(nh.Weight)
		}
	}

	if cmdType == notifier.Add {
		return r.control(ROUTER_CMD_PBRRULE_ADD, unsafe.Pointer(pe))
	}
	return r.control(ROUTER_CMD_PBRRULE_DELETE, unsafe.Pointer(pe))
}

func (r *RouterInstance) procRouteEntry(cmdType notifier.Type, route vswitch.Route) error {
	// Ignore Non-IPv4 route
	if route.Dst != nil && route.Dst.IP.To4() == nil {
		return nil
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	info, err := r.setRouteEntry(&route)
	if err != nil {
		return err
	}

	if cmdType == notifier.Add {
		return r.control(ROUTER_CMD_ROUTE_ADD, unsafe.Pointer(info))
	}
	return r.control(ROUTER_CMD_ROUTE_DELETE, unsafe.Pointer(info))
}

func (r *RouterInstance) updateNeighborEntry(index vswitch.VIFIndex, target IPv4Addr, hwaddr EtherAddr) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	ne := (*C.struct_neighbor_entry)(unsafe.Pointer(&r.param.p[0]))
	for i := 0; i < 6; i++ {
		ne.mac.addr_bytes[i] = C.uint8_t(hwaddr[i])
	}
	ne.ifindex = C.vifindex_t(index)
	ne.ip = C.uint32_t(target)

	return r.control(ROUTER_CMD_NEIGH_UPDATE, unsafe.Pointer(ne))
}

func (r *RouterInstance) deleteNeighborEntry(index vswitch.VIFIndex, target IPv4Addr) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	ne := (*C.struct_neighbor_entry)(unsafe.Pointer(&r.param.p[0]))
	ne.ifindex = C.vifindex_t(index)
	ne.ip = C.uint32_t(target)

	return r.control(ROUTER_CMD_NEIGH_DELETE, unsafe.Pointer(ne))
}

func (r *RouterInstance) procInterfaceIpEntry(cmdType notifier.Type, vifindex vswitch.VIFIndex, ip vswitch.IPAddr) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// update IP addresses held by ARP resolver
	r.arpResolver.updateIPAddr(vifindex)

	var cmd routerCmd
	if cmdType == notifier.Add {
		if r.addrsCount == C.ROUTER_MAX_VIF_IPADDRS {
			return errors.New("Number of self IP addresses exceeded the limit")
		}
		cmd = ROUTER_CMD_VIF_ADD_IP
		r.addrsCount++
	} else {
		cmd = ROUTER_CMD_VIF_DELETE_IP
		r.addrsCount--
	}

	plen, _ := ip.Mask.Size()
	ie := (*C.struct_interface_addr_entry)(unsafe.Pointer(&r.param.p[0]))
	*ie = C.struct_interface_addr_entry{}
	ie.addr = ipv4toCuint32(ip.IP)
	ie.ifindex = C.vifindex_t(vifindex)
	ie.prefixlen = C.uint32_t(plen)

	// update interface table.
	return r.control(cmd, unsafe.Pointer(ie))
}

func (r *RouterInstance) procInterfaceMTU(cmtType notifier.Type, vifindex vswitch.VIFIndex, mtu vswitch.MTU) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	ie := (*C.struct_interface_entry)(unsafe.Pointer(&r.param.p[0]))
	*ie = C.struct_interface_entry{}
	ie.ifindex = C.vifindex_t(vifindex)
	ie.mtu = C.uint16_t(mtu)

	// MTU only supports Notifier.Update
	return r.control(ROUTER_CMD_VIF_UPDATE_MTU, unsafe.Pointer(ie))
}

// for control
type routerCmd int

const (
	ROUTER_CMD_CONFIG_TAP     = routerCmd(C.ROUTER_CMD_CONFIG_TAP)
	ROUTER_CMD_RULE_ADD       = routerCmd(C.ROUTER_CMD_RULE_ADD)
	ROUTER_CMD_RULE_DELETE    = routerCmd(C.ROUTER_CMD_RULE_DELETE)
	ROUTER_CMD_VIF_ADD        = routerCmd(C.ROUTER_CMD_VIF_ADD)
	ROUTER_CMD_VIF_DELETE     = routerCmd(C.ROUTER_CMD_VIF_DELETE)
	ROUTER_CMD_VIF_ADD_IP     = routerCmd(C.ROUTER_CMD_VIF_ADD_IP)
	ROUTER_CMD_VIF_DELETE_IP  = routerCmd(C.ROUTER_CMD_VIF_DELETE_IP)
	ROUTER_CMD_VIF_UPDATE_MTU = routerCmd(C.ROUTER_CMD_VIF_UPDATE_MTU)
	ROUTER_CMD_ROUTE_ADD      = routerCmd(C.ROUTER_CMD_ROUTE_ADD)
	ROUTER_CMD_ROUTE_DELETE   = routerCmd(C.ROUTER_CMD_ROUTE_DELETE)
	ROUTER_CMD_NEIGH_UPDATE   = routerCmd(C.ROUTER_CMD_NEIGH_UPDATE)
	ROUTER_CMD_NEIGH_DELETE   = routerCmd(C.ROUTER_CMD_NEIGH_DELETE)
	ROUTER_CMD_NAPT_ENABLE    = routerCmd(C.ROUTER_CMD_NAPT_ENABLE)
	ROUTER_CMD_NAPT_DISABLE   = routerCmd(C.ROUTER_CMD_NAPT_DISABLE)
	ROUTER_CMD_PBRRULE_ADD    = routerCmd(C.ROUTER_CMD_PBRRULE_ADD)
	ROUTER_CMD_PBRRULE_DELETE = routerCmd(C.ROUTER_CMD_PBRRULE_DELETE)
)

// static functions for control
func ipv4toCuint32(ip net.IP) C.uint32_t {
	if ip := ip.To4(); ip != nil {
		return C.uint32_t(ip[0])<<24 | C.uint32_t(ip[1])<<16 |
			C.uint32_t(ip[2])<<8 | C.uint32_t(ip[3])
	}
	return 0
}

func (r *RouterInstance) setRouteEntry(rt *vswitch.Route) (*C.struct_route_entry, error) {
	// route.Dst == nil is defaut gateway.
	prefixlen := 0
	dst := net.IPv4(0, 0, 0, 0)
	if rt.Dst != nil {
		prefixlen, _ = rt.Dst.Mask.Size()
		dst = rt.Dst.IP
	}
	dstip := ipv4toCuint32(dst)

	route := (*C.struct_route_entry)(unsafe.Pointer(&r.param.p[0]))
	*route = C.struct_route_entry{}
	route.prefixlen = C.uint32_t(prefixlen)
	route.netmask = C.uint32_t(prefixlen)
	route.dst = dstip
	route.scope = C.uint32_t(rt.Scope)
	route.route_type = C.uint32_t(rt.Type)
	route.metric = C.uint32_t(rt.Metrics)

	length := len(rt.Nexthops)
	if length == 0 {
		length = 1
	}
	// allocation nexthops array
	size := length * C.sizeof_nexthop_t
	route.nexthops = (*C.nexthop_t)(C.calloc(1, C.size_t(size)))
	nexthops := (*[1 << 30]C.nexthop_t)(unsafe.Pointer(route.nexthops))[:length:length]

	// set nexthops
	route.nexthop_num = C.uint32_t(length)
	if len(rt.Nexthops) == 0 {
		// len(v.Nexthops) is 0, no v.Nexthops.
		// use v.Interface and v.Nexthop
		nexthops[0].ifindex = C.vifindex_t(rt.Dev.VIFIndex())
		nexthops[0].weight = 0
		nexthops[0].gw = ipv4toCuint32(rt.Gw)
		nexthops[0].netmask = C.uint8_t(prefixlen)
	} else {
		for i, nh := range rt.Nexthops {
			nexthops[i].ifindex = C.vifindex_t(nh.Dev.VIFIndex())
			nexthops[i].weight = C.uint32_t(nh.Weight)
			nexthops[i].gw = ipv4toCuint32(nh.Gw)
			nexthops[i].netmask = C.uint8_t(prefixlen)
		}
	}

	return route, nil
}

//-----

func (r *RouterInstance) control(cmd routerCmd, info unsafe.Pointer) error {
	log.Debug(0, "RS: control: cmd: %v, info: %p\n", cmd, info)

	p := &r.param.control
	p.cmd = C.router_cmd_t(cmd)
	p.info = info
	r.ctrls++
	rc, err := r.instance.Control(unsafe.Pointer(p))
	if rc == false || err != nil {
		r.ctrlsErr++
		return fmt.Errorf("RS: Control command(%v) failed: %v", cmd, err)
	}
	return nil
}

// configuration apis.
func (r *RouterInstance) AddVIF(vif *vswitch.VIF) error {
	log.Printf("AddVIF: %v", vif)
	r.mutex.Lock()
	defer r.mutex.Unlock()

	ips := vif.ListIPAddrs()
	if r.addrsCount+uint(len(ips)) > C.ROUTER_MAX_VIF_IPADDRS {
		return errors.New("Can register nomore IP addresses")
	}

	// Add VIF to the ARP resolver
	r.arpResolver.addVIF(vif)

	// add vif
	ie := (*C.struct_interface_entry)(unsafe.Pointer(&r.param.p[0]))
	*ie = C.struct_interface_entry{}
	ie.ifindex = C.vifindex_t(vif.Index())
	ie.ring = (*C.struct_rte_ring)(unsafe.Pointer(vif.Input()))
	ie.mtu = C.uint16_t(vif.MTU())
	ie.vid = C.uint16_t(vif.VID())
	mac := vif.MACAddress()
	if mac != nil {
		m := (*[1 << 30]byte)(unsafe.Pointer(&ie.mac.addr_bytes))[:6:6]
		copy(m, (mac)[:])
	}

	if vif.Tunnel() != nil {
		ie.flags |= C.IFF_TYPE_TUNNEL
	}

	if err := r.control(ROUTER_CMD_VIF_ADD, unsafe.Pointer(ie)); err != nil {
		return err
	}

	// save neighbor cache if available
	if vif.Tunnel() == nil {
		r.neighborCaches[vif] = (*[1 << 30]C.struct_neighbor)(unsafe.Pointer(ie.cache))[:ie.cache_size:ie.cache_size]
	}

	// add ip addresses
	for _, ip := range ips {
		// send backend process
		plen, _ := ip.Mask.Size()
		addr := (*C.struct_interface_addr_entry)(unsafe.Pointer(&r.param.p[0]))
		*addr = C.struct_interface_addr_entry{}
		addr.addr = ipv4toCuint32(ip.IP)
		addr.ifindex = C.vifindex_t(vif.Index())
		addr.prefixlen = C.uint32_t(plen)

		// We intentionally ignore error here.
		// It should never fail as all condition should be cleared before
		// adding IP address.
		if err := r.control(ROUTER_CMD_VIF_ADD_IP, unsafe.Pointer(addr)); err != nil {
			log.Err("Adding IP address of %v failed: %v", vif, err)
		}
		r.addrsCount++
	}

	return nil
}

func (r *RouterInstance) DeleteVIF(vif *vswitch.VIF) error {
	// TODO: config agent not supported.
	log.Printf("DeleteVIF: %v", vif)
	r.mutex.Lock()
	defer r.mutex.Unlock()
	for _, ip := range vif.ListIPAddrs() {
		// send backend process
		plen, _ := ip.Mask.Size()
		addr := (*C.struct_interface_addr_entry)(unsafe.Pointer(&r.param.p[0]))
		*addr = C.struct_interface_addr_entry{}
		addr.addr = ipv4toCuint32(ip.IP)
		addr.ifindex = C.vifindex_t(vif.Index())
		addr.prefixlen = C.uint32_t(plen)

		// We intentionally ignore error here
		// It should never fail as all condition should be cleared before
		// deleting IP address.
		if err := r.control(ROUTER_CMD_VIF_DELETE_IP, unsafe.Pointer(addr)); err != nil {
			log.Err("Deleting IP address of %v failed: %v", vif, err)
		}
		r.addrsCount--
	}

	ie := (*C.struct_interface_entry)(unsafe.Pointer(&r.param.p[0]))
	*ie = C.struct_interface_entry{}
	ie.ifindex = C.vifindex_t(vif.Index())
	if err := r.control(ROUTER_CMD_VIF_DELETE, unsafe.Pointer(ie)); err != nil {
		return err
	}

	// Delete VIF from the ARP resolver
	r.arpResolver.deleteVIF(vif)

	delete(r.neighborCaches, vif)
	return nil
}

func (r *RouterInstance) getNeighborCache(vif *vswitch.VIF) []C.struct_neighbor {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	return r.neighborCaches[vif]
}

func (r *RouterInstance) AddOutputDevice(dev vswitch.OutputDevice) error {
	log.Info("AddOutputDevice: %v", dev)
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Sanity check
	if _, ok := dev.(*vswitch.VRF); !ok {
		return fmt.Errorf("%v is not VRF", dev)
	}

	// For now, we assume we only get VRF.
	ie := (*C.struct_interface_entry)(unsafe.Pointer(&r.param.p[0]))
	*ie = C.struct_interface_entry{}
	ie.ifindex = C.vifindex_t(dev.VIFIndex())
	ie.ring = (*C.struct_rte_ring)(unsafe.Pointer(dev.Input()))
	ie.flags = C.IFF_TYPE_VRF

	if err := r.control(ROUTER_CMD_VIF_ADD, unsafe.Pointer(ie)); err != nil {
		return err
	}

	return nil
}

func (r *RouterInstance) DeleteOutputDevice(dev vswitch.OutputDevice) error {
	log.Info("DeleteOutputDevice: %v", dev)
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Sanity check
	if _, ok := dev.(*vswitch.VRF); !ok {
		return fmt.Errorf("%v is not VRF", dev)
	}

	// For now, we assume we only get VRF.
	ie := (*C.struct_interface_entry)(unsafe.Pointer(&r.param.p[0]))
	*ie = C.struct_interface_entry{}
	ie.ifindex = C.vifindex_t(dev.VIFIndex())

	if err := r.control(ROUTER_CMD_VIF_DELETE, unsafe.Pointer(ie)); err != nil {
		return err
	}

	return nil
}

func (r *RouterInstance) EnableNAPT(vif *vswitch.VIF) error {
	log.Info("EnableNAPT: %v", vif)
	r.mutex.Lock()
	defer r.mutex.Unlock()

	napt := vif.NAPT()

	if napt == nil {
		log.Fatalf("vif.NAPT() shall not return nil: %v", vif)
	}

	nc := (*C.struct_napt_config)(unsafe.Pointer(&r.param.p[0]))
	*nc = C.struct_napt_config{}
	nc.wan_addr = ipv4toCuint32(napt.Address())
	nc.port_min = C.uint16_t(napt.PortRange().Start)
	nc.port_max = C.uint16_t(napt.PortRange().End)
	nc.max_entries = C.uint16_t(napt.MaximumEntries())
	nc.aging_time = C.uint16_t(napt.AgingTime())
	nc.vif = C.vifindex_t(vif.Index())

	return r.control(ROUTER_CMD_NAPT_ENABLE, unsafe.Pointer(nc))
}

func (r *RouterInstance) DisableNAPT(vif *vswitch.VIF) error {
	log.Info("DisableNAPT: %v", vif)
	r.mutex.Lock()
	defer r.mutex.Unlock()

	index := C.vifindex_t(vif.Index())

	return r.control(ROUTER_CMD_NAPT_DISABLE, unsafe.Pointer(&index))
}

func init() {
	if l, err := vlog.New(moduleName); err == nil {
		log = l
	} else {
		log.Fatalf("Can't create logger: %s", moduleName)
	}
	rp := &vswitch.RingParam{
		Count:    C.ROUTER_MAX_MBUFS,
		SocketId: dpdk.SOCKET_ID_ANY,
	}

	if err := vswitch.RegisterModule(moduleName, newRouterInstance, rp, vswitch.TypeRouter); err != nil {
		log.Fatalf("Failed to register the class.")
	}
}
