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
	"sync"
	"syscall"
	"unsafe"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/notifier"
	"github.com/lagopus/vsw/utils/ringpair"
	"github.com/lagopus/vsw/vswitch"
	vlog "github.com/lagopus/vsw/vswitch/log"
)

const (
	moduleName        = "router"
	maxRouterRequests = 1024
)

// package private: read only
var pbrAction map[vswitch.PBRAction]C.pbr_action_t = map[vswitch.PBRAction]C.pbr_action_t{
	vswitch.PBRActionNone:    C.PBRACTION_NONE,
	vswitch.PBRActionDrop:    C.PBRACTION_DROP,
	vswitch.PBRActionPass:    C.PBRACTION_PASS,
	vswitch.PBRActionForward: C.PBRACTION_FORWARD}

type RouterInstance struct {
	base       *vswitch.BaseInstance
	service    *routerService
	vrfidx     uint64
	instance   *vswitch.RuntimeInstance
	param      *C.struct_router_instance
	enabled    bool
	mtu        vswitch.MTU
	vifs       map[vswitch.VIFIndex]*dpdk.Ring
	addrsCount uint
	notifyRule chan notifier.Notification
	pbr        map[string]int
	ctrls      uint
	ctrlsErr   uint
}

/*
 * Each informations are managed by VRF.
 */

// Backend Manager
type routerService struct {
	runtime   *vswitch.Runtime
	mutex     sync.Mutex
	terminate chan struct{}
	rp        *ringpair.RingPair
	routers   map[uint64]*RouterInstance
	running   bool
	refcnt    uint
	notify    chan notifier.Notification // receive routing informations
}

// internal purpose only
var log = vswitch.Logger
var rs *routerService
var mutex sync.Mutex

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
	RRProcessMode: "disable",
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

	// create a pair of rings for C/Go communication
	rp := ringpair.Create(&ringpair.Config{
		Prefix:   "router",
		Counts:   [2]uint{maxRouterRequests},
		SocketID: dpdk.SOCKET_ID_ANY,
	})
	if rp == nil {
		rp.Free()
		return nil, errors.New("Can't create a ringpair")
	}

	param := C.struct_router_runtime_param{
		notify: (*C.struct_rte_ring)(unsafe.Pointer(rp.Rings[0])),
		pool:   (*C.struct_rte_mempool)(unsafe.Pointer(vswitch.GetDpdkResource().Mempool)),
	}

	ops := vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.router_runtime_ops))
	log.Printf("call NewRuntime with slave core(%v)\n", config.SlaveCore)
	rt, err := vswitch.NewRuntime(config.SlaveCore, moduleName, ops, unsafe.Pointer(&param))
	if err != nil {
		return nil, err
	}
	if err := rt.Enable(); err != nil {
		return nil, err
	}

	rs = &routerService{
		runtime:   rt,
		terminate: make(chan struct{}),
		rp:        rp,
		routers:   make(map[uint64]*RouterInstance),
		refcnt:    1,
		notify:    vswitch.GetNotifier().Listen(),
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
		for _, r := range s.routers {
			r.instance.Unregister()
		}
		s.runtime.Terminate()
		s.rp.Free()
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

func (s *routerService) start() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.running {
		return
	}

	s.running = true
	go func() {
		<-s.terminate
		s.stop()
	}()

	// listen to receive routing informations.
	go s.listen()
}

func (s *routerService) stop() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.running {
		s.terminate <- struct{}{}
	}
}

func (s *routerService) listen() {
	for notify := range s.notify {
		if vif, ok := notify.Target.(*vswitch.VIF); ok {
			if vif.VRF() == nil {
				continue
			}
			// VIF informations.
			vrfidx := uint64(vif.VRF().Index())
			router := s.routers[vrfidx]
			if router == nil {
				continue
			}

			switch val := notify.Value.(type) {
			case nil:
				log.Printf("RS:[nil]")
			case vswitch.MTU:
				log.Printf("RS:[MTU] mtu(%v)", val)
				if err := router.updateInterfaceMTU(notify.Type, vif.Index(), val); err != nil {
					log.Err("RS: updateInterfaceMTU failed: %v", err)
				}
			case vswitch.IPAddr:
				log.Printf("RS:[IPAddr] vif: %v, val: %v\n", vif, val)
				if err := router.updateInterfaceIpEntry(notify.Type, vif.Index(), val); err != nil {
					log.Err("RS: updateInterfaceIpEntry failed: %v", err)
				}
			case bool:
				log.Printf("RS:[VIF enabled] %v", val)
			case vswitch.Neighbour:
				if err := router.updateNeighborEntry(notify.Type, vif.Index(), val); err != nil {
					log.Err("RS: updateNeighborEntry failed: %v", err)
				}
			}
		} else if vrf, ok := notify.Target.(*vswitch.VRF); ok {
			/// VRF informations.
			vrfidx := uint64(vrf.Index())
			router := s.routers[vrfidx]
			if router == nil {
				continue
			}

			switch val := notify.Value.(type) {
			case nil:
				//TODO: VRF created and deleted.
				log.Printf("RS:[VRF] vrf(%v) type(%v)",
					vrf.Name(), notify.Type)
			case vswitch.Route:
				// Route added and deleted.
				if err := router.updateRouteEntry(notify.Type, val); err != nil {
					log.Err("RS: updateRouteEntry failed: %v", err)
				}
			case vswitch.VIF:
				//TODO: VIF added to vrf.
				log.Printf("RS:[VIF] vrf(%v) type(%v) vif(%v)",
					vrf.Name(), notify.Type, val.Name())
			case vswitch.PBREntry:
				if err := router.updatePBREntry(notify.Type, val); err != nil {
					log.Err("RS: updatePBREntry failed: %v", err)
				}
			default:
				vif, _ := val.(*vswitch.VIF)
				if vif != nil {
					log.Printf("RS: vrf(%v) not supported vif(%v)",
						vrf.Name(), vif.Name())
				}
			}
		}
	}
}

func (r *RouterInstance) listenRules() {
	for n := range r.notifyRule {
		rule, ok := n.Value.(vswitch.Rule)
		if !ok {
			log.Err("Unknown value received (Expecting vswitch.Rule): %v", reflect.TypeOf(n.Value))
			continue
		}

		switch rule.Match {
		case vswitch.MatchAny:
			// Default Output (The same as Output())

		case vswitch.MatchIPv4DstSelf:
			// to Tap module
			if err := r.control(ROUTER_CMD_CONFIG_TAP, unsafe.Pointer(rule.Ring)); err != nil {
				log.Printf("Config ring failed: %v", err)
			}

		case vswitch.MatchIPv4Dst:
			// hostif
			// TODO: set routerMatchParam
			// if err := r.control(ROUTER_CMD_CONFIG_RULE, rule.Ring, nil); err != nil {
			// 	log.Printf("Config ring failed: %v", err)
			// }

		case vswitch.Match5Tuple:
			val, ok := rule.Param.(*vswitch.FiveTuple)
			if !ok {
				log.Err("Unknown value received (Expecting *vswitch.FiveTyple): %v",
					reflect.TypeOf(rule.Param))
				continue
			}

			crule := C.struct_rule{
				srcip:   ipv4toCuint32(val.SrcIP.IP),
				dstip:   ipv4toCuint32(val.DstIP.IP),
				dstport: C.uint16_t(val.DstPort.Start),
				proto:   C.uint8_t(val.Proto),
			}

			info := &C.struct_router_rule{
				rule: crule,
				ring: (*C.struct_rte_ring)(unsafe.Pointer(rule.Ring)),
			}

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
				continue
			}

			crule := C.struct_rule{
				srcip:   ipv4toCuint32(val.Src),
				dstip:   ipv4toCuint32(val.Dst),
				dstport: C.uint16_t(val.DstPort),
				proto:   C.uint8_t(vswitch.IPP_UDP),
				vni:     C.uint32_t(val.VNI),
			}

			info := &C.struct_router_rule{
				rule: crule,
				ring: (*C.struct_rte_ring)(unsafe.Pointer(rule.Ring)),
			}

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
	}
}

func loadConfig() {
	// Get configuration
	c := routerConfigSection{defaultConfig}
	vswitch.GetConfig().Decode(&c)
	config = c.Router
}

var once sync.Once

var routerCount uint64 = 0
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

	if routerCount == C.MAX_ROUTERS {
		return nil, errors.New("Router instance exceeded the limit.")
	}
	routerCount++

	r := &RouterInstance{
		base:       base,
		service:    s,
		vrfidx:     uint64(vrf.Index()),
		enabled:    false,
		mtu:        vswitch.DefaultMTU,
		vifs:       make(map[vswitch.VIFIndex]*dpdk.Ring),
		notifyRule: base.Rules().Notifier().Listen(),
	}

	if err := s.registerRouter(r); err != nil {
		return nil, err
	}

	// r.param
	r.param = (*C.struct_router_instance)(C.calloc(1, C.sizeof_struct_router_instance))
	// check name
	if len(base.Name()) > C.ROUTER_NAME_SIZE {
		return nil, fmt.Errorf("Invalid router name(too long).")
	}
	r.param.base.name = C.CString(base.Name())
	r.param.base.input = (*C.struct_rte_ring)(unsafe.Pointer(base.Input()))
	switch config.RRProcessMode {
	case "disable":
		r.param.rr_mode = C.RECORDROUTE_DISABLE
	case "ignore":
		r.param.rr_mode = C.RECORDROUTE_IGNORE
	case "enable":
		r.param.rr_mode = C.RECORDROUTE_ENABLE
	default:
		log.Printf("RI: invalid record route process mode, set default \"disable\"\n")
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

	// listen to receive rules.
	go r.listenRules()

	return r, nil
}

func (r *RouterInstance) Free() {
	if r.instance != nil {
		r.instance.Unregister()
	}

	r.service.unregisterRouter(r)

	C.free(unsafe.Pointer(r.param.base.name))
	C.free(unsafe.Pointer(r.param))

	r.service = nil
	r.base = nil
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

	r.service.free()
}

// for listen
func (r *RouterInstance) updatePBREntry(cmdType notifier.Type, pbr vswitch.PBREntry) error {
	// Management pbr index
	smask, _ := pbr.SrcIP.Mask.Size()
	dmask, _ := pbr.DstIP.Mask.Size()
	inif := C.vifindex_t(C.VIF_INVALID_INDEX)
	if pbr.InputVIF != nil {
		inif = C.vifindex_t(pbr.InputVIF.Index())
	}
	sp := C.struct_range{
		from: C.uint16_t(pbr.SrcPort.Start),
		to:   C.uint16_t(pbr.SrcPort.End),
	}
	dp := C.struct_range{
		from: C.uint16_t(pbr.DstPort.Start),
		to:   C.uint16_t(pbr.DstPort.End),
	}
	pe := &C.struct_pbr_entry{
		priority: C.int(pbr.Priority),
		in_vif:   inif,
		src_addr: ipv4toCuint32(pbr.SrcIP.IP),
		src_mask: C.uint8_t(smask),
		dst_addr: ipv4toCuint32(pbr.DstIP.IP),
		dst_mask: C.uint8_t(dmask),
		src_port: sp,
		dst_port: dp,
		protocol: C.uint8_t(pbr.Proto),
	}
	// no nexthop is drop
	length := len(pbr.NextHops)
	if length == 0 {
		// for drop action
		length = 1
	}
	// set nexthop
	pe.nexthop_num = C.uint32_t(length)
	size := length * C.sizeof_struct_nexthop
	pe.nexthops = (*C.struct_nexthop)(C.calloc(1, C.ulong(size)))
	nexthops := (*[1 << 30]C.struct_nexthop)(unsafe.Pointer(pe.nexthops))[:length:length]
	i := 0 // index of array
	// If there is no nexthop, the action is DROP
	nexthops[i].action = C.PBRACTION_DROP
	for _, nh := range pbr.NextHops {
		if nh.Dev != nil {
			nexthops[i].ifindex = C.uint16_t(nh.Dev.VIFIndex())
		} else {
			nexthops[i].ifindex = C.VIF_INVALID_INDEX
		}
		nexthops[i].gw = ipv4toCuint32(nh.Gw)
		nexthops[i].weight = C.uint32_t(nh.Weight)
		nexthops[i].broadcast_type = C.IPV4_NO_BROADCAST
		// Action NONE is not used in PBR
		if nh.Action == C.PBRACTION_PASS {
			nexthops[i].action = C.PBRACTION_PASS
		} else {
			nexthops[i].action = C.PBRACTION_FORWARD
		}
		i++
	}

	if cmdType == notifier.Add {
		return r.control(ROUTER_CMD_PBRRULE_ADD, unsafe.Pointer(pe))
	}
	return r.control(ROUTER_CMD_PBRRULE_DELETE, unsafe.Pointer(pe))
}

func (r *RouterInstance) updateRouteEntry(cmdType notifier.Type, route vswitch.Route) error {
	info, err := allocRouteEntry(&route)
	if err != nil {
		return err
	}

	if cmdType == notifier.Add {
		return r.control(ROUTER_CMD_ROUTE_ADD, unsafe.Pointer(info))
	}
	return r.control(ROUTER_CMD_ROUTE_DELETE, unsafe.Pointer(info))
}

func (r *RouterInstance) updateNeighborEntry(cmdType notifier.Type, index vswitch.VIFIndex, neighbor vswitch.Neighbour) error {
	// create entry.
	ne := &C.struct_neighbor_entry{
		ifindex: C.int(index),
		ip:      ipv4toCuint32(neighbor.Dst),
		mac:     createStructEtherAddr(neighbor.LinkLocalAddr),
		state:   C.int(neighbor.State),
	}

	switch cmdType {
	case notifier.Add, notifier.Update:
		// Add neighbor entry to backend hash table.
		// And addition processing and update processing are the same processing.
		return r.control(ROUTER_CMD_NEIGH_ADD, unsafe.Pointer(ne))

	case notifier.Delete:
		// Remove neighbor entry from bakend hash table.
		return r.control(ROUTER_CMD_NEIGH_DELETE, unsafe.Pointer(ne))

	default:
		return fmt.Errorf("Unknown cmdType: %v", cmdType)
	}

	return nil
}

func (r *RouterInstance) updateInterfaceIpEntry(cmdType notifier.Type, vifindex vswitch.VIFIndex, ip vswitch.IPAddr) error {
	var cmd routerCmd
	if cmdType == notifier.Add {
		if r.addrsCount == C.IPADDR_MAX_NUM {
			return errors.New("Number of self IP addresses exceeded the limit")
		}
		cmd = ROUTER_CMD_VIF_ADD_IP
		r.addrsCount++
	} else {
		cmd = ROUTER_CMD_VIF_DELETE_IP
		r.addrsCount--
	}

	plen, _ := ip.Mask.Size()
	ie := &C.struct_interface_addr_entry{
		addr:      ipv4toCuint32(ip.IP),
		ifindex:   C.uint32_t(vifindex),
		prefixlen: C.uint32_t(plen),
	}

	// update interface table.
	return r.control(cmd, unsafe.Pointer(ie))
}

func (r *RouterInstance) updateInterfaceMTU(cmtType notifier.Type, vifindex vswitch.VIFIndex, mtu vswitch.MTU) error {
	ie := &C.struct_interface_entry{
		ifindex: C.uint32_t(vifindex),
		mtu:     C.uint16_t(mtu),
	}

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
	ROUTER_CMD_NEIGH_ADD      = routerCmd(C.ROUTER_CMD_NEIGH_ADD)
	ROUTER_CMD_NEIGH_DELETE   = routerCmd(C.ROUTER_CMD_NEIGH_DELETE)
	ROUTER_CMD_NAPT_ENABLE    = routerCmd(C.ROUTER_CMD_NAPT_ENABLE)
	ROUTER_CMD_NAPT_DISABLE   = routerCmd(C.ROUTER_CMD_NAPT_DISABLE)
	ROUTER_CMD_PBRRULE_ADD    = routerCmd(C.ROUTER_CMD_PBRRULE_ADD)
	ROUTER_CMD_PBRRULE_DELETE = routerCmd(C.ROUTER_CMD_PBRRULE_DELETE)
)

// static functions for control
func ipv4toCuint32(ip net.IP) C.uint32_t {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	addr := int(ip[0])<<24 | int(ip[1])<<16 | int(ip[2])<<8 | int(ip[3])
	return C.uint32_t(addr)

}

func allocRouteEntry(rt *vswitch.Route) (*C.struct_route_entry, error) {
	// route.Dst == nil is defaut gateway.
	prefixlen := 0
	dst := net.IPv4(0, 0, 0, 0)
	if rt.Dst != nil {
		prefixlen, _ = rt.Dst.Mask.Size()
		dst = rt.Dst.IP
		if dst.To4() == nil {
			return nil, fmt.Errorf("not supported ip addresss(%v).", rt.Dst)
		}
	}
	dstip := ipv4toCuint32(dst)

	route := &C.struct_route_entry{
		prefixlen:  C.uint32_t(prefixlen),
		netmask:    C.uint32_t(prefixlen),
		dst:        dstip,
		scope:      C.uint32_t(rt.Scope),
		route_type: C.uint32_t(rt.Type),
		metric:     C.uint32_t(rt.Metrics),
	}

	length := len(rt.Nexthops)
	if length == 0 {
		length = 1
	}
	// allocation nexthops array
	size := length * C.sizeof_struct_nexthop
	route.nexthops = (*C.struct_nexthop)(C.calloc(1, C.ulong(size)))
	nexthops := (*[1 << 30]C.struct_nexthop)(unsafe.Pointer(route.nexthops))[:length:length]

	// get broadcast type
	bt := C.IPV4_NO_BROADCAST
	if rt.Type == syscall.RTN_BROADCAST {
		if (dstip & 1) == 1 {
			bt = C.IPV4_DIRECTED_BROADCAST
		} else {
			bt = C.IPV4_NONSTANDARD_BROADCAST
		}
	}

	// set nexthops
	route.nexthop_num = C.uint32_t(length)
	if len(rt.Nexthops) == 0 {
		// len(v.Nexthops) is 0, no v.Nexthops.
		// use v.Interface and v.Nexthop
		nexthops[0].ifindex = C.uint16_t(rt.Dev.VIFIndex())
		nexthops[0].weight = 0
		nexthops[0].gw = ipv4toCuint32(rt.Gw)
		nexthops[0].netmask = C.uint8_t(prefixlen)
		nexthops[0].broadcast_type = C.uint8_t(bt)
	} else {
		for i, nh := range rt.Nexthops {
			nexthops[i].ifindex = C.uint16_t(nh.Dev.VIFIndex())
			nexthops[i].weight = C.uint32_t(nh.Weight)
			nexthops[i].gw = ipv4toCuint32(nh.Gw)
			nexthops[i].netmask = C.uint8_t(prefixlen)
			nexthops[i].broadcast_type = C.uint8_t(bt)
		}
	}

	return route, nil
}

//-----

func (r *RouterInstance) control(cmd routerCmd, info unsafe.Pointer) error {
	log.Debug(0, "RS: control: cmd: %v, info: %p\n", cmd, info)
	p := C.struct_router_control_param{
		cmd:  C.router_cmd_t(cmd),
		info: info,
	}
	r.ctrls++
	rc, err := r.instance.Control(unsafe.Pointer(&p))
	if rc == false || err != nil {
		r.ctrlsErr++
		return fmt.Errorf("RS: Control command(%v) failed: %v", cmd, err)
	}
	return nil
}

// configuration apis.
func (r *RouterInstance) AddVIF(vif *vswitch.VIF) error {
	log.Printf("AddVIF: %v", vif)

	ips := vif.ListIPAddrs()
	if r.addrsCount+uint(len(ips)) > C.IPADDR_MAX_NUM {
		return errors.New("Can register nomore IP addresses")
	}

	// add vif
	ie := &C.struct_interface_entry{
		ifindex: C.uint32_t(vif.Index()),
		ring:    (*C.struct_rte_ring)(unsafe.Pointer(vif.Input())),
		mtu:     C.uint16_t(vif.MTU()),
		vid:     C.uint16_t(vif.VID()),
		mac:     createStructEtherAddr(vif.MACAddress()),
	}

	if vif.Tunnel() != nil {
		ie.flags |= C.IFF_TYPE_TUNNEL
	}

	if err := r.control(ROUTER_CMD_VIF_ADD, unsafe.Pointer(ie)); err != nil {
		return err
	}

	// add ip addresses
	for _, ip := range ips {
		// send backend process
		plen, _ := ip.Mask.Size()
		addr := &C.struct_interface_addr_entry{
			addr:      ipv4toCuint32(ip.IP),
			ifindex:   C.uint32_t(vif.Index()),
			prefixlen: C.uint32_t(plen),
		}

		// We intentionally ignore error here.
		// It should never fail as all condition should be cleared before
		// adding IP address.
		if err := r.control(ROUTER_CMD_VIF_ADD_IP, unsafe.Pointer(addr)); err != nil {
			log.Err("Adding IP address of %v failed: %v", err)
		}
		r.addrsCount++
	}
	return nil
}

func (r *RouterInstance) DeleteVIF(vif *vswitch.VIF) error {
	// TODO: config agent not supported.
	log.Printf("DeleteVIF: %v", vif)
	for _, ip := range vif.ListIPAddrs() {
		// send backend process
		plen, _ := ip.Mask.Size()
		addr := &C.struct_interface_addr_entry{
			addr:      ipv4toCuint32(ip.IP),
			ifindex:   C.uint32_t(vif.Index()),
			prefixlen: C.uint32_t(plen),
		}

		// We intentionally ignore error here
		// It should never fail as all condition should be cleared before
		// deleting IP address.
		if err := r.control(ROUTER_CMD_VIF_DELETE_IP, unsafe.Pointer(addr)); err != nil {
			log.Err("Deleting IP address of %v failed: %v", err)
		}
		r.addrsCount--
	}

	ie := &C.struct_interface_entry{ifindex: C.uint32_t(vif.Index())}
	return r.control(ROUTER_CMD_VIF_DELETE, unsafe.Pointer(ie))
}

func (r *RouterInstance) AddOutputDevice(dev vswitch.OutputDevice) error {
	log.Info("AddOutputDevice: %v", dev)

	// Sanity check
	if _, ok := dev.(*vswitch.VRF); !ok {
		return fmt.Errorf("%v is not VRF", dev)
	}

	// For now, we assume we only get VRF.
	ie := &C.struct_interface_entry{
		ifindex: C.uint32_t(dev.VIFIndex()),
		ring:    (*C.struct_rte_ring)(unsafe.Pointer(dev.Input())),
		flags:   C.IFF_TYPE_VRF,
	}

	if err := r.control(ROUTER_CMD_VIF_ADD, unsafe.Pointer(ie)); err != nil {
		return err
	}

	return nil
}

func (r *RouterInstance) DeleteOutputDevice(dev vswitch.OutputDevice) error {
	log.Info("DeleteOutputDevice: %v", dev)

	// Sanity check
	if _, ok := dev.(*vswitch.VRF); !ok {
		return fmt.Errorf("%v is not VRF", dev)
	}

	// For now, we assume we only get VRF.
	ie := &C.struct_interface_entry{
		ifindex: C.uint32_t(dev.VIFIndex()),
	}

	if err := r.control(ROUTER_CMD_VIF_DELETE, unsafe.Pointer(ie)); err != nil {
		return err
	}

	return nil
}

func (r *RouterInstance) EnableNAPT(vif *vswitch.VIF) error {
	log.Info("EnableNAPT: %v", vif)

	napt := vif.NAPT()

	if napt == nil {
		log.Fatalf("vif.NAPT() shall not return nil: %v", vif)
	}

	nc := &C.struct_napt_config{
		wan_addr:    ipv4toCuint32(napt.Address()),
		port_min:    C.uint16_t(napt.PortRange().Start),
		port_max:    C.uint16_t(napt.PortRange().End),
		max_entries: C.uint16_t(napt.MaximumEntries()),
		aging_time:  C.uint16_t(napt.AgingTime()),
		vif:         C.vifindex_t(vif.Index()),
	}

	return r.control(ROUTER_CMD_NAPT_ENABLE, unsafe.Pointer(nc))
}

func (r *RouterInstance) DisableNAPT(vif *vswitch.VIF) error {
	log.Info("DisableNAPT: %v", vif)

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
		Count:    C.MAX_ROUTER_MBUFS,
		SocketId: dpdk.SOCKET_ID_ANY,
	}

	if err := vswitch.RegisterModule(moduleName, newRouterInstance, rp, vswitch.TypeRouter); err != nil {
		log.Fatalf("Failed to register the class.")
	}
}
