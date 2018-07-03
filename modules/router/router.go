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

package router

/*
#cgo CFLAGS: -I${SRCDIR}/../../include -I/usr/local/include/dpdk -m64 -pthread -O3 -msse4.2
#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all -L/usr/local/lib -ldpdk

#include "router_common.h"

*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/hashlist"
	"github.com/lagopus/vsw/utils/notifier"
	"github.com/lagopus/vsw/utils/ringpair"
	"github.com/lagopus/vsw/vswitch"
	"net"
	"sync"
	"unsafe"
)

const (
	moduleName        = "router"
	maxRouterRequests = 1024
)

type RouterInstance struct {
	base       *vswitch.BaseInstance
	service    *routerService
	vrfidx     uint64
	instance   *vswitch.RuntimeInstance
	param      *C.struct_router_instance
	enabled    bool
	mtu        vswitch.MTU
	vifs       map[vswitch.VIFIndex]*dpdk.Ring
	arpTable   *hashlist.HashList
	notifyRule chan notifier.Notification
}

/*
 * Each informations are managed by VRF.
 */
// for management MAC address of the interface(vif).
type InterfaceEntry struct {
	VRFIdx     uint64
	VIFId      uint32
	VID        uint16
	MACAddress net.HardwareAddr
	IPAddress  vswitch.IPAddr
	MTU        uint16
	Tunnel     bool
	Error      int
}

// for management IP address of the interface(vif).
type InterfaceIpEntry struct {
	VRFIdx           uint64
	VIFId            uint32
	IPAddress        vswitch.IPAddr
	BroadcastAddress net.IP
	MTU              uint16
}

// route entry for routing table.
type RouteEntry struct {
	VRFIdx    uint64 // VRF ID
	BridgeId  uint32
	Interface uint32
	Prefix    uint32
	DestAddr  net.IP
	NextHop   net.IP
	Metric    uint32
	Scope     uint32
	Recurse   bool
}

// arp entry for arp table.
type ArpEntry struct {
	VRFIdx     uint64 // VRF ID
	Interface  uint32
	IPAddress  net.IP
	MACAddress net.HardwareAddr
}

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
	SlaveCore uint `toml:"core"`
}

var config routerConfig
var defaultConfig = routerConfig{
	SlaveCore: 2,
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

	// Start Rou/er Service
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

	if _, exists := s.routers[r.vrfidx]; exists {
		return
	}

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
	for {
		select {
		case notify, ok := <-s.notify:
			if !ok {
				// notification error.
				fmt.Errorf("notification failed.")
				return
			}

			if vif, ok := notify.Target.(*vswitch.VIF); ok {
				if !ok {
					fmt.Errorf("notification failed.")
				}
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
				case vswitch.IPAddr:
					log.Printf("RS:[IPAddr] vif: %v, val: %v\n", vif, val)
					router.updateInterfaceIpEntry(
						notify.Type, vrfidx, uint32(vif.Index()), val)
				case bool:
					log.Printf("RS:[VIF enabled] %v", val)
				case vswitch.Neighbour:
					router.updateArpEntry(notify.Type, vrfidx, vif.Index(), val)
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
					router.updateRouteEntry(notify.Type, vrfidx, val)
				case vswitch.VIF:
					//TODO: VIF added to vrf.
					log.Printf("RS:[VIF] vrf(%v) type(%v) vif(%v)",
						vrf.Name(), notify.Type, val.Name())
				default:
					vif, _ := val.(*vswitch.VIF)
					log.Printf("RS: vrf(%v) not supported vif(%v)",
						vrf.Name(), vif.Name())
				}
			}
		default:
			// not supported.
		}
	}
}

func (r *RouterInstance) listenRules() {
	for n := range r.notifyRule {
		rule, ok := n.Value.(vswitch.Rule)
		if !ok {
			continue
		}

		switch rule.Match {
		case vswitch.MATCH_ANY:
			// Default Output (The same as Output())

		case vswitch.MATCH_IPV4_DST_SELF:
			// to Tap module
			if err := r.control(ROUTER_CMD_CONFIG_RING_TAP, rule.Ring, nil); err != nil {
				log.Printf("Config ring failed: %v", err)
			}

		case vswitch.MATCH_IPV4_DST:
			// hostif
			if err := r.control(ROUTER_CMD_CONFIG_RING_HOSTIF, rule.Ring, nil); err != nil {
				log.Printf("Config ring failed: %v", err)
			}

		case vswitch.MATCH_IPV4_PROTO:
			val, ok := rule.Param.(vswitch.IPProto)
			if !ok {
				continue
			}
			var cmd routerCmd
			switch val {
			case vswitch.IPP_IPIP:
				cmd = ROUTER_CMD_CONFIG_RING_IPIP
			case vswitch.IPP_ESP:
				cmd = ROUTER_CMD_CONFIG_RING_ESP
			case vswitch.IPP_GRE:
				cmd = ROUTER_CMD_CONFIG_RING_GRE
			}
			if err := r.control(cmd, rule.Ring, nil); err != nil {
				log.Printf("Config ring failed: %v", err)
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
		arpTable:   hashlist.New(),
		notifyRule: base.Rules().Notifier().Listen(),
	}

	if err := s.registerRouter(r); err != nil {
		return nil, err
	}

	// r.param
	r.param = (*C.struct_router_instance)(C.malloc(C.sizeof_struct_router_instance))
	r.param.base.name = C.CString(base.Name())
	r.param.base.input = (*C.struct_rte_ring)(unsafe.Pointer(base.Input()))
	r.param.base.outputs = (**C.struct_rte_ring)(C.malloc(C.size_t(unsafe.Sizeof(uintptr(0)))))
	r.param.vrfidx = C.uint64_t(vrf.Index())

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
	C.free(unsafe.Pointer(r.param.base.outputs))
	C.free(unsafe.Pointer(r.param))

	r.service = nil
	r.base = nil
	r.vifs = nil
	r.arpTable = nil
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
func (r *RouterInstance) updateRouteEntry(cmdType notifier.Type, idx uint64, route vswitch.Route) error {
	ones, _ := route.Dst.Mask.Size()
	if route.Dst.IP.To4() == nil {
		return errors.New("not supported ip address.")
	}
	re := RouteEntry{
		VRFIdx:    idx,
		Prefix:    uint32(ones),
		DestAddr:  route.Dst.IP,
		NextHop:   route.Gw,
		Interface: uint32(route.VIFIndex),
		Scope:     uint32(route.Scope),
		Metric:    uint32(route.Metrics),
	}

	var t routerCmd
	if cmdType == notifier.Add {
		t = ROUTER_CMD_ROUTE_ADD
	} else {
		t = ROUTER_CMD_ROUTE_DELETE
	}
	r.control(t, nil, re)
	return nil
}

func Ipv4ToHashkey(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		log.Printf("RI: ERROR: Invalid ip address\n")
		return 0
	}
	return binary.LittleEndian.Uint32(ip)
}

func (r *RouterInstance) updateArpEntry(cmdType notifier.Type, idx uint64, index vswitch.VIFIndex, arp vswitch.Neighbour) error {
	// convert net.IP to uint32 to use as hashmap key.
	key := Ipv4ToHashkey(arp.Dst)

	// create entry.
	ae := ArpEntry{
		VRFIdx:     idx,
		Interface:  uint32(index),
		IPAddress:  arp.Dst,
		MACAddress: arp.LinkLocalAddr,
	}

	// check if the entry exists.
	if entry := r.arpTable.Find(key); entry != nil {
		old := entry.Value.(*ArpEntry)
		if cmdType == notifier.Add {
			// entry information has been updated.
			if old.Interface == ae.Interface &&
				(bytes.Compare(old.MACAddress, ae.MACAddress) == 0) {
				// no change, nothing to do.
				//log.Printf("RI: [ARP: ADD] no changed.")
			} else {
				// changed, so update backend.
				log.Printf("RI: [ARP: UPDATE] changed and notify backend.")
				r.arpTable.Add(key, &ae)
				r.control(ROUTER_CMD_ARP_ADD, nil, ae)
			}
		} else if cmdType == notifier.Delete {
			// remove entry from hashmap n frontend.
			log.Printf("RI: [ARP: DELETE] delete and notify backend.")
			r.arpTable.Remove(key)
			r.control(ROUTER_CMD_ARP_DELETE, nil, ae)
		}
	}

	// add new entry.
	if cmdType == notifier.Add {
		log.Printf("RI: [ARP: ADD] add and notify backend.")
		r.arpTable.Add(key, &ae)
		r.control(ROUTER_CMD_ARP_ADD, nil, ae)
	}

	return nil
}

func (r *RouterInstance) updateInterfaceIpEntry(cmdType notifier.Type, idx uint64, vifindex uint32, ip vswitch.IPAddr) error {
	ie := InterfaceEntry{
		VRFIdx:    idx,
		VIFId:     vifindex,
		IPAddress: ip,
	}

	// update interface table.
	var t routerCmd
	if cmdType == notifier.Add {
		t = ROUTER_CMD_VIF_ADD_IP
	} else {
		t = ROUTER_CMD_VIF_DELETE_IP
	}
	r.control(t, nil, ie)

	return nil
}

// for control
type routerCmd int

const (
	ROUTER_CMD_CONFIG_RING_TAP    = routerCmd(C.ROUTER_CMD_CONFIG_RING_TAP)
	ROUTER_CMD_CONFIG_RING_HOSTIF = routerCmd(C.ROUTER_CMD_CONFIG_RING_HOSTIF)
	ROUTER_CMD_CONFIG_RING_IPIP   = routerCmd(C.ROUTER_CMD_CONFIG_RING_IPIP)
	ROUTER_CMD_CONFIG_RING_ESP    = routerCmd(C.ROUTER_CMD_CONFIG_RING_ESP)
	ROUTER_CMD_CONFIG_RING_GRE    = routerCmd(C.ROUTER_CMD_CONFIG_RING_GRE)
	ROUTER_CMD_VIF_ADD            = routerCmd(C.ROUTER_CMD_VIF_ADD)
	ROUTER_CMD_VIF_DELETE         = routerCmd(C.ROUTER_CMD_VIF_DELETE)
	ROUTER_CMD_VIF_ADD_IP         = routerCmd(C.ROUTER_CMD_VIF_ADD_IP)
	ROUTER_CMD_VIF_DELETE_IP      = routerCmd(C.ROUTER_CMD_VIF_DELETE_IP)
	ROUTER_CMD_ROUTE_ADD          = routerCmd(C.ROUTER_CMD_ROUTE_ADD)
	ROUTER_CMD_ROUTE_DELETE       = routerCmd(C.ROUTER_CMD_ROUTE_DELETE)
	ROUTER_CMD_ARP_ADD            = routerCmd(C.ROUTER_CMD_ARP_ADD)
	ROUTER_CMD_ARP_DELETE         = routerCmd(C.ROUTER_CMD_ARP_DELETE)
)

// static functions for control
func createEntry(cmd C.router_cmd_t, idx uint64) *C.struct_router_information {
	r := (*C.struct_router_information)(C.malloc(C.sizeof_struct_router_information))
	if r == nil {
		return nil
	}
	r.cmd = cmd
	r.vrfidx = C.uint64_t(idx)
	return r
}

func ipv4toCuint32(ip net.IP) C.uint32_t {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return C.uint32_t(binary.LittleEndian.Uint32(ip))
}

type macAddress [6]byte

func hardwareAddrToMacAddress(ha net.HardwareAddr) macAddress {
	var ma macAddress
	copy(ma[:], []byte(ha))
	return ma
}

func allocInterfaceEntry(cmd C.router_cmd_t, v InterfaceEntry) *C.struct_router_information {
	info := createEntry(cmd, v.VRFIdx)
	if info == nil {
		return nil
	}
	mac := hardwareAddrToMacAddress(v.MACAddress)
	macp := (*C.struct_ether_addr)(C.CBytes((mac)[:]))
	C.memcpy(unsafe.Pointer(&info.vif.mac), unsafe.Pointer(macp), C.sizeof_struct_ether_addr)
	info.vif.ifindex = C.uint32_t(v.VIFId)
	info.vif.mtu = C.uint16_t(v.MTU)
	info.vif.vid = C.uint16_t(v.VID)
	info.vif.tunnel = C.bool(v.Tunnel)
	return info
}

func allocInterfaceIPAddressEntry(cmd C.router_cmd_t, v InterfaceEntry) *C.struct_router_information {
	info := createEntry(cmd, v.VRFIdx)
	if info == nil {
		return nil
	}
	if v.IPAddress.IP.To4() == nil {
		return nil
	}
	info.addr.addr = ipv4toCuint32(v.IPAddress.IP)
	info.addr.ifindex = C.uint32_t(v.VIFId)
	plen, _ := v.IPAddress.Mask.Size()
	info.addr.prefixlen = C.uint32_t(plen)
	return info
}

func allocRouteEntry(cmd C.router_cmd_t, v RouteEntry) *C.struct_router_information {
	info := createEntry(cmd, v.VRFIdx)
	if info == nil {
		return nil
	}
	info.route.prefixlen = C.uint32_t(v.Prefix)
	info.route.network = C.uint32_t(v.Prefix)
	info.route.dst = ipv4toCuint32(v.DestAddr)
	info.route.gw = ipv4toCuint32(v.NextHop)
	info.route.ifindex = C.uint32_t(v.Interface)
	info.route.scope = C.uint32_t(v.Scope)
	info.route.metric = C.uint32_t(v.Metric)

	return info
}

func allocArpEntry(cmd C.router_cmd_t, v ArpEntry) *C.struct_router_information {
	info := createEntry(cmd, v.VRFIdx)
	if info == nil {
		return nil
	}
	mac := hardwareAddrToMacAddress(v.MACAddress)
	macp := (*C.struct_ether_addr)(C.CBytes((mac)[:]))
	C.memcpy(unsafe.Pointer(&info.arp.mac), unsafe.Pointer(macp), C.sizeof_struct_ether_addr)
	info.arp.ifindex = C.int(v.Interface)
	info.arp.ip = ipv4toCuint32(v.IPAddress)

	return info
}

func (r *RouterInstance) allocConfigRing(cmd C.router_cmd_t, ring *dpdk.Ring) *C.struct_router_information {
	info := createEntry(cmd, r.vrfidx)
	if info == nil {
		return nil
	}
	cring := (*C.struct_rte_ring)(unsafe.Pointer(ring))

	switch cmd {
	case C.ROUTER_CMD_CONFIG_RING_TAP:
		info.rings.tap = cring
	case C.ROUTER_CMD_CONFIG_RING_HOSTIF:
		info.rings.hostif = cring
	case C.ROUTER_CMD_CONFIG_RING_IPIP:
		info.rings.ipip = cring
	case C.ROUTER_CMD_CONFIG_RING_ESP:
		info.rings.esp = cring
	case C.ROUTER_CMD_CONFIG_RING_GRE:
		info.rings.gre = cring
	}

	return info
}

//-----

func (r *RouterInstance) control(cmd routerCmd, ring *dpdk.Ring, v interface{}) error {
	log.Printf("RS: control: cmd: %v, ring: %p\n", cmd, ring)
	p := C.struct_router_control_param{
		cmd:  C.router_cmd_t(cmd),
		ring: (*C.struct_rte_ring)(unsafe.Pointer(ring)),
	}
	switch cmd {
	case ROUTER_CMD_CONFIG_RING_TAP:
		p.info = r.allocConfigRing(C.ROUTER_CMD_CONFIG_RING_TAP, ring)
	case ROUTER_CMD_CONFIG_RING_HOSTIF:
		p.info = r.allocConfigRing(C.ROUTER_CMD_CONFIG_RING_HOSTIF, ring)
	case ROUTER_CMD_CONFIG_RING_IPIP:
		p.info = r.allocConfigRing(C.ROUTER_CMD_CONFIG_RING_IPIP, ring)
	case ROUTER_CMD_CONFIG_RING_ESP:
		p.info = r.allocConfigRing(C.ROUTER_CMD_CONFIG_RING_ESP, ring)
	case ROUTER_CMD_CONFIG_RING_GRE:
		p.info = r.allocConfigRing(C.ROUTER_CMD_CONFIG_RING_GRE, ring)
	case ROUTER_CMD_VIF_ADD:
		// add interface entry to interface table.
		ie, ok := v.(InterfaceEntry)
		if !ok {
			return fmt.Errorf("Invalid parameter v = %v", v)
		}
		p.info = allocInterfaceEntry(C.ROUTER_CMD_VIF_ADD, ie)
	case ROUTER_CMD_VIF_DELETE:
		// delete interface entry to interface table.
		ie, ok := v.(InterfaceEntry)
		if !ok {
			return fmt.Errorf("Invalid parameter v = %v", v)
		}
		p.info = allocInterfaceEntry(C.ROUTER_CMD_VIF_DELETE, ie)
	case ROUTER_CMD_VIF_ADD_IP:
		ie, ok := v.(InterfaceEntry)
		if !ok {
			return fmt.Errorf("Invalid parameter v = %v", v)
		}
		p.info = allocInterfaceIPAddressEntry(C.ROUTER_CMD_VIF_ADD_IP, ie)
	case ROUTER_CMD_VIF_DELETE_IP:
		ie, ok := v.(InterfaceEntry)
		if !ok {
			return fmt.Errorf("Invalid parameter v = %v", v)
		}
		p.info = allocInterfaceIPAddressEntry(C.ROUTER_CMD_VIF_DELETE_IP, ie)
	case ROUTER_CMD_ROUTE_ADD:
		// add route entry to routing table.
		re, ok := v.(RouteEntry)
		if !ok {
			return fmt.Errorf("Invalid parameter v = %v", v)
		}
		p.info = allocRouteEntry(C.ROUTER_CMD_ROUTE_ADD, re)
	case ROUTER_CMD_ROUTE_DELETE:
		// delete route entry from routing table.
		re, ok := v.(RouteEntry)
		if !ok {
			return fmt.Errorf("Invalid parameter v = %v", v)
		}
		p.info = allocRouteEntry(C.ROUTER_CMD_ROUTE_DELETE, re)
	case ROUTER_CMD_ARP_ADD:
		ae, ok := v.(ArpEntry)
		if !ok {
			return fmt.Errorf("Invalid parameter v = %v", v)
		}
		p.info = allocArpEntry(C.ROUTER_CMD_ARP_ADD, ae)
	case ROUTER_CMD_ARP_DELETE:
		ae, ok := v.(ArpEntry)
		if !ok {
			return fmt.Errorf("Invalid parameter v = %v", v)
		}
		p.info = allocArpEntry(C.ROUTER_CMD_ARP_DELETE, ae)
	}
	if p.info == nil {
		return fmt.Errorf("Control entry allocation failed(v = %v).\n", v)
	}

	rc, err := r.instance.Control(unsafe.Pointer(&p))
	if rc == false || err != nil {
		return fmt.Errorf("%v Failed: %v", cmd, err)
	}
	return nil
}

// configuration apis.
func (r *RouterInstance) AddVIF(vif *vswitch.VIF) error {
	log.Printf("AddVIF: %v, %v", vif, r.vifs[vif.Index()])
	if r.vifs[vif.Index()] == nil {
		r.vifs[vif.Index()] = vif.Input()

		// add vif
		tunnel := false
		if vif.Tunnel() != nil {
			tunnel = true
		}
		ie := InterfaceEntry{
			VRFIdx:     uint64(vif.VRF().Index()),
			VIFId:      uint32(vif.Index()),
			VID:        uint16(vif.VID()),
			MACAddress: vif.MACAddress(),
			MTU:        uint16(vif.MTU()),
			Tunnel:     tunnel,
		}
		log.Printf("CALL ROUTER_CMD_VIF_ADD")
		r.control(ROUTER_CMD_VIF_ADD, vif.Input(), ie)
	}

	// add ip addresses
	ips := vif.ListIPAddrs()
	for _, ip := range ips {
		ie := InterfaceEntry{
			VIFId:     uint32(vif.Index()),
			IPAddress: ip,
		}
		r.control(ROUTER_CMD_VIF_ADD_IP, vif.Input(), ie)
	}
	return nil
}

func (r *RouterInstance) DeleteVIF(vif *vswitch.VIF) error {
	// TODO: config agent not supported.
	log.Printf("DeleteVIF: %v", vif)
	ips := vif.ListIPAddrs()
	for i := range ips {
		ie := InterfaceEntry{
			VIFId:     uint32(vif.Index()),
			IPAddress: ips[i],
		}
		r.control(ROUTER_CMD_VIF_DELETE_IP, vif.Input(), ie)
	}
	delete(r.vifs, vif.Index())
	return r.control(ROUTER_CMD_VIF_DELETE, nil, vif)
}

func init() {
	rp := &vswitch.RingParam{
		Count:    C.MAX_ROUTER_MBUFS,
		SocketId: dpdk.SOCKET_ID_ANY,
	}

	if err := vswitch.RegisterModule(moduleName, newRouterInstance, rp, vswitch.TypeRouter); err != nil {
		log.Fatalf("Failed to register the class.")
	}
}
