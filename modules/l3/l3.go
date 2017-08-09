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

package l3

/*
#cgo CFLAGS: -I${SRCDIR}/../../include -I/usr/local/include/dpdk -m64 -pthread -O3 -msse4.2
#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all -L/usr/local/lib -ldpdk

#include "l3.h"

*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/hashlist"
	"github.com/lagopus/vsw/utils/notifier"
	"github.com/lagopus/vsw/utils/ringpair"
	"github.com/lagopus/vsw/vswitch"
	"net"
	"runtime"
	"sync"
	"unsafe"
)

type L3Module struct {
	vswitch.ModuleService
	l3Mgr    *l3Manager
	arpTable *hashlist.HashList
}

/*
 * Each informations are managed by VRF.
 */
// for management MAC address of the interface(vif).
type InterfaceEntry struct {
	VrfRd      uint64
	VifId      uint32
	MacAddress net.HardwareAddr
	Error      int
}

// for management IP address of the interface(vif).
type InterfaceIpEntry struct {
	VrfRd            uint64
	VifId            uint32
	IpAddress        vswitch.IPAddr
	BroadcastAddress net.IP
}

// route entry for routing table.
type RouteEntry struct {
	VrfRd     uint64 // VRF ID
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
	VrfRd      uint64 // VRF ID
	Interface  uint32
	IpAddress  net.IP
	MacAddress net.HardwareAddr
}

// internal purpose only
var log = vswitch.Logger

// Backend Manager
type l3Manager struct {
	refcount      uint
	request       chan *C.struct_l3_request // Go -> C
	control       chan l3MgrCmd             // Modules -> Frontend (Lifecycle)
	done          chan struct{}
	terminate     chan struct{}
	stopReceiving chan struct{}
	slaveId       uint
	rp            *ringpair.RingPair
	vrfs          map[uint64]*L3Module
	vswch         chan notifier.Notification
}

type l3MgrCmd int

const (
	L3MGR_START l3MgrCmd = iota
	L3MGR_STOP
	L3MGR_REF
	L3MGR_UNREF
)

// --- l3 module manager --- //

func initL3Manager() *l3Manager {
	// reserve slave core
	coreid, err := vswitch.GetDpdkResource().AllocLcore()
	if err != nil {
		return nil
	}

	// create a pair of rings for C/Go communication
	rp := ringpair.Create(&ringpair.Config{
		Prefix: "l3",
		Counts: [2]uint{
			C.MAX_L3_REQUESTS, // Go Frontend -> C Backend
		},
		SocketID: dpdk.SOCKET_ID_ANY,
	})
	if rp == nil {
		return nil
	}

	// start backend
	log.Printf("l3: Starting backend task on Slave Core %d\n", coreid)
	p := (*C.struct_l3_launch_param)(C.malloc(C.sizeof_struct_l3_launch_param))
	p.name = C.CString("L3")
	p.request = unsafe.Pointer(rp.Rings[0])
	dpdk.EalRemoteLaunch((dpdk.LcoreFunc)(C.l3_task), unsafe.Pointer(p), coreid)

	// instantiate l3Manager
	mgr := &l3Manager{
		request:       make(chan *C.struct_l3_request),
		control:       make(chan l3MgrCmd),
		terminate:     make(chan struct{}),
		done:          make(chan struct{}),
		stopReceiving: make(chan struct{}),
		slaveId:       coreid,
		rp:            rp,
		vrfs:          make(map[uint64]*L3Module),
		vswch:         vswitch.GetNotifier().Listen(),
	}

	// start frontend task
	go mgr.doControl()
	go mgr.doRequest()
	go mgr.doL3Task()

	// yield before we leave
	runtime.Gosched()

	// listen notifications from vswitch.
	go func() {
		mgr.listen()
	}()

	return mgr
}

//
// Control Related
//
func (mgr *l3Manager) doControl() {
	log.Print("L3 manager controller started.")
	for c := range mgr.control {
		switch c {
		case L3MGR_REF:
			mgr.refcount++
			log.Printf("L3: Ref backend (%d).", mgr.refcount)
		case L3MGR_UNREF:
			mgr.refcount--
			log.Printf("L3: Unref backend (%d).", mgr.refcount)
			if mgr.refcount == 0 {
				mgr.terminate <- struct{}{}
				return
			}
		}
	}
}

func (mgr *l3Manager) refBackend() {
	mgr.control <- L3MGR_REF
}

func (mgr *l3Manager) unrefBackend() {
	mgr.control <- L3MGR_UNREF
}

// Terminate backend
func (mgr *l3Manager) doTerminate() {
	r := (*C.struct_l3_request)(C.malloc(C.sizeof_struct_l3_request))
	r.cmd = C.L3_CMD_QUIT
	mgr.request <- r
	close(mgr.request)

	dpdk.EalWaitLcore(mgr.slaveId)
	vswitch.GetDpdkResource().FreeLcore(mgr.slaveId)
	mgr.rp.Free()

	close(mgr.done)
	return
}

// Wait for backend to terminate
func (mgr *l3Manager) waitBackend() {
	log.Printf("L3: Waiting backend to terminate")
	<-mgr.done
	log.Printf("L3: Backend terminated")
}

//
// Requesting Backend Related
//
func (mgr *l3Manager) doRequest() {
	log.Printf("L3 Manager started.")
	ring := mgr.rp.Rings[0]
	for req := range mgr.request {
		ring.Enqueue(unsafe.Pointer(req))
	}
}

//
// L3 Tasks
//
func (mgr *l3Manager) doL3Task() {
	for {
		select {
		case <-mgr.terminate:
			mgr.doTerminate()
			return
		}
	}
}

// Singleton
var instance *l3Manager
var once sync.Once
var stop_once sync.Once

func getL3Manager() *l3Manager {
	once.Do(func() {
		instance = initL3Manager()
	})
	return instance
}

// Factory function
func newL3Module(p *vswitch.ModuleParam) (vswitch.Module, error) {
	mgr := getL3Manager()
	if mgr == nil {
		return nil, errors.New("Can't start L3 Manager")
	}
	mgr.refBackend()

	// create a module
	l3m := &L3Module{
		ModuleService: vswitch.NewModuleService(p),
		l3Mgr:         mgr,
		arpTable:      hashlist.New(),
	}

	vrfrd := l3m.Vrf().VrfRD()
	mgr.vrfs[vrfrd] = l3m

	// register new l3 instance to backend
	l3m.registerL3()

	return l3m, nil
}

// --- for Request --- //
func (l3m *L3Module) createRequest(cmd C.l3_cmd_t, vrfrd uint64) *C.struct_l3_request {
	r := (*C.struct_l3_request)(C.malloc(C.sizeof_struct_l3_request))
	if r == nil {
		return nil
	}
	r.cmd = cmd
	r.vrfrd = C.uint64_t(vrfrd)
	return r
}

// Register the l3 instance
func (l3m *L3Module) registerL3() {
	r := l3m.createRequest(C.L3_CMD_CREATE, l3m.Vrf().VrfRD())
	l3m.l3Mgr.request <- r
}

// Unregister the l3 instance
func (l3m *L3Module) unregisterL3() {
	r := l3m.createRequest(C.L3_CMD_DESTROY, l3m.Vrf().VrfRD())
	l3m.l3Mgr.request <- r
}

// Enable L3
func (l3m *L3Module) enableL3() {
	log.Printf("%s: enable.", l3m.Name())

	r := l3m.createRequest(C.L3_CMD_ENABLE, l3m.Vrf().VrfRD())
	l3m.l3Mgr.request <- r
}

// Disable L3
func (l3m *L3Module) disableL3() {
	log.Printf("%s: disable.", l3m.Name())

	r := l3m.createRequest(C.L3_CMD_DISABLE, l3m.Vrf().VrfRD())
	l3m.l3Mgr.request <- r
}

// configure rings
func (l3m *L3Module) configureRing() {
	log.Printf("%s: configure ring .", l3m.Name())

	r := l3m.createRequest(C.L3_CMD_CONFIG_RING, l3m.Vrf().VrfRD())
	// set input ring
	r.ring.input = (*C.struct_rte_ring)(unsafe.Pointer(l3m.Input()))
	// set output ring for bridge module.
	for _, rule := range l3m.Rules().SubRules(vswitch.MATCH_BRIDGE_ID) {
		r.ring.output[rule.Param[0]] =
			(*C.struct_rte_ring)(unsafe.Pointer(rule.Ring))
	}
	// set output ring for tap module.
	dest_self := l3m.Rules().Output(vswitch.MATCH_IPV4_DST_SELF)
	r.ring.tap = (*C.struct_rte_ring)(unsafe.Pointer(dest_self))
	// set output ring for hostif module.
	hostif := l3m.Rules().Output(vswitch.MATCH_IPV4_DST)
	r.ring.hostif = (*C.struct_rte_ring)(unsafe.Pointer(hostif))

	l3m.l3Mgr.request <- r
}

// -- for netlink notification --- //
func ipv4toCinaddr(ip net.IP) C.in_addr_t {
	//TODO: pass a pointer of struct in_addr instead of uint32 to backend.
	//      don't use LittleEndian.
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return C.in_addr_t(binary.LittleEndian.Uint32(ip))
}

func ipv4Broadcast(ip vswitch.IPAddr) net.IP {
	ipv4 := ip.IP.To4()
	if ipv4 == nil {
		return nil
	}
	mask := ip.Mask
	broad := make([]byte, 4)
	for i := range ipv4 {
		broad[i] = ipv4[i] | ^mask[i]
	}
	return broad
}

type macAddress [6]byte

func hardwareAddrToMacAddress(ha net.HardwareAddr) macAddress {
	var ma macAddress
	copy(ma[:], []byte(ha))
	return ma
}

/*
 * Allocation request messages.
 */
func (l3m *L3Module) allocInterfaceRequest(v InterfaceEntry, cmd C.l3_cmd_t) {
	r := l3m.createRequest(cmd, v.VrfRd)
	if r == nil {
		return
	}
	r.vif.ifindex = C.uint32_t(v.VifId)
	mac := hardwareAddrToMacAddress(v.MacAddress)
	r.vif.mac = (*C.struct_ether_addr)(C.CBytes((mac)[:]))
	l3m.l3Mgr.request <- r
}

func (l3m *L3Module) allocInterfaceIpRequest(v InterfaceIpEntry, cmd C.l3_cmd_t) {
	b := ipv4Broadcast(v.IpAddress)
	if b == nil {
		return
	}
	r := l3m.createRequest(cmd, v.VrfRd)
	if r == nil {
		return
	}
	r.vif.ifindex = C.uint32_t(v.VifId)
	r.vif.ip.s_addr = ipv4toCinaddr(v.IpAddress.IP)
	r.vif.broad.s_addr = ipv4toCinaddr(b)
	l3m.l3Mgr.request <- r
}

func (l3m *L3Module) allocRouteRequest(v RouteEntry, cmd C.l3_cmd_t) {
	r := l3m.createRequest(cmd, v.VrfRd)
	if r == nil {
		return
	}
	r.route.bridgeid = C.uint32_t(v.BridgeId)
	r.route.prefixlen = C.uint32_t(v.Prefix)
	r.route.dest.s_addr = ipv4toCinaddr(v.DestAddr)
	r.route.gate.s_addr = ipv4toCinaddr(v.NextHop)
	r.route.ifindex = C.uint32_t(v.Interface)
	r.route.scope = C.uint32_t(v.Scope)
	r.route.metric = C.uint32_t(v.Metric)
	l3m.l3Mgr.request <- r
}

func (l3m *L3Module) allocArpRequest(v ArpEntry, cmd C.l3_cmd_t) {
	r := l3m.createRequest(cmd, v.VrfRd)
	if r == nil {
		return
	}
	r.arp.ifindex = C.uint32_t(v.Interface)
	r.arp.ip.s_addr = ipv4toCinaddr(v.IpAddress)
	mac := hardwareAddrToMacAddress(v.MacAddress)
	r.arp.mac = (*C.struct_ether_addr)(C.CBytes((mac)[:]))
	l3m.l3Mgr.request <- r
}

func (l3m *L3Module) Control(cmd string, v interface{}) interface{} {
	switch cmd {
	case "ROUTE_ADD":
		re, ok := v.(RouteEntry)
		if !ok {
			log.Printf("%s: Invalid parameter: %v\n", l3m.Name(), v)
			return false
		}
		l3m.allocRouteRequest(re, C.L3_CMD_ROUTE_ADD)
		return true
	case "ROUTE_DELETE":
		re, ok := v.(RouteEntry)
		if !ok {
			log.Printf("%s: Invalid parameter: %v\n", l3m.Name(), v)
			return false
		}
		l3m.allocRouteRequest(re, C.L3_CMD_ROUTE_DELETE)
		return true
	case "ARP_ADD":
		ae, ok := v.(ArpEntry)
		if !ok {
			log.Printf("%s: Invalid parameter: %v\n", l3m.Name(), v)
			return false
		}
		l3m.allocArpRequest(ae, C.L3_CMD_ARP_ADD)
		return true
	case "ARP_DELETE":
		ae, ok := v.(ArpEntry)
		if !ok {
			log.Printf("%s: Invalid parameter: %v\n", l3m.Name(), v)
			return false
		}
		l3m.allocArpRequest(ae, C.L3_CMD_ARP_DELETE)
		return true
	case "INTERFACE_ADD":
		ie, ok := v.(InterfaceEntry)
		if !ok {
			log.Printf("%s: Invalid parameter: %v\n", l3m.Name(), v)
			return false
		}
		l3m.allocInterfaceRequest(ie, C.L3_CMD_INTERFACE_ADD)
		return true
	case "INTERFACE_DELETE":
		ie, ok := v.(InterfaceEntry)
		if !ok {
			log.Printf("%s: Invalid parameter: %v\n", l3m.Name(), v)
			return false
		}
		l3m.allocInterfaceRequest(ie, C.L3_CMD_INTERFACE_DELETE)
		return true
	case "INTERFACE_IP_ADD":
		ie, ok := v.(InterfaceIpEntry)
		if !ok {
			log.Printf("%s: Invalid parameter: %v\n", l3m.Name(), v)
			return false
		}
		l3m.allocInterfaceIpRequest(ie, C.L3_CMD_INTERFACE_IP_ADD)
		return true
	case "INTERFACE_IP_DELETE":
		ie, ok := v.(InterfaceIpEntry)
		if !ok {
			log.Printf("%s: Invalid parameter: %v\n", l3m.Name(), v)
			return false
		}
		l3m.allocInterfaceIpRequest(ie, C.L3_CMD_INTERFACE_IP_DELETE)
		return true
	case "INTERFACE_HOSTIF_IP_ADD":
		ie, ok := v.(InterfaceIpEntry)
		if !ok {
			log.Printf("%s: Invalid parameter: %v\n", l3m.Name(), v)
			return false
		}
		l3m.allocInterfaceIpRequest(ie, C.L3_CMD_INTERFACE_HOSTIF_IP_ADD)
		return true
	case "INTERFACE_HOSTIF_IP_DELETE":
		ie, ok := v.(InterfaceIpEntry)
		if !ok {
			log.Printf("%s: Invalid parameter: %v\n", l3m.Name(), v)
			return false
		}
		l3m.allocInterfaceIpRequest(ie, C.L3_CMD_INTERFACE_HOSTIF_IP_DELETE)
		return true
	default:
		log.Printf("%s: Unknown control: %s.\n", l3m.Name(), cmd)
	}
	return false
}

func Ipv4ToHashkey(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		log.Printf("l3: ERROR: Invalid ip address\n")
		return 0
	}
	return binary.LittleEndian.Uint32(ip)
}

func updateArpEntry(l3m *L3Module, cmd_type notifier.Type, ae ArpEntry) {
	// conver net.IP to uint32 to use as hashmap key.
	key := Ipv4ToHashkey(ae.IpAddress)

	// check if the entry exists.
	if entry := l3m.arpTable.Find(key); entry != nil {
		oldEntry := entry.Value.(*ArpEntry)
		if cmd_type == notifier.Update {
			// entry information has been updated.
			if oldEntry.Interface == ae.Interface &&
				(bytes.Compare(oldEntry.MacAddress, ae.MacAddress) == 0) {
				// no change, nothing to do.
				log.Printf("L3: [ARP: UPDATE] no changed.")
			} else {
				// changed, so update backend.
				log.Printf("L3: [ARP: UPDATE] changed, notify backend.")
				l3m.arpTable.Add(key, &ae)
				l3m.Control("ARP_ADD", ae)
			}
		} else if cmd_type == notifier.Delete {
			// remove entry from hashmap in frontend.
			log.Printf("L3: [ARP: DELETE] delete, notify backend.")
			l3m.arpTable.Remove(key)
			l3m.Control("ARP_DELETE", ae)
		}
	}

	// add new entry.
	if cmd_type == notifier.Add {
		log.Printf("L3: [ARP: ADD] add, notify backend.")
		l3m.arpTable.Add(key, &ae)
		l3m.Control("ARP_ADD", ae)
	}

}

func updateRouteEntry(l3m *L3Module, cmd_type notifier.Type, re RouteEntry) {
	if cmd_type == notifier.Add {
		// add route entry.
		l3m.Control("ROUTE_ADD", re)
	} else if cmd_type == notifier.Update {
		// update route entry.
		l3m.Control("ROUTE_ADD", re)
	} else if cmd_type == notifier.Delete {
		// delete route entry.
		l3m.Control("ROUTE_DELETE", re)
	}
}

// Receive informations from netlink.
func (mgr *l3Manager) listen() {
	for {

		select {
		case noti, ok := <-mgr.vswch:
			if !ok {
				return
			}

			if vif, ok := noti.Target.(*vswitch.VifInfo); ok {
				vrfrd := vif.Vrf().VrfRD()
				l3mod := mgr.vrfs[vrfrd]
				if l3mod == nil {
					continue
				}

				switch value := noti.Value.(type) {
				case nil:
					// TODO: delete VIF, delete interface info.

				case net.HardwareAddr:
					// TODO: update mac address of self interface.
					if noti.Type == notifier.Update {
					}
				case vswitch.IPAddr:
					if noti.Type == notifier.Add {
						// TODO: add ip address of self interface.
					} else if noti.Type == notifier.Update {
						// TODO: update ip address of self interface.
					} else {
						// TODO: delete ip address of self interface.
					}
				case vswitch.Neighbour:
					ae := ArpEntry{
						VrfRd:      vrfrd,
						Interface:  uint32(vif.VifIndex()),
						IpAddress:  value.Dst,
						MacAddress: value.LinkLocalAddr,
					}
					updateArpEntry(l3mod, noti.Type, ae)
				case vswitch.LinkStatus:
					// nothing to do.
				default:
					log.Printf("L3MGR(%s): Unexpected value: %v\n", l3mod.Name(), vif)
				}

			} else if vrf, ok := noti.Target.(*vswitch.VrfInfo); ok {
				vrfrd := vrf.VrfRD()
				l3mod := mgr.vrfs[vrfrd]
				if l3mod == nil {
					continue
				}

				switch vif := noti.Value.(type) {
				case nil:
					// TODO: VRF created, nothing to do.

				case vswitch.Route:
					ones, _ := vif.Dst.Mask.Size()
					if vif.Dst.IP.To4() == nil {
						break
					}
					re := RouteEntry{
						VrfRd:     vrfrd,
						BridgeId:  uint32(vif.VifIndex), // TODO
						Prefix:    uint32(ones),
						DestAddr:  vif.Dst.IP,
						NextHop:   vif.Gw,
						Interface: uint32(vif.VifIndex),
						Scope:     uint32(vif.Scope),
						Metric:    uint32(vif.Metrics),
					}
					updateRouteEntry(l3mod, noti.Type, re)

				default:
					log.Printf("L3MGR(%s): not supported vif: vif = %v",
						l3mod.Name(), vif)
				}
			} else {
				log.Printf("L3MGR: not supported target: %v\n", noti.Target)
			}
		default:
			// not supported.
		}
	}
}

func notifyInterfaceInfo(l3m *L3Module) {
	// get all vif belonging in vrf
	vifs := l3m.Vrf().VIFs()
	for _, vif := range vifs {
		vifinfo := vswitch.GetVifInfo(vif)

		log.Printf("%s: interface request (vrf rd: %v, vif id: %v)\n",
			l3m.Name(), l3m.Vrf().VrfRD(), vif)
		// set mac address to if table
		mac := InterfaceEntry{
			VrfRd:      l3m.Vrf().VrfRD(),
			VifId:      uint32(vif),
			MacAddress: vifinfo.MacAddress(),
		}
		l3m.allocInterfaceRequest(mac, C.L3_CMD_INTERFACE_ADD)
		ipv4s := vifinfo.ListIPAddrs()
		for _, ipv4 := range ipv4s {
			if ipv4.IP.To4() == nil {
				continue
			}
			// set ip address and broadcast address to if table
			ip := InterfaceIpEntry{
				VrfRd:     l3m.Vrf().VrfRD(),
				VifId:     uint32(vif),
				IpAddress: ipv4,
			}
			l3m.allocInterfaceIpRequest(ip, C.L3_CMD_INTERFACE_IP_ADD)
		}

	}
}

func (l3m *L3Module) Start() bool {
	log.Printf("%s: Start().", l3m.Name())

	// Tell backend which rings to use for inputs and default output.
	l3m.configureRing()

	// set interface infomation from vif
	notifyInterfaceInfo(l3m)

	// Activate this bridge domain
	l3m.enableL3()

	return true
}

func (l3m *L3Module) Stop() {
	log.Printf("%s: Stop().", l3m.Name())
	stop_once.Do(func() {
		// for check terminated in listen().
		vswitch.GetNotifier().Close(l3m.l3Mgr.vswch)
	})

	l3m.disableL3()
	l3m.l3Mgr.unrefBackend()
}

func (l3m *L3Module) Wait() {
	log.Printf("%s: Wait().", l3m.Name())
	l3m.l3Mgr.waitBackend()
}

func init() {
	rp := &vswitch.RingParam{
		Count:    C.MAX_L3_MBUFS,
		SocketId: dpdk.SOCKET_ID_ANY,
		Flags:    0,
	}

	if !vswitch.RegisterModule("l3", newL3Module, rp, vswitch.TypeOther) {
		log.Fatalf("Failed to register the module.")
	}
}
