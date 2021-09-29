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
#include <rte_mbuf.h>
#include "packet.h"
#include "neighbor.h"
*/
import "C"

import (
	"sync"
	"time"
	"unsafe"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/vswitch"
)

// ARP resolustion configs
// TODO: make it configurable via TOML
const (
	ARPMaxTries = 5       // Try ARPMaxTries before giving up resolution
	ARPKeep     = 20 * 60 // Keep ARP cache for ARPKeep seconds
)

// ring buffer size between C backend and Go frontend
const arpRingSize = 256

type arpRequest struct {
	resolver *arpResolver
	target   vswitch.IPv4Addr
	vif      vswitch.VIFIndex
}

type arpStatus struct {
	requested int
	valid     bool
	etherAddr vswitch.EtherAddr
	neigh     *C.struct_neighbor
	mutex     sync.Mutex
}

func (as *arpStatus) isValid() bool {
	as.mutex.Lock()
	defer as.mutex.Unlock()
	return as.valid
}

func (as *arpStatus) validate() {
	as.mutex.Lock()
	defer as.mutex.Unlock()
	as.valid = true
}

type ipaddr struct {
	addr vswitch.IPv4Addr
	mask vswitch.IPv4Addr
}

type arpVIF struct {
	mutex    sync.Mutex
	vif      *vswitch.VIF
	outbound *dpdk.Ring
	status   map[vswitch.IPv4Addr]*arpStatus
	hwAddr   vswitch.EtherAddr
	addrs    []ipaddr
}

func newArpVIF(vif *vswitch.VIF) *arpVIF {
	a := &arpVIF{
		vif:      vif,
		outbound: vif.Outbound(),
		hwAddr:   vswitch.NewEtherAddr(vif.MACAddress()),
		status:   make(map[vswitch.IPv4Addr]*arpStatus),
	}
	a.updateIPAddrs()
	return a
}

func (a *arpVIF) updateIPAddrs() {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.addrs = nil
	for _, i := range a.vif.ListIPAddrs() {
		ipv4 := i.IP.To4()
		if ipv4 == nil {
			continue
		}

		var addr, mask vswitch.IPv4Addr
		for _, b := range ipv4 {
			addr = (addr << 8) | vswitch.IPv4Addr(b)
		}
		for _, b := range i.Mask {
			mask = (addr << 8) | vswitch.IPv4Addr(b)
		}

		a.addrs = append(a.addrs, ipaddr{addr, mask})
	}
}

func (a *arpVIF) isTargetAddress(addr vswitch.IPv4Addr) (target bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	for _, ipaddr := range a.addrs {
		if ipaddr.addr == addr {
			target = true
			return
		}
	}
	return
}

func (a *arpVIF) getCompatibleSenderAddr(target vswitch.IPv4Addr) vswitch.IPv4Addr {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	for _, s := range a.addrs {
		if ((s.addr ^ target) & s.mask) == 0 {
			return s.addr
		}
	}
	return 0
}

// newARPStatus returns new arpStatus for the target.
// If there's already one created, it returns the existing
// instance.
func (a *arpVIF) newARPStatus(target vswitch.IPv4Addr) *arpStatus {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	status, found := a.status[target]
	if !found {
		status = &arpStatus{}
		a.status[target] = status
	}
	return status
}

// getARPStatus returns arpStatus for the target.
func (a *arpVIF) getARPStatus(target vswitch.IPv4Addr) *arpStatus {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	return a.status[target]
}

func (a *arpVIF) deleteARPStatus(target vswitch.IPv4Addr) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	delete(a.status, target)
}

func (a *arpVIF) doARPRequest(req *arpRequest) {
	status := a.newARPStatus(req.target)
	status.requested = 0
	arp := vswitch.NewARPRequest(req.target, a.getCompatibleSenderAddr(req.target), a.hwAddr)

	for {
		// create ARP request
		arpRequest := mempool.AllocMbuf()
		arpRequest.SetData(arp.Encode())
		arpRequest.SetVlanTCI(uint16(a.vif.VID()))

		// enqueue ARP request
		retryCount := 0
		enqueued := (a.outbound.EnqueueMbuf(arpRequest) == 0)
		for !enqueued && retryCount < 5 {
			time.Sleep(1)
			enqueued = (a.outbound.EnqueueMbuf(arpRequest) == 0)
			retryCount++
		}

		if !enqueued {
			log.Err("Enqueue ARP request to VIF %d failed", req.vif)
			arpRequest.Free()
		}
		status.requested++

		// wait for a second.
		time.Sleep(time.Second)

		// resolved successivley
		if status.isValid() {
			time.AfterFunc(ARPKeep*time.Second, func() {
				if status.neigh.used {
					a.doARPRequest(req)
				} else {
					req.resolver.deleteNeighborCache(req.vif, req.target)
					a.deleteARPStatus(req.target)
				}
			})
			return
		}

		if status.requested > ARPMaxTries {
			log.Info("No ARP Reply from %v", req.target)
			req.resolver.deleteNeighborCache(req.vif, req.target)
			a.deleteARPStatus(req.target)
			return
		}
	}
}

type arpResolver struct {
	router *RouterInstance
	reqCh  chan *arpRequest
	arpCh  chan *C.struct_rte_mbuf
	vifs   map[vswitch.VIFIndex]*arpVIF
	mutex  sync.Mutex
	quit   chan int
	done   chan int
}

var arpResolvers = make(map[vswitch.VRFIndex]*arpResolver)

func newARPResolver(ri *RouterInstance) (ar *arpResolver) {
	ar = &arpResolver{
		router: ri,
		reqCh:  make(chan *arpRequest),
		arpCh:  make(chan *C.struct_rte_mbuf, C.ROUTER_MAX_MBUFS),
		vifs:   make(map[vswitch.VIFIndex]*arpVIF),
		done:   make(chan int),
	}
	arpResolvers[ri.vrfidx] = ar
	return ar
}

func (ar *arpResolver) getArpVIF(index vswitch.VIFIndex) *arpVIF {
	ar.mutex.Lock()
	defer ar.mutex.Unlock()

	return ar.vifs[index]
}

func (ar *arpResolver) addVIF(vif *vswitch.VIF) {
	ar.mutex.Lock()
	defer ar.mutex.Unlock()

	ar.vifs[vif.Index()] = newArpVIF(vif)
}

func (ar *arpResolver) deleteVIF(vif *vswitch.VIF) {
	ar.mutex.Lock()
	defer ar.mutex.Unlock()

	delete(ar.vifs, vif.Index())
}

func (ar *arpResolver) updateIPAddr(index vswitch.VIFIndex) {
	if vif := ar.getArpVIF(index); vif != nil {
		vif.updateIPAddrs()
	}
}

// resolve resolves MAC address.
func (ar *arpResolver) resolve(req *arpRequest) {
	vif := ar.getArpVIF(req.vif)
	if vif == nil {
		log.Err("ARP requested on unknown VIF %d (target: %v)", req.vif, req.target)
		return
	}

	go vif.doARPRequest(req)
}

// findNeighborCache find struct neighbor corresponding to this neighbor.
// Later we'll use this to check, if the entry has been used or not.
func (ar *arpResolver) findNeighborCache(vif *vswitch.VIF, target vswitch.IPv4Addr, status *arpStatus) {
	nc := ar.router.getNeighborCache(vif)
	if nc == nil {
		log.Info("No neighbor cache: %v is deleted.", vif)
		return
	}
	for i, cache := range nc {
		if vswitch.IPv4Addr(cache.addr) == target {
			status.neigh = &ar.router.neighborCaches[vif][i]
			return
		}
	}
	log.Err("Can't find neighbor cache for %v", target)
}

// input processes incoming ARP packet.
//
// ARP reply should be handled here. But anyway all ARP
// request should be forwarded to the kernel via TAP for now.
func (ar *arpResolver) input(mbuf *dpdk.Mbuf) {
	packet := mbuf.Data()
	arp, err := vswitch.ARPParse(packet)
	if err != nil {
		log.Warning("Parsing ARP packet failed: %v", err)
		return
	}

	metadata := (*vswitch.Metadata)(mbuf.Metadata())
	vifindex := metadata.InVIF()
	vif := ar.getArpVIF(vifindex)
	if vif == nil {
		log.Warning("VIF (Index: %d) correspoding to ARP not found", vifindex)
		return
	}

	//
	// Packet Reception from RFC 826
	//
	// ?Do I have the hardware type in ar$hrd?
	// Yes: (almost definitely)
	//   [optionally check the hardware length ar$hln]
	//   ?Do I speak the protocol in ar$pro?
	//   Yes:
	//     [optionally check the protocol length ar$pln]
	//     Merge_flag := false
	//     If the pair <protocol type, sender protocol address> is
	//         already in my translation table, update the sender
	//         hardware address field of the entry with the new
	//         information in the packet and set Merge_flag to true.
	//     ?Am I the target protocol address?
	//     Yes:
	//       If Merge_flag is false, add the triplet <protocol type,
	//           sender protocol address, sender hardware address> to
	//           the translation table.
	//       ?Is the opcode ares_op$REQUEST?  (NOW look at the opcode!!)
	//       Yes:
	//         Swap hardware and protocol fields, putting the local
	//             hardware and protocol addresses in the sender fields.
	//         Set the ar$op field to ares_op$REPLY
	//         Send the packet to the (new) target hardware address on
	//             the same hardware on which the request was received.
	//

	// ?Do I have the hardware type in ar$hrd?
	if arp.HWAddrSpc != vswitch.ARPHrdEthernet {
		log.Debug(0, "ARP: Unknown hardware type: %v", arp.HWAddrSpc)
		return
	}

	// [optionally check the hardware length ar$hln]
	if arp.HWAddrLen != vswitch.EthernetAddrLen {
		log.Debug(0, "ARP: Bad hardware address length: %v", arp.HWAddrLen)
		return
	}

	// ?Do I speak the protocol in ar$pro?
	if arp.ProtoAddrSpc != vswitch.EthertypeIPv4 {
		log.Debug(0, "ARP: Unknown protocol type: %v", arp.ProtoAddrSpc)
		return
	}

	// [optionally check the protocol length ar$pln]
	if arp.ProtoAddrLen != vswitch.IPv4AddrLen {
		log.Debug(0, "ARP: Bad protocol address length: %v", arp.HWAddrLen)
		return
	}

	// Merge_flag := false
	mergeFlag := false

	// If the pair <protocol type, sender protocol address> is
	// already in my translation table, update the sender
	// hardware address field of the entry with the new
	// information in the packet and set Merge_flag to true.

	status := vif.getARPStatus(arp.SenderProtoAddr)
	if status != nil && status.isValid() {
		// Note that lock on arpStatus is held during until we
		// return from processing this ARP packet.
		if !status.etherAddr.Equal(arp.SenderHWAddr) {
			if err := ar.router.UpdateNeighborEntry(vifindex, arp.SenderProtoAddr, arp.SenderHWAddr); err != nil {
				log.Err("Neighbor cache update failed: %v", err)
			}
			status.etherAddr = arp.SenderHWAddr
			mergeFlag = true
		}
	}

	// ?Am I the target protocol address?
	if !vif.isTargetAddress(arp.TargetProtoAddr) {
		return
	}

	// If Merge_flag is false, add the triplet <protocol type,
	// sender protocol address, sender hardware address> to
	// the translation table.
	if !mergeFlag && status != nil {
		if err := ar.router.UpdateNeighborEntry(vifindex, arp.SenderProtoAddr, arp.SenderHWAddr); err != nil {
			log.Err("Neighbor cache update failed: %v", err)
		}
		status.etherAddr = arp.SenderHWAddr
		status.validate()
		ar.findNeighborCache(vif.vif, arp.SenderProtoAddr, status)
	}

	// forward all ARP packets to the kernel for now
	ar.router.tap.Enqueue(unsafe.Pointer(mbuf))

	/*
		// ?Is the opcode ares_op$REQUEST?  (NOW look at the opcode!!)
		if arp.Op != vswitch.ARPOpRequest {
			// We now forward ARP packet to the kernel
			ar.router.tap.Enqueue(unsafe.Pointer(mbuf))
			return
		}

		// Swap hardware and protocol fields, putting the local
		// hardware and protocol addresses in the sender fields.
		// Set the ar$op field to ares_op$REPLY
		arp.ConvertRequestToReply(vif.hwAddr)

		// Send the packet to the (new) target hardware address on
		// the same hardware on which the request was received.
		metadata.SetOutVIF(vifindex)
		reply := mempool.AllocMbuf()
		reply.SetData(arp.Encode())
		vif.outbound.Enqueue(unsafe.Pointer(reply))
	*/
}

func (ar *arpResolver) deleteNeighborCache(index vswitch.VIFIndex, target vswitch.IPv4Addr) {
	ar.mutex.Lock()
	defer ar.mutex.Unlock()

	if ar.router != nil {
		ar.router.DeleteNeighborEntry(index, target)
	}
}

func (ar *arpResolver) start() {
	ar.quit = make(chan int)
	go func() {
		for {
			select {
			case req := <-ar.reqCh:
				req.resolver = ar
				ar.resolve(req)

			case mbuf := <-ar.arpCh:
				ar.input(dpdk.ToMbuf(unsafe.Pointer(mbuf)))

			case <-ar.quit:
				ar.mutex.Lock()
				ar.router = nil
				ar.mutex.Unlock()
				ar.done <- 0
				return
			}
		}
	}()
}

func (ar *arpResolver) stop() {
	if ar.quit == nil {
		return
	}
	close(ar.quit)
	<-ar.done
}

//export ARPResolve
func ARPResolve(routerID C.vrfindex_t, target C.uint32_t, vif C.vifindex_t) {
	if ar, ok := arpResolvers[vswitch.VRFIndex(routerID)]; ok {
		ar.reqCh <- &arpRequest{
			target: vswitch.IPv4Addr(target),
			vif:    vswitch.VIFIndex(vif),
		}
	}
}

//export ARPForward
func ARPForward(routerID C.vrfindex_t, mbuf *C.struct_rte_mbuf) {
	if ar, ok := arpResolvers[vswitch.VRFIndex(routerID)]; ok {
		ar.arpCh <- mbuf
	}
}
