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

package vif

/*
#cgo CFLAGS: -I${SRCDIR}/../../include -I/usr/local/include/dpdk -m64 -pthread -O3 -msse4.2
#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all -L/usr/local/lib -ldpdk

#include <rte_config.h>
#include <rte_ethdev.h>

#include "vif.h"

static struct rte_eth_conf *get_port_conf() {
	static struct rte_eth_conf port_conf = {
		.rxmode = {
#if MAX_PACKET_SZ > 2048
			.jumbo_frame    = 1, // Jumbo Frame Support enabled
			.max_rx_pkt_len = 9000, // Max RX packet length
#endif // MAX_PACKET_SZ
		},
		.rx_adv_conf = {
			.rss_conf = {
				.rss_key = NULL,
				.rss_hf = ETH_RSS_IPV4 | ETH_RSS_IPV6,
			},
		},
		.txmode = {
			.mq_mode = ETH_MQ_TX_NONE,
		},
	};
	return &port_conf;
}

*/
import "C"

import (
	"errors"
	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/ringpair"
	"github.com/lagopus/vsw/vswitch"
	"sync"
	"unsafe"
)

const rxFreeThreshold = uint16(128)

type VifModule struct {
	vswitch.ModuleService
	dev    *dpdk.EthDev
	rxq    *dpdk.EthRxQueue
	txq    *dpdk.EthTxQueue
	config VifConfig
	vifmgr *vifManager
	ls     vswitch.LinkStatus
}

// For Control()
type VifQueue struct {
	QueueId   uint
	QueueLen  uint
	maxQueues uint
}

type VifConfig struct {
	PortId   uint
	SocketId uint
	RxQueue  VifQueue
	TxQueue  VifQueue
	vm       *VifModule
}

var log = vswitch.Logger

// Backend Manager
type vifManager struct {
	refcount uint
	inuse    uint
	request  chan *C.struct_vif_request
	control  chan VifMgrCmd
	done     chan int
	slaveId  uint
	rp       *ringpair.RingPair
}

type VifMgrCmd int

const (
	VIFMGR_START VifMgrCmd = iota
	VIFMGR_STOP
	VIFMGR_REF
	VIFMGR_UNREF
)

func initVifManager() *vifManager {
	coreid, err := vswitch.GetDpdkResource().AllocLcore()
	if err != nil {
		return nil
	}

	// craete a ring for C/Go communication
	rp := ringpair.Create(&ringpair.Config{
		Prefix:   "vif",
		Counts:   [2]uint{32, 0}, // we only need a ring (Go -> C)
		SocketID: dpdk.SOCKET_ID_ANY,
	})
	if rp == nil {
		return nil
	}

	// start backend
	log.Printf("VIF: Starting backend task on Slave Core %d\n", coreid)
	p := (*C.struct_vif_task_param)(C.malloc(C.sizeof_struct_vif_task_param))
	p.req = unsafe.Pointer(rp.Rings[0])
	dpdk.EalRemoteLaunch((dpdk.LcoreFunc)(C.vif_do_task), unsafe.Pointer(p), coreid)

	// instantiate vifManager
	mgr := &vifManager{
		request: make(chan *C.struct_vif_request),
		control: make(chan VifMgrCmd),
		done:    make(chan int),
		slaveId: coreid,
		rp:      rp,
	}

	// start frontend task
	go mgr.doControl()
	go mgr.doRequest()

	return mgr
}

var instance *vifManager
var once sync.Once

func getVifManager() *vifManager {
	once.Do(func() {
		instance = initVifManager()
	})
	return instance
}

//
// Control Related
//
func (vm *vifManager) doControl() {
	log.Print("VIF Manager controller started.")
	for c := range vm.control {
		switch c {
		case VIFMGR_START:
			if vm.inuse == 0 {
				vm.controlBackend(C.VIF_CMD_START)
			}
			vm.inuse++
			log.Printf("VIF: Start backend (%d).", vm.inuse)
		case VIFMGR_STOP:
			vm.inuse--
			if vm.inuse == 0 {
				vm.controlBackend(C.VIF_CMD_STOP)
			}
			log.Printf("VIF: Stop backend (%d).", vm.inuse)
		case VIFMGR_REF:
			vm.refcount++
			log.Printf("VIF: Ref backend (%d).", vm.refcount)
		case VIFMGR_UNREF:
			vm.refcount--
			log.Printf("VIF: Unref backend (%d).", vm.refcount)
			if vm.refcount == 0 {
				vm.controlBackend(C.VIF_CMD_QUIT)
				dpdk.EalWaitLcore(vm.slaveId)
				vm.rp.Free()
				close(vm.request)
				close(vm.done)
				return
			}
		}
	}
}

func (vm *vifManager) StartBackend() {
	vm.control <- VIFMGR_START
}

func (vm *vifManager) StopBackend() {
	vm.control <- VIFMGR_STOP
}

func (vm *vifManager) RefBackend() {
	vm.control <- VIFMGR_REF
}

func (vm *vifManager) UnrefBackend() {
	vm.control <- VIFMGR_UNREF
}

// Wait for backend to termiante
func (vm *vifManager) WaitBackend() {
	log.Printf("VIF: Waiting backend to terminate")
	<-vm.done
	log.Printf("VIF: Backend terminated")
}

//
// Reuquest Related Task
//
func (vm *vifManager) doRequest() {
	log.Print("VIF Manager started.")
	ring := vm.rp.Rings[0]
	for req := range vm.request {
		ring.Enqueue(unsafe.Pointer(req))
	}
}

// Request backend to start packet processing
func (vm *vifManager) controlBackend(cmd C.vif_cmd_t) {
	r := (*C.struct_vif_request)(C.malloc(C.sizeof_struct_vif_request))
	r.cmd = cmd
	vm.request <- r
}

func (vm *vifManager) createRequest(cmd C.vif_cmd_t, vif vswitch.VifIndex) *C.struct_vif_request {
	r := (*C.struct_vif_request)(C.malloc(C.sizeof_struct_vif_request))
	r.entity = (*C.struct_vif_entity)(C.malloc(C.sizeof_struct_vif_entity))
	r.cmd = cmd
	r.entity.vif = C.vifindex_t(vif)
	return r
}

// Add a new interface
func (vm *vifManager) AddVIF(module *VifModule) bool {
	out_ring := module.Rules().Output(vswitch.MATCH_ANY)
	if out_ring == nil {
		log.Printf("VIF: No output ring found for %s\n", module.Name())
		return false
	}

	r := vm.createRequest(C.VIF_CMD_NEW, module.Vif().VifIndex())

	r.entity.name = C.CString(module.Name())
	r.entity.vrf = C.uint64_t(module.Vrf().VrfRD())
	r.entity.out_ring = unsafe.Pointer(out_ring)
	r.entity.in_ring = unsafe.Pointer(module.Input())
	r.entity.port_id = C.uint(module.config.PortId)
	r.entity.rx_queue_id = C.uint(module.config.RxQueue.QueueId)
	r.entity.tx_queue_id = C.uint(module.config.TxQueue.QueueId)

	vm.request <- r

	return true
}

// Delete an interface
func (vm *vifManager) DeleteVIF(module *VifModule) {
	vm.request <- vm.createRequest(C.VIF_CMD_DELETE, module.Vif().VifIndex())
}

//
func newVifModule(p *vswitch.ModuleParam) (vswitch.Module, error) {
	vm := getVifManager()
	if vm == nil {
		return nil, errors.New("Cant' start VIF Manager")
	}
	vm.RefBackend()

	return &VifModule{
		ModuleService: vswitch.NewModuleService(p),
		vifmgr:        vm,
		ls:            vswitch.LinkDown,
	}, nil
}

func (vc *VifConfig) configEthDev() *dpdk.EthDev {
	dev := dpdk.EthDevOpen(vc.PortId)
	if dev == nil {
		log.Printf("%s: Can't open port ID: %d", vc.vm.Name(), vc.PortId)
		return nil
	}

	// XXX: Limit number of queues to 1 for now.
	// In the future, we need to make use of multiple queues.
	// 	rxqm, txqm := dev.GetMaxQueues()
	vc.RxQueue.maxQueues = 1
	vc.TxQueue.maxQueues = 1

	if dev.Configure(vc.RxQueue.maxQueues, vc.TxQueue.maxQueues, (*dpdk.EthConf)(unsafe.Pointer(C.get_port_conf()))) != 0 {
		log.Printf("%s: Can't configure the device\n", vc.vm.Name())
		return nil
	}

	// Set the device to promiscuous mode
	dev.SetPromiscuous(true)
	if dev.Promiscuous() != true {
		log.Printf("%s: Can't set to promiscuous mode.\n", vc.vm.Name())
	}

	return dev
}

func (vc *VifConfig) configEthQueues(dev *dpdk.EthDev) (rxQueue *dpdk.EthRxQueue, txQueue *dpdk.EthTxQueue) {
	if !vc.RxQueue.validateQueueId() {
		log.Printf("%s: Invalid Rx Queue ID.\n", vc.vm.Name())
		return nil, nil
	}

	if !vc.TxQueue.validateQueueId() {
		log.Printf("%s: Invalid Tx Queue ID.\n", vc.vm.Name())
		return nil, nil
	}

	pool := vswitch.GetDpdkResource().Mempool

	rxConf := dev.DevInfo().DefaultRxConf()
	rxConf.SetFreeThresh(rxFreeThreshold)

	rxQueue = dev.RxQueueSetup(vc.RxQueue.QueueId, vc.RxQueue.QueueLen, vc.SocketId, rxConf, pool)
	txQueue = dev.TxQueueSetup(vc.TxQueue.QueueId, vc.TxQueue.QueueLen, vc.SocketId, nil)

	return
}

func (vq *VifQueue) validateQueueId() bool {
	return vq.maxQueues > vq.QueueId
}

func (vm *VifModule) Link() vswitch.LinkStatus {
	return vm.ls
}

func (vm *VifModule) SetLink(newLs vswitch.LinkStatus) bool {
	if vm.dev == nil {
		return false
	}

	if vm.ls == newLs {
		return true
	}

	if newLs == vswitch.LinkUp {
		if vm.dev.Start() != 0 {
			return false
		}
		// Add VIF to the backend
		vm.vifmgr.AddVIF(vm)
	} else {
		vm.dev.Stop()
		// Delete VIF from the backend
		vm.vifmgr.DeleteVIF(vm)
	}

	vm.ls = newLs
	return true
}

func (vm *VifModule) Control(c string, v interface{}) interface{} {
	switch c {
	case "CONFIG":
		log.Printf("%s: Config requested.\n", vm.Name())
		vc, ok := v.(VifConfig)
		if !ok {
			log.Printf("%s: Invalid parameter: %v\n", vm.Name(), v)
			return false
		}
		vc.vm = vm

		if vm.dev == nil {
			vm.dev = vc.configEthDev()
			if vm.dev == nil {
				log.Printf("%s: Can't configure ether device.\n", vm.Name())
				return false
			}
		}

		rxq, txq := vc.configEthQueues(vm.dev)

		if rxq == nil || txq == nil {
			log.Printf("%s: Can't configure ether device.\n", vm.Name())
			return false
		}

		vm.rxq = rxq
		vm.txq = txq
		vm.config = vc

		// Set MAC Address of the interface
		vm.Vif().SetMacAddress(vm.dev.MacAddr())
		if mtu := vm.dev.MTU(); mtu > 0 {
			vm.Vif().SetMTU(vswitch.MTU(mtu))
		} else {
			log.Printf("%s: Can't get MTU of the ether device.\n", vm.Name())
		}

		return true

	case "LINK_UP":
		log.Printf("%s: Link up requested.\n", vm.Name())
		return vm.SetLink(vswitch.LinkUp)

	case "LINK_DOWN":
		log.Printf("%s: Link down requested.\n", vm.Name())
		vm.SetLink(vswitch.LinkDown)
		return true

	case "SET_SPEED":
		log.Printf("%s: Set speed requested.\n", vm.Name())
		return true

	default:
		log.Printf("%s: Unknown control: %s.\n", vm.Name(), c)
	}
	return false
}

const (
	MbufLen = C.VIF_MBUF_LEN
)

func (vm *VifModule) Start() bool {
	log.Printf("%s: Start()", vm.Name())
	vm.vifmgr.StartBackend()
	return true
}

func (vm *VifModule) Stop() {
	log.Printf("%s: Stop()", vm.Name())
	vm.vifmgr.StopBackend()
	vm.vifmgr.UnrefBackend()
}

func (vm *VifModule) Wait() {
	log.Printf("%s: Wait()", vm.Name())
	vm.vifmgr.WaitBackend()
}

/*
 * Register module here
 */
func init() {
	rp := &vswitch.RingParam{
		Count:    MbufLen,
		SocketId: dpdk.SOCKET_ID_ANY,
	}

	if !vswitch.RegisterModule("vif", newVifModule, rp, vswitch.TypeVif) {
		log.Fatalf("Failed to register the module.")
	}
}
