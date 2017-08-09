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

package bridge

/*
#cgo CFLAGS: -I${SRCDIR}/../../include -I/usr/local/include/dpdk -m64 -pthread -O3 -msse4.2
#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all -L/usr/local/lib -ldpdk

#include "bridge.h"
*/
import "C"

import (
	"errors"
	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/hashlist"
	"github.com/lagopus/vsw/utils/ringpair"
	"github.com/lagopus/vsw/vswitch"
	"math"
	"net"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

type macAddress [6]byte

func (m *macAddress) HardwareAddr() net.HardwareAddr {
	return m[:]
}

func hardwareAddrToMacAddress(ha net.HardwareAddr) macAddress {
	var ma macAddress
	copy(ma[:], []byte(ha))
	return ma
}

type BridgeModule struct {
	vswitch.ModuleService
	bridgeMgr     *bridgeManager
	bridgeId      uint32
	domainHashSig dpdk.HashSig
	config        Config
	vifs          map[uint]*dpdk.Ring
	static        map[macAddress]bool
	macTable      *hashlist.HashList
	ageOut        *hashlist.HashList
}

// For Control()
type Config struct {
	MacLearning  bool   // true to enable mac learning
	MacAgingTime int    // age time
	MaxEntries   int    // maximum # of entries
	macTableSize uint32 // Actual MAC table size
}

var defaultConfig = Config{true, 300, 128, 128}

type MacEntry struct {
	VifIndex   uint // Output VIF Index
	MacAddress net.HardwareAddr
}

// internal purpose only
type configCmd int

const (
	CMD_ADD_ENTRY configCmd = iota + 1
	CMD_DEL_ENTRY
	CMD_UPDATE_CONFIG
)

type config struct {
	cmd       configCmd
	rc        chan bool // result
	domain    *BridgeModule
	entry     MacEntry
	newConfig Config
}

type macTableEntry struct {
	macAddress macAddress
	ring       *dpdk.Ring
}

type macAgeOut struct {
	macAddress macAddress
	expire     int64
}

var log = vswitch.Logger

// Backend Manager
type bridgeManager struct {
	refcount      uint
	request       chan *C.struct_bridge_request // Go -> C
	learn         chan *C.struct_bridge_learn   // C -> Go
	configure     chan *config                  // Modules -> Frontend (Config)
	control       chan bridgeMgrCmd             // Modules -> Frontend (Lifecycle)
	done          chan struct{}
	terminate     chan struct{}
	stopReceiving chan struct{}
	slaveId       uint
	rp            *ringpair.RingPair // For regular requests
	rpl           *ringpair.RingPair // For learning: 0=used, 1=free
	bridgeHash    *dpdk.Hash         // Hash to manage bridge domains
	domains       map[uint32]*BridgeModule
}

type bridgeMgrCmd int

const (
	BRIDGEMGR_START bridgeMgrCmd = iota
	BRIDGEMGR_STOP
	BRIDGEMGR_REF
	BRIDGEMGR_UNREF
)

func initBridgeManager() *bridgeManager {
	// reserve slave core
	coreid, err := vswitch.GetDpdkResource().AllocLcore()
	if err != nil {
		return nil
	}

	// create a pair of rings for C/Go communication
	rp := ringpair.Create(&ringpair.Config{
		Prefix: "bridge",
		Counts: [2]uint{
			C.MAX_BRIDGE_REQUESTS, // Go Frontend -> C Backend
		},
		SocketID: dpdk.SOCKET_ID_ANY,
	})
	if rp == nil {
		return nil
	}

	rpl := ringpair.Create(&ringpair.Config{
		Prefix: "bridgeL",
		Counts: [2]uint{
			C.MAX_BRIDGE_MBUFS, // Used
			C.MAX_BRIDGE_MBUFS, // Free
		},
		SocketID: dpdk.SOCKET_ID_ANY,
	})
	if rpl == nil {
		rp.Free()
		return nil
	}

	// Create DPDK Hash to manager Bridge
	/*
		hashParam := &dpdk.HashParams{
			Name:            "bridge_domains",
			Entries:         C.MAX_BRIDGE_DOMAINS,
			KeyLen:          C.sizeof_uint32_t,
			HashFunc:        unsafe.Pointer(C.bridge_domain_hash_func),
			HashFuncInitVal: 0,
			SocketId:        dpdk.LcoreToSocketId(coreid),
		}
		hash := dpdk.HashCreate(hashParam)
	*/

	// start backend
	log.Printf("BRIDGE: Starting backend task on Slave Core %d\n", coreid)
	p := (*C.struct_bridge_launch_param)(C.malloc(C.sizeof_struct_bridge_launch_param))
	p.name = C.CString("BRIDGE")
	p.request = unsafe.Pointer(rp.Rings[0])
	p.used = unsafe.Pointer(rpl.Rings[0])
	p.free = unsafe.Pointer(rpl.Rings[1])
	//p.bridge_hash = (*C.struct_rte_hash)(hash)
	dpdk.EalRemoteLaunch((dpdk.LcoreFunc)(C.bridge_task), unsafe.Pointer(p), coreid)

	// instantiate bridgeManager
	mgr := &bridgeManager{
		request:       make(chan *C.struct_bridge_request),
		learn:         make(chan *C.struct_bridge_learn),
		configure:     make(chan *config),
		control:       make(chan bridgeMgrCmd),
		terminate:     make(chan struct{}),
		done:          make(chan struct{}),
		stopReceiving: make(chan struct{}),
		slaveId:       coreid,
		rp:            rp,
		rpl:           rpl,
		//		bridgeHash: hash,
		domains: make(map[uint32]*BridgeModule),
	}

	// start frontend task
	go mgr.doControl()
	go mgr.doRequest()
	go mgr.doBridgeTask()
	go mgr.doReceivePackets()

	// yield before we leave
	runtime.Gosched()

	return mgr
}

//
// Control Related
//
func (mgr *bridgeManager) doControl() {
	log.Print("BRIDGE Manager controller started.")
	for c := range mgr.control {
		switch c {
		case BRIDGEMGR_REF:
			mgr.refcount++
			log.Printf("BRIDGE: Ref backend (%d).", mgr.refcount)
		case BRIDGEMGR_UNREF:
			mgr.refcount--
			log.Printf("BRIDGE: Unref backend (%d).", mgr.refcount)
			if mgr.refcount == 0 {
				mgr.terminate <- struct{}{}
				return
			}
		}
	}
}

func (mgr *bridgeManager) refBackend() {
	mgr.control <- BRIDGEMGR_REF
}

func (mgr *bridgeManager) unrefBackend() {
	mgr.control <- BRIDGEMGR_UNREF
}

// Terminate backend
func (mgr *bridgeManager) doTerminate() {
	mgr.stopReceiving <- struct{}{}

	r := (*C.struct_bridge_request)(C.malloc(C.sizeof_struct_bridge_request))
	r.cmd = C.BRIDGE_CMD_QUIT
	mgr.request <- r
	close(mgr.request)

	dpdk.EalWaitLcore(mgr.slaveId)
	vswitch.GetDpdkResource().FreeLcore(mgr.slaveId)
	mgr.rp.Free()
	mgr.rpl.Free()

	close(mgr.done)
	return
}

// Wait for backend to termiante
func (mgr *bridgeManager) waitBackend() {
	log.Printf("BRIDGE: Waiting backend to terminate")
	<-mgr.done
	log.Printf("BRIDGE: Backend terminated")
}

//
// Requesting Backend Related
//
func (mgr *bridgeManager) doRequest() {
	log.Print("Bridge Manager started.")
	ring := mgr.rp.Rings[0]
	for req := range mgr.request {
		ring.Enqueue(unsafe.Pointer(req))
	}
}

//
// Bridge Tasks
//
func (mgr *bridgeManager) doAgeOut() {
	currentTime := time.Now().Unix()
	for _, domain := range mgr.domains {
		alist := domain.ageOut.List()
		elem := alist.Front()
		for elem != nil {
			next := elem.Next()
			ae := elem.Value.(macAgeOut)
			if ae.expire <= currentTime {
				domain.deleteMACEntry(ae.macAddress)
			} else {
				// No need to check anymore
				// ageOutList is in order of time.
				// The oldest comes in the front.
				// The newest comes in the end.
				break
			}
			elem = next
		}
	}
}

func (mgr *bridgeManager) doConfigure(c *config) {
	domain := c.domain
	switch c.cmd {
	case CMD_UPDATE_CONFIG:
		//  update
		domain.updateDomainConfig(c.newConfig)
		c.rc <- true

	case CMD_ADD_ENTRY:
		macaddr := hardwareAddrToMacAddress(c.entry.MacAddress)
		domain.ageOut.Remove(macaddr)
		domain.static[macaddr] = true
		domain.addMACEntry(macaddr, c.entry.VifIndex)
		c.rc <- true

	case CMD_DEL_ENTRY:
		rc := false
		macaddr := hardwareAddrToMacAddress(c.entry.MacAddress)
		if _, ok := domain.static[macaddr]; ok {
			delete(domain.static, macaddr)
			domain.deleteMACEntry(macaddr)
			rc = true
		} else {
			log.Printf("%s: No static MAC address %s found\n",
				domain.Name(), c.entry.MacAddress)
		}
		c.rc <- rc
	}
}

func (mgr *bridgeManager) doLearning(l *C.struct_bridge_learn) {
	defer mgr.rpl.Rings[1].Enqueue(unsafe.Pointer(l))

	bridgeId := uint32(l.domain_id)
	domain, ok := mgr.domains[bridgeId]
	if !ok {
		log.Printf("BRIDGE: Unknown domain %d encountered.", bridgeId)
		return
	}
	if !domain.config.MacLearning {
		// no learning on this domain
		return
	}

	saddr := (*[1 << 30]byte)(unsafe.Pointer(&l.mac))[:6:6]
	srcmac := hardwareAddrToMacAddress(saddr)
	vifidx := uint(l.index)

	//	log.Printf("BRIDGE: incoming packet: bridge=%d, vif=%d, mac=%s",
	//		bridgeId, vifidx, srcmac.HardwareAddr())

	if _, ok := domain.static[srcmac]; ok {
		// ignore MACs in the static entry
		return
	}

	// Add to MAC Table
	domain.addMACEntry(srcmac, vifidx)

	expire := time.Now().Unix() + int64(domain.config.MacAgingTime)
	ageOutEntry := macAgeOut{macAddress: srcmac, expire: expire}
	domain.ageOut.Add(srcmac, ageOutEntry)
}

func (mgr *bridgeManager) doBridgeTask() {
	ticker := time.NewTicker(3 * time.Second)
	for {
		select {
		case c := <-mgr.configure:
			mgr.doConfigure(c)

		case l := <-mgr.learn:
			mgr.doLearning(l)

		case <-ticker.C:
			mgr.doAgeOut()

		case <-mgr.terminate:
			ticker.Stop()
			mgr.doTerminate()
			return
		}
	}
}

func (mgr *bridgeManager) doReceivePackets() {
	ring := mgr.rpl.Rings[0]

	for {
		select {
		case <-mgr.stopReceiving:
			close(mgr.learn)
			return

		default:
			var l *C.struct_bridge_learn
			for ring.Dequeue((*unsafe.Pointer)(unsafe.Pointer(&l))) == 0 {
				mgr.learn <- l
			}
			runtime.Gosched()
		}
	}
}

// Singleton
var instance *bridgeManager
var once sync.Once

func getBridgeManager() *bridgeManager {
	once.Do(func() {
		instance = initBridgeManager()
	})
	return instance
}

// Unique Domain ID Generation
var domainCount uint32 = 0
var domainCountMutex sync.Mutex

func newDomainId() (uint32, error) {
	domainCountMutex.Lock()
	defer domainCountMutex.Unlock()

	if domainCount < C.MAX_BRIDGE_DOMAINS {
		domainCount++
		return domainCount, nil
	}
	return 0, errors.New("Exceeded max bridge domains")
}

// Factory function
func newBridgeModule(p *vswitch.ModuleParam) (vswitch.Module, error) {
	mgr := getBridgeManager()
	if mgr == nil {
		return nil, errors.New("Can't start Bridge Manager")
	}
	mgr.refBackend()

	// assign bridge domain ID
	bridgeId, err := newDomainId()
	if err != nil {
		return nil, err
	}

	// create a module
	module := &BridgeModule{
		ModuleService: vswitch.NewModuleService(p),
		bridgeMgr:     mgr,
		bridgeId:      bridgeId,
		config:        defaultConfig,
		vifs:          make(map[uint]*dpdk.Ring),
		static:        make(map[macAddress]bool),
		macTable:      hashlist.New(),
		ageOut:        hashlist.New(),
	}
	mgr.domains[bridgeId] = module

	// register domain to the backend
	module.registerDomain()

	return module, nil
}

func (bm *BridgeModule) createRequest(cmd C.bridge_cmd_t) *C.struct_bridge_request {
	r := (*C.struct_bridge_request)(C.malloc(C.sizeof_struct_bridge_request))
	r.cmd = cmd
	r.domain_id = C.uint32_t(bm.bridgeId)
	r.domain_hsig = C.hash_sig_t(bm.domainHashSig) // XXX: Not used for now
	return r
}

// Register the domain
func (bm *BridgeModule) registerDomain() {
	log.Printf("%s: registering domain to the backend.", bm.Name())

	r := bm.createRequest(C.BRIDGE_CMD_DOMAIN_ADD)
	r.domain = (*C.struct_bridge_domain)(C.malloc(C.sizeof_struct_bridge_domain))
	r.domain.name = C.CString(bm.Name())
	r.domain.mac_hash = nil
	r.config.max_mac_entry = C.uint32_t(bm.config.macTableSize)
	bm.bridgeMgr.request <- r
}

// Unregister the domain
func (bm *BridgeModule) unregisterDomain() {
	log.Printf("%s: unregistering domain from the backend.", bm.Name())

	r := bm.createRequest(C.BRIDGE_CMD_DOMAIN_DELETE)
	bm.bridgeMgr.request <- r
}

// Enable the domain
func (bm *BridgeModule) enableDomain() {
	log.Printf("%s: enabling domain.", bm.Name())

	r := bm.createRequest(C.BRIDGE_CMD_DOMAIN_ENABLE)
	bm.bridgeMgr.request <- r
}

// Disable the domain
func (bm *BridgeModule) disableDomain() {
	log.Printf("%s: disbling domain.", bm.Name())

	r := bm.createRequest(C.BRIDGE_CMD_DOMAIN_DISABLE)
	bm.bridgeMgr.request <- r
}

// Update domain config
func (bm *BridgeModule) updateDomainConfig(newConfig Config) {
	log.Printf("%s: update domain config.", bm.Name())

	// If MAC learning is disable, flush all dynamic MAC entries
	if !newConfig.MacLearning {
		// If we are re-creating a hash table in the backend
		// we don't need to delete MAC entry manually.
		// We anyway have to re-register whole MAC entry.
		deleteMac := bm.deleteMACEntry
		if newConfig.macTableSize == bm.config.macTableSize {
			deleteMac = func(mac macAddress) {
				bm.macTable.Remove(mac)
			}
		}

		for _, elem := range bm.ageOut.AllElements() {
			ae := elem.Value.(macAgeOut)
			deleteMac(ae.macAddress)
		}
		bm.ageOut.Reset()
	}

	if newConfig.macTableSize != bm.config.macTableSize {
		// recreate hash in the backend
		r := bm.createRequest(C.BRIDGE_CMD_DOMAIN_CONFIG)
		r.config.max_mac_entry = C.uint32_t(newConfig.macTableSize)
		bm.bridgeMgr.request <- r

		// Re-register all MAC entry
		for _, elem := range bm.macTable.AllElements() {
			entry := elem.Value.(*macTableEntry)
			bm.addMACEntryToBackend(entry.macAddress, entry.ring)
		}
	}
	bm.config = newConfig
}

// configure rings
func (bm *BridgeModule) configureRing() {
	log.Printf("%s: configuring ring.", bm.Name())

	r := bm.createRequest(C.BRIDGE_CMD_CONFIG_RING)
	r.ring.input = (*C.struct_rte_ring)(unsafe.Pointer(bm.Input()))
	r.ring.vif_input = (*C.struct_rte_ring)(unsafe.Pointer(bm.VifInput()))
	r.ring.output = (*C.struct_rte_ring)(unsafe.Pointer(bm.Rules().Output(vswitch.MATCH_ETH_DST_SELF)))
	r.ring.tap = (*C.struct_rte_ring)(unsafe.Pointer(bm.Rules().Output(vswitch.MATCH_ETH_TYPE_ARP)))
	bm.bridgeMgr.request <- r
}

// Add a VIF
func (bm *BridgeModule) addVIF(vifidx uint, ring *dpdk.Ring) {
	log.Printf("%s: adding VIF %v.", bm.Name(), vifidx)

	r := bm.createRequest(C.BRIDGE_CMD_VIF_ADD)
	r.vif.index = C.vifindex_t(vifidx)
	r.vif.ring = (*C.struct_rte_ring)(unsafe.Pointer(ring))
	bm.vifs[vifidx] = ring
	bm.bridgeMgr.request <- r
}

// Delete a VIF
func (bm *BridgeModule) deleteVIF(vifidx uint) {
	log.Printf("%s: deleting VIF %v.", bm.Name(), vifidx)

	r := bm.createRequest(C.BRIDGE_CMD_VIF_DELETE)
	r.vif.index = C.vifindex_t(vifidx)
	delete(bm.vifs, vifidx)
	bm.bridgeMgr.request <- r
}

// Add a MAC Entry to Backend
func (bm *BridgeModule) addMACEntryToBackend(mac macAddress, ring *dpdk.Ring) {
	r := bm.createRequest(C.BRIDGE_CMD_MAC_ADD)
	s := (*[1 << 30]byte)(unsafe.Pointer(&r.mac.mac.addr_bytes))[:6:6]
	copy(s, mac[:])
	r.mac.ring = (*C.struct_rte_ring)(unsafe.Pointer(ring))
	bm.bridgeMgr.request <- r
}

// Delete a MAC Entry from Backend
func (bm *BridgeModule) deleteMACEntryFromBackend(mac macAddress) {
	r := bm.createRequest(C.BRIDGE_CMD_MAC_DELETE)
	s := (*[1 << 30]byte)(unsafe.Pointer(&r.mac.mac.addr_bytes))[:6:6]
	copy(s, mac[:])
	bm.bridgeMgr.request <- r
}

// Add a MAC Entry
func (bm *BridgeModule) addMACEntry(mac macAddress, vifidx uint) {
	//log.Printf("%s: adding MAC entry %v (VIF %d).", bm.Name(), mac.HardwareAddr(), vifidx)

	ring, ok := bm.vifs[vifidx]
	if !ok {
		log.Printf("%s: Unknown VIF %d.", bm.Name(), vifidx)
		return
	}

	// Add to hash lists
	if elem := bm.macTable.Find(mac); elem != nil {
		oldEntry := elem.Value.(*macTableEntry)
		if oldEntry.ring == ring {
			// no change. just push to the end of the list.
			bm.macTable.Add(mac, oldEntry)
			return
		}
	}

	// Either new entry or vif has changed
	entry := &macTableEntry{macAddress: mac, ring: ring}
	bm.macTable.Add(mac, entry)

	// Update backend
	bm.addMACEntryToBackend(mac, ring)
}

// Delete a MAC Entry
func (bm *BridgeModule) deleteMACEntry(mac macAddress) {
	log.Printf("%s: deleting MAC entry %v.", bm.Name(), mac.HardwareAddr())

	// Remove from hash lists
	bm.ageOut.Remove(mac)
	bm.macTable.Remove(mac)

	bm.deleteMACEntryFromBackend(mac)
}

func (bm *BridgeModule) requestConfig(c *config) bool {
	c.rc = make(chan bool)
	defer close(c.rc)
	c.domain = bm
	bm.bridgeMgr.configure <- c
	return <-c.rc
}

func (bm *BridgeModule) updateMacEntry(cmd configCmd, v interface{}) bool {
	me, ok := v.(MacEntry)
	if !ok {
		log.Printf("%s: Invalid parameter: %v\n", bm.Name(), v)
		return false
	}
	return bm.requestConfig(&config{cmd: cmd, entry: me})
}

func nextPowerOfTwo(v uint32) uint32 {
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v++
	return v
}

func (bm *BridgeModule) Control(cmd string, v interface{}) interface{} {
	log.Printf("%s: %s requested", bm.Name(), cmd)

	switch cmd {
	case "GET_BRIDGE_ID":
		return bm.bridgeId

	case "SET_CONFIG":
		c, ok := v.(Config)
		if !ok {
			log.Printf("%s: Invalid parameter: %v\n", bm.Name(), v)
			return false
		}

		if c.MaxEntries > math.MaxUint32 {
			log.Printf("%s: MaxEntres beyond limit %d\n", bm.Name(), math.MaxUint32)
			return false
		}
		c.macTableSize = nextPowerOfTwo(uint32(c.MaxEntries))
		log.Printf("%s: config: %v\n", bm.Name(), c)

		return bm.requestConfig(&config{cmd: CMD_UPDATE_CONFIG, newConfig: c})

	case "GET_CONFIG":
		return bm.config

	case "ADD_MAC_ENTRY":
		return bm.updateMacEntry(CMD_ADD_ENTRY, v)

	case "DELETE_MAC_ENTRY":
		return bm.updateMacEntry(CMD_DEL_ENTRY, v)

	default:
		log.Printf("Unknown control: %s.\n", cmd)
	}
	return false
}

func (bm *BridgeModule) Start() bool {
	log.Printf("%s: Start().", bm.Name())

	// Tell backend which rings to use for inputs and default output.
	bm.configureRing()

	// Register VIFs
	for _, rule := range bm.Rules().SubRules(vswitch.MATCH_OUT_VIF) {
		bm.addVIF(uint(rule.Param[0]), rule.Ring)
	}

	// Activate this bridge domain
	bm.enableDomain()

	return true
}

func (bm *BridgeModule) Stop() {
	log.Printf("%s: Stop().", bm.Name())
	bm.disableDomain()
	bm.bridgeMgr.unrefBackend()
}

func (bm *BridgeModule) Wait() {
	log.Printf("%s: Wait().", bm.Name())
	bm.bridgeMgr.waitBackend()
}

/*
 * Do module set up here.
 */
func init() {
	rp := &vswitch.RingParam{
		Count:    C.MAX_BRIDGE_MBUFS,
		SocketId: dpdk.SOCKET_ID_ANY,
		Flags:    0,
	}

	if !vswitch.RegisterModule("bridge", newBridgeModule, rp, vswitch.TypeBridge) {
		log.Fatalf("Failed to register the class.")
	}
}
