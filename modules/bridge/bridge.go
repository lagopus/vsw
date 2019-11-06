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

package bridge

/*
#cgo CFLAGS: -I${SRCDIR}/../../include -m64 -pthread -O3 -msse4.2
#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all

#include "bridge.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/hashlist"
	"github.com/lagopus/vsw/utils/ringpair"
	"github.com/lagopus/vsw/vswitch"
	vlog "github.com/lagopus/vsw/vswitch/log"
)

const (
	moduleName           = "bridge"
	maxLearningBufs      = 1024
	defaultAgingTime     = 300
	defaultMaxMACEntries = 128
)

type macAddress [6]byte

func (m *macAddress) HardwareAddr() net.HardwareAddr {
	return m[:]
}

func ha2ma(ha net.HardwareAddr) macAddress {
	var ma macAddress
	copy(ma[:], []byte(ha))
	return ma
}

type BridgeInstance struct {
	base          *vswitch.BaseInstance
	service       *bridgeService
	bridgeID      uint32
	instance      *vswitch.RuntimeInstance
	param         *C.struct_bridge_instance
	enabled       bool
	mtu           vswitch.MTU
	learning      bool
	agingTime     int
	maxMACEntries int // Maximum MAC entries
	macTableSize  int // Actual MAC table size (2^n)
	vifs          map[vswitch.VIFIndex]*vswitch.VIF
	macTable      *hashlist.HashList
	ageOut        *hashlist.HashList
	macTableCh    chan []vswitch.BridgeMACEntry
	mutex         sync.Mutex
}

type MacEntry struct {
	VifIndex   uint // Output VIF Index
	MacAddress net.HardwareAddr
}

type macAgeOut struct {
	macAddress macAddress
	expire     int64
}

type bridgeService struct {
	runtime         *vswitch.Runtime
	mutex           sync.Mutex
	terminate       chan struct{}
	disableLearning chan *BridgeInstance
	dumpMACTable    chan *BridgeInstance
	rp              *ringpair.RingPair
	bridges         map[uint32]*BridgeInstance
	running         bool
	refcnt          int
}

var log = vswitch.Logger

var bs *bridgeService
var mutex sync.Mutex

//
// TOML Config
//
type bridgeConfigSection struct {
	Bridge bridgeConfig
}

type bridgeConfig struct {
	Core uint
}

var config bridgeConfig

var defaultConfig = bridgeConfig{
	Core: 3,
}

//
// Bridge Instance
//

func getBridgeService() (*bridgeService, error) {
	mutex.Lock()
	defer mutex.Unlock()

	if bs != nil {
		bs.refcnt++
		return bs, nil
	}

	// Create a ringpair for learning MAC
	rp := ringpair.Create(&ringpair.Config{
		Prefix:   "bridge",
		Counts:   [2]uint{maxLearningBufs, maxLearningBufs},
		SocketID: dpdk.SOCKET_ID_ANY,
	})
	if rp == nil {
		rp.Free()
		return nil, errors.New("Can't create a ringpair")
	}

	param := (*C.struct_bridge_runtime_param)(C.calloc(1, C.sizeof_struct_bridge_runtime_param))
	param.learn = (*C.struct_rte_ring)(unsafe.Pointer(rp.Rings[0]))
	param.free = (*C.struct_rte_ring)(unsafe.Pointer(rp.Rings[1]))

	ops := vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.bridge_runtime_ops))
	rt, err := vswitch.NewRuntime(config.Core, moduleName, ops, unsafe.Pointer(param))
	if err != nil {
		return nil, err
	}
	if err := rt.Enable(); err != nil {
		return nil, err
	}

	bs = &bridgeService{
		runtime:         rt,
		terminate:       make(chan struct{}),
		disableLearning: make(chan *BridgeInstance),
		dumpMACTable:    make(chan *BridgeInstance),
		rp:              rp,
		bridges:         make(map[uint32]*BridgeInstance),
		refcnt:          1,
	}

	// Start Bridge Service
	bs.start()

	return bs, nil
}

func (s *bridgeService) free() {
	mutex.Lock()
	defer mutex.Unlock()

	s.refcnt--
	if s.refcnt == 0 {
		s.stop()
		for _, b := range s.bridges {
			b.instance.Unregister()
		}
		s.runtime.Terminate()
		s.rp.Free()
		bs = nil
	}
}

func (s *bridgeService) registerBridge(b *BridgeInstance) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.bridges[b.bridgeID]; exists {
		return fmt.Errorf("BridgeID %v already registered", b.bridgeID)
	}

	s.bridges[b.bridgeID] = b

	return nil
}

func (s *bridgeService) unregisterBridge(b *BridgeInstance) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.bridges[b.bridgeID]; !exists {
		return
	}

	delete(s.bridges, b.bridgeID)
}

func (s *bridgeService) doAgeOut() {
	currentTime := time.Now().Unix()
	for _, bridge := range s.bridges {
		// agingTime of 0 means unlimited.
		if bridge.agingTime > 0 {
			alist := bridge.ageOut.List()
			elem := alist.Front()
			for elem != nil {
				next := elem.Next()
				ae := elem.Value.(*macAgeOut)
				if ae.expire <= currentTime {
					bridge.deleteMACEntry(ae.macAddress)
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
}

func (s *bridgeService) flushMACEntry(b *BridgeInstance) {
	// Remove all learned entries
	for _, e := range b.macTable.AllElements() {
		entry := e.Value.(*vswitch.BridgeMACEntry)
		if entry.EntryType == vswitch.EntryDynamic {
			b.deleteMACEntry(ha2ma(entry.MACAddress))
		}
	}
}

func (s *bridgeService) learn(l *C.struct_bridge_learn) {
	bridgeID := uint32(l.domain_id)
	bridge, ok := s.bridges[bridgeID]
	if !ok {
		log.Printf("BRIDGE: Unknown domain %d encountered.", bridgeID)
		return
	}
	if !bridge.learning {
		// no learning on this domain
		return
	}

	saddr := (*[1 << 30]byte)(unsafe.Pointer(&l.mac))[:6:6]
	srcmac := ha2ma(saddr)
	vifidx := vswitch.VIFIndex(l.index)

	// Update FDB
	bridge.addMACEntry(srcmac, vifidx)
}

func (s *bridgeService) sendMACTable(b *BridgeInstance) {
	b.macTableCh <- b.dumpMACTable()
}

func (s *bridgeService) start() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.running {
		return
	}

	s.running = true
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		bufs := make([]*C.struct_bridge_learn, maxLearningBufs)
		p := (*unsafe.Pointer)(unsafe.Pointer(&bufs[0]))
		learningRing := s.rp.Rings[0]
		freeRing := s.rp.Rings[1]

		for {
			select {
			case <-ticker.C:
				s.doAgeOut()

			case b := <-s.disableLearning:
				s.flushMACEntry(b)

			case <-s.terminate:
				ticker.Stop()
				s.stop()
				return

			case b := <-s.dumpMACTable:
				s.sendMACTable(b)

			default:
				if n := learningRing.DequeueBurst(p, maxLearningBufs); n > 0 {
					for i := uint(0); i < n; i++ {
						s.learn(bufs[i])
					}
					freeRing.EnqueueBurst(p, n)
				}
				runtime.Gosched()
			}
		}
	}()
}

func (s *bridgeService) stop() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.running {
		s.terminate <- struct{}{}
	}
}

var bridgeCount uint32 = 0
var bridgeCountMutex sync.Mutex

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

func loadConfig() {
	c := bridgeConfigSection{defaultConfig}
	vswitch.GetConfig().Decode(&c)
	config = c.Bridge
}

var once sync.Once

// Factory function
func newBridgeInstance(base *vswitch.BaseInstance, priv interface{}) (vswitch.Instance, error) {
	once.Do(loadConfig)

	bridgeCountMutex.Lock()
	defer bridgeCountMutex.Unlock()

	s, err := getBridgeService()
	if err != nil {
		return nil, err
	}

	if bridgeCount == C.MAX_BRIDGE_DOMAINS {
		return nil, errors.New("Bridge instance exceeded the limit.")
	}
	bridgeCount++
	bridgeID := bridgeCount

	// Create an instance
	b := &BridgeInstance{
		base:       base,
		service:    s,
		bridgeID:   bridgeID,
		enabled:    false,
		mtu:        vswitch.DefaultMTU,
		learning:   true,
		agingTime:  defaultAgingTime,
		vifs:       make(map[vswitch.VIFIndex]*vswitch.VIF),
		macTable:   hashlist.New(),
		ageOut:     hashlist.New(),
		macTableCh: make(chan []vswitch.BridgeMACEntry),
	}

	if err := s.registerBridge(b); err != nil {
		return nil, err
	}

	b.param = (*C.struct_bridge_instance)(C.calloc(1, C.sizeof_struct_bridge_instance))
	b.param.base.name = C.CString(base.Name())
	b.param.base.input = (*C.struct_rte_ring)(unsafe.Pointer(base.Input()))
	b.param.base.outputs = (**C.struct_rte_ring)(C.calloc(1, C.size_t(unsafe.Sizeof(uintptr(0)))))
	b.param.domain_id = C.uint32_t(bridgeID)

	bi, err := vswitch.NewRuntimeInstance((vswitch.LagopusInstance)(unsafe.Pointer(b.param)))
	if err != nil {
		b.Free()
		return nil, fmt.Errorf("Can't create a new instance: %v", err)
	}

	if err := s.runtime.Register(bi); err != nil {
		b.Free()
		return nil, fmt.Errorf("Can't register the instance: %v", err)
	}

	b.instance = bi

	return b, nil
}

func (b *BridgeInstance) Free() {
	if b.instance != nil {
		b.instance.Unregister()
	}

	b.service.unregisterBridge(b)

	C.free(unsafe.Pointer(b.param.base.name))
	C.free(unsafe.Pointer(b.param.base.outputs))
	C.free(unsafe.Pointer(b.param))

	b.service = nil
	b.base = nil
	b.vifs = nil
	b.macTable = nil
	b.ageOut = nil
}

func (b *BridgeInstance) Enable() error {
	if !b.enabled {
		if err := b.instance.Enable(); err != nil {
			return err
		}
		b.enabled = true
	}
	return nil
}

func (b *BridgeInstance) Disable() {
	if b.enabled {
		b.instance.Disable()
		b.enabled = false
	}
}

type bridgeCmd int

const (
	BRIDGE_CMD_RIF_ADD         = bridgeCmd(C.BRIDGE_CMD_RIF_ADD)
	BRIDGE_CMD_RIF_DELETE      = bridgeCmd(C.BRIDGE_CMD_RIF_DELETE)
	BRIDGE_CMD_VIF_ADD         = bridgeCmd(C.BRIDGE_CMD_VIF_ADD)
	BRIDGE_CMD_VIF_DELETE      = bridgeCmd(C.BRIDGE_CMD_VIF_DELETE)
	BRIDGE_CMD_MAC_ADD         = bridgeCmd(C.BRIDGE_CMD_MAC_ADD)
	BRIDGE_CMD_MAC_DELETE      = bridgeCmd(C.BRIDGE_CMD_MAC_DELETE)
	BRIDGE_CMD_SET_MTU         = bridgeCmd(C.BRIDGE_CMD_SET_MTU)
	BRIDGE_CMD_SET_MAX_ENTRIES = bridgeCmd(C.BRIDGE_CMD_SET_MAX_ENTRIES)
	BRIDGE_CMD_SET_MAT         = bridgeCmd(C.BRIDGE_CMD_SET_MAT)
)

//
// BridgeInstance interface
//
func (b *BridgeInstance) control(cmd bridgeCmd, ring *dpdk.Ring, mac *macAddress, vif *vswitch.VIF) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	p := &b.param.control
	p.cmd = C.bridge_cmd_t(cmd)
	p.ring = (*C.struct_rte_ring)(unsafe.Pointer(ring))
	p.mtu = C.int(b.mtu)
	p.max_mac_entries = C.int(b.macTableSize)

	if mac != nil {
		d := (*[1 << 30]byte)(unsafe.Pointer(&p.mac.addr_bytes))[:6:6]
		copy(d, (*mac)[:])
	}

	if vif != nil {
		p.index = C.vifindex_t(vif.Index())
	}

	rc, err := b.instance.Control(unsafe.Pointer(p))
	if rc == false || err != nil {
		return fmt.Errorf("%v Failed: %v", cmd, err)
	}
	return nil
}

func (b *BridgeInstance) AddVIF(vif *vswitch.VIF, mtu vswitch.MTU) error {
	b.vifs[vif.Index()] = vif
	b.mtu = mtu
	return b.control(BRIDGE_CMD_VIF_ADD, vif.BridgeInput(), nil, vif)
	// TODO: Check if VIF is RIF. If so, add its MAC address as a static entry.
	// mac := ha2ma(vif.MACAddress())
	// b.control(BRIDGE_CMD_RIF_ADD, vif.Input(), &mac, vif)
}

func (b *BridgeInstance) DeleteVIF(vif *vswitch.VIF, mtu vswitch.MTU) error {
	delete(b.vifs, vif.Index())
	b.mtu = mtu
	return b.control(BRIDGE_CMD_VIF_DELETE, nil, nil, vif)
	// TODO: Check if VIF is RIF. If so, delete its MAC address from FDB.
	// b.control(BRIDGE_CMD_RIF_DELETE, nil, nil, vif)
}

func (b *BridgeInstance) SetMTU(mtu vswitch.MTU) {
	b.mtu = mtu
	b.control(BRIDGE_CMD_SET_MTU, nil, nil, nil)
}

func (b *BridgeInstance) SetMACAgingTime(agingTime int) {
	b.agingTime = agingTime
}

func (b *BridgeInstance) SetMaxEntries(maxMACEntries int) {
	b.maxMACEntries = maxMACEntries
	b.macTableSize = int(nextPowerOfTwo(uint32(maxMACEntries)))
	b.control(BRIDGE_CMD_SET_MAX_ENTRIES, nil, nil, nil)
	// TODO: Update FDB size and then re-register all MAC entry if needed.
}

func (b *BridgeInstance) EnableMACLearning() {
	b.learning = true
}

func (b *BridgeInstance) DisableMACLearning() {
	b.learning = false
	b.service.disableLearning <- b
}

func (b *BridgeInstance) SetMAT(matRing *dpdk.Ring) error {
	return b.control(BRIDGE_CMD_SET_MAT, matRing, nil, nil)
}

func (b *BridgeInstance) MACTable() []vswitch.BridgeMACEntry {
	b.service.dumpMACTable <- b
	return <-b.macTableCh
}

//
// FDB related internal API
//
// addMACEntry() and deleteMACEntry() are not thread safe. Must be called from
// the same context as those who accesses macTable and ageOut. In our implmentation,
// i.e. from bridgeService only.
//
func (b *BridgeInstance) addMACEntry(mac macAddress, vifidx vswitch.VIFIndex) {
	// Check if we already have an entry
	if elem := b.macTable.Find(mac); elem != nil {
		entry := elem.Value.(*vswitch.BridgeMACEntry)

		// Do not update static entry
		if entry.EntryType == vswitch.EntryStatic {
			return
		}

		// If the entry is the same, we just push them to the end
		// of the list.
		if entry.VIF.Index() == vifidx {
			expire := time.Now().Unix() + int64(b.agingTime)
			b.macTable.Add(mac, entry)
			b.ageOut.Add(mac, &macAgeOut{mac, expire})
			return
		}
	}

	vif, ok := b.vifs[vifidx]
	if !ok {
		log.Err("%s: Unknown VIF %d. Ignore.", b.base.Name(), vifidx)
		return
	}

	// Either new entry or VIF has changed
	now := time.Now().Unix()
	entry := &vswitch.BridgeMACEntry{
		MACAddress: mac.HardwareAddr(),
		VIF:        vif,
		Age:        uint64(now),
		EntryType:  vswitch.EntryDynamic,
	}

	b.macTable.Add(mac, entry)
	b.ageOut.Add(mac, &macAgeOut{mac, now + int64(b.agingTime)})
	b.control(BRIDGE_CMD_MAC_ADD, vif.BridgeInput(), &mac, nil)
}

func (b *BridgeInstance) addStaticMACEntry(mac macAddress, vifidx vswitch.VIFIndex) {
	// Ignore the existing static entry.
	if elem := b.macTable.Find(mac); elem != nil {
		entry := elem.Value.(*vswitch.BridgeMACEntry)

		if entry.EntryType == vswitch.EntryDynamic {
			b.ageOut.Remove(mac)
		}

		if entry.VIF.Index() == vifidx {
			entry.EntryType = vswitch.EntryStatic
			return
		}
	}

	vif, ok := b.vifs[vifidx]
	if !ok {
		log.Err("%s: Unknown VIF %d. Ignore.", b.base.Name(), vifidx)
		return
	}

	entry := &vswitch.BridgeMACEntry{
		MACAddress: mac.HardwareAddr(),
		VIF:        vif,
		Age:        uint64(time.Now().Unix()),
		EntryType:  vswitch.EntryDynamic,
	}

	b.macTable.Add(mac, entry)
	b.control(BRIDGE_CMD_MAC_ADD, vif.BridgeInput(), &mac, nil)
}

func (b *BridgeInstance) deleteMACEntry(mac macAddress) {
	// Remove from hash lists
	b.ageOut.Remove(mac)
	b.macTable.Remove(mac)

	// Delete from runtime instance
	b.control(BRIDGE_CMD_MAC_DELETE, nil, &mac, nil)
}

func (b *BridgeInstance) deleteStaticMACEntry(mac macAddress) {
	b.deleteMACEntry(mac)
}

func (b *BridgeInstance) dumpMACTable() []vswitch.BridgeMACEntry {
	now := uint64(time.Now().Unix())
	mt := make([]vswitch.BridgeMACEntry, 0, b.macTable.List().Len())
	for _, elem := range b.macTable.AllElements() {
		entry := *elem.Value.(*vswitch.BridgeMACEntry)
		entry.Age = now - entry.Age
		mt = append(mt, entry)
	}
	return mt
}

/*
 * Do module set up here.
 */
func init() {
	if l, err := vlog.New(moduleName); err == nil {
		log = l
	} else {
		log.Fatalf("Can't create logger: %s", moduleName)
	}

	rp := &vswitch.RingParam{
		Count:    C.MAX_BRIDGE_MBUFS,
		SocketId: dpdk.SOCKET_ID_ANY,
	}

	if err := vswitch.RegisterModule(moduleName, newBridgeInstance, rp, vswitch.TypeBridge); err != nil {
		log.Fatalf("Failed to register the class.")
	}
}
