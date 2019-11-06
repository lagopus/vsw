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

package ethdev

/*
#cgo CFLAGS: -I${SRCDIR}/../../include -m64 -pthread -O3 -msse4.2
#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all

#include <rte_config.h>
#include <rte_ethdev.h>

#include "ethdev.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/notifier"
	"github.com/lagopus/vsw/vswitch"
	vlog "github.com/lagopus/vsw/vswitch/log"
)

const (
	moduleName = "ethdev"
)

type EthdevInstance struct {
	base        *vswitch.BaseInstance
	counter     *vswitch.Counter
	dev         *dpdk.EthDev
	rts         *ethdevRuntime
	rx_instance *vswitch.RuntimeInstance
	tx_instance *vswitch.RuntimeInstance
	rx_param    *C.struct_ethdev_rx_instance
	tx_param    *C.struct_ethdev_tx_instance
	cname       *C.char
	enabled     bool
	mutex       sync.Mutex

	// XXX: Do we really need this?
	mode      vswitch.VLANMode
	nativeVID vswitch.VID
}

type EthdevVIFInstance struct {
	vif     *vswitch.VIF
	iface   *EthdevInstance
	output  *dpdk.Ring
	noti    *notifier.Notifier
	notiCh  chan notifier.Notification
	counter *vswitch.Counter
}

type ethdevRuntime struct {
	rx     *vswitch.Runtime
	tx     *vswitch.Runtime
	refcnt int
	id     int
}

var runtimes = make(map[int]*ethdevRuntime)

var log = vswitch.Logger
var mutex sync.Mutex

//
// TOML Config
//
type ethdevConfigSection struct {
	Ethdev ethdevConfig
}

type ethdevConfig struct {
	RxCore         uint `toml:"rx_core"`         // Slave core for RX.
	TxCore         uint `toml:"tx_core"`         // Slave core for TX.
	ForceLinearize bool `toml:"force_linearize"` // Whether to linearize multi-sgement mbuf.
}

var config ethdevConfig

var defaultConfig = ethdevConfig{
	RxCore:         2,
	TxCore:         3,
	ForceLinearize: false,
}

//
// Interface Instance
//

func getRuntimeForEthdev(dev *dpdk.EthDev) (*ethdevRuntime, error) {
	mutex.Lock()
	defer mutex.Unlock()

	sid := dev.SocketID()
	if rts, ok := runtimes[sid]; ok {
		rts.refcnt++
		return rts, nil
	}

	pool := vswitch.GetDpdkResource().Mempools[sid]
	if pool == nil {
		return nil, fmt.Errorf("No memory pool for socket %d", sid)
	}

	// Create runtime argument
	param := (*C.struct_ethdev_runtime_param)(C.calloc(1, C.sizeof_struct_ethdev_runtime_param))
	param.pool = (*C.struct_rte_mempool)(unsafe.Pointer(pool))
	param.iopl_required = (C.bool)(dev.RequireIOPL())

	rxOps := vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.ethdev_rx_runtime_ops))
	rx_rt, err := vswitch.NewRuntime(config.RxCore, "ethdev_rx", rxOps, unsafe.Pointer(param))
	if err != nil {
		return nil, err
	}
	if err := rx_rt.Enable(); err != nil {
		return nil, err
	}

	txOps := vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.ethdev_tx_runtime_ops))
	tx_rt, err := vswitch.NewRuntime(config.TxCore, "ethdev_tx", txOps, unsafe.Pointer(param))
	if err != nil {
		rx_rt.Terminate()
		return nil, err
	}
	if err := tx_rt.Enable(); err != nil {
		return nil, err
	}

	rts := &ethdevRuntime{rx_rt, tx_rt, 1, sid}
	runtimes[sid] = rts
	return rts, nil
}

func (er *ethdevRuntime) free() {
	mutex.Lock()
	defer mutex.Unlock()

	er.refcnt--
	if er.refcnt == 0 {
		er.rx.Terminate()
		er.tx.Terminate()
		delete(runtimes, er.id)
	}
}

func openEthDev(name string) (*dpdk.EthDev, error) {
	dev, err := dpdk.EthDevOpenByName(name)
	if err != nil {
		return nil, fmt.Errorf("Can't open %v: %v", name, err)
	}

	// Construct port configuration
	port_conf := &C.struct_rte_eth_conf{}

	if C.MAX_PACKET_SZ > 2048 {
		port_conf.rxmode.offloads = C.DEV_RX_OFFLOAD_JUMBO_FRAME
		port_conf.rxmode.max_rx_pkt_len = 9000
	}

	dev_info := (*C.struct_rte_eth_dev_info)(unsafe.Pointer(dev.DevInfo()))
	port_conf.rx_adv_conf.rss_conf.rss_hf = C.ETH_RSS_IP & dev_info.flow_type_rss_offloads

	// Limit numbers of rx/tx queues to 1 each
	if dev.Configure(1, 1, (*dpdk.EthConf)(unsafe.Pointer(port_conf))) != 0 {
		return nil, fmt.Errorf("Can't configure %v", name)
	}

	// Set the device to promiscuous mode
	dev.SetPromiscuous(true)
	if dev.Promiscuous() != true {
		return nil, fmt.Errorf("Can't set  %v to promiscuous mode", name)
	}

	return dev, nil
}

func instantiate(runtime *vswitch.Runtime, param unsafe.Pointer) (*vswitch.RuntimeInstance, error) {
	ri, err := vswitch.NewRuntimeInstance((vswitch.LagopusInstance)(param))
	if err != nil {
		return nil, fmt.Errorf("Can't create a new instance: %v", err)
	}

	if err := runtime.Register(ri); err != nil {
		return nil, fmt.Errorf("Can't register an instance: %v", err)
	}

	return ri, nil
}

func loadConfig() {
	// Get configuration
	c := ethdevConfigSection{defaultConfig}
	vswitch.GetConfig().Decode(&c)
	config = c.Ethdev
}

var once sync.Once

// newEthdevInstance creates the ethdev instance.
func newEthdevInstance(base *vswitch.BaseInstance, priv interface{}) (vswitch.Instance, error) {
	once.Do(loadConfig)

	var dev *dpdk.EthDev

	switch p := priv.(type) {
	default:
		return nil, errors.New("Bad parameter")
	case string:
		var err error
		if dev, err = openEthDev(p); err != nil {
			return nil, err
		}
	}

	// Get the runtime appropriate for the ethdev
	rts, err := getRuntimeForEthdev(dev)
	if err != nil {
		return nil, err
	}

	// Create & register ethdev instance
	e := &EthdevInstance{
		base:     base,
		counter:  base.Counter(),
		dev:      dev,
		rts:      rts,
		rx_param: (*C.struct_ethdev_rx_instance)(C.calloc(1, C.sizeof_struct_ethdev_rx_instance)),
		tx_param: (*C.struct_ethdev_tx_instance)(C.calloc(1, C.sizeof_struct_ethdev_tx_instance)),
		mode:     vswitch.AccessMode,
		enabled:  false,
	}
	e.cname = C.CString(base.Name())

	// Prepare RX Instance
	e.rx_param.common.base.name = e.cname
	e.rx_param.common.base.outputs = &e.rx_param.common.o[0]
	e.rx_param.common.port_id = C.uint16_t(dev.PortID())
	e.rx_param.common.counter = (*C.struct_vsw_counter)(unsafe.Pointer(e.counter))
	e.rx_param.nb_rx_desc = MbufLen / 4 // XXX: Must be configurable

	e.rx_instance, err = instantiate(rts.rx, unsafe.Pointer(e.rx_param))
	if err != nil {
		e.Free()
		return nil, err
	}

	// Prepare TX Instance
	e.tx_param.common.base.name = e.cname
	e.tx_param.common.base.input = (*C.struct_rte_ring)(unsafe.Pointer(e.base.Input()))
	// We don't actually need outputs for TX, but we use them to check validity of VID
	e.tx_param.common.base.outputs = &e.tx_param.common.o[0]
	e.tx_param.common.port_id = C.uint16_t(dev.PortID())
	e.tx_param.common.counter = (*C.struct_vsw_counter)(unsafe.Pointer(e.counter))
	e.tx_param.nb_tx_desc = MbufLen // XXX: Must be configurable
	e.tx_param.force_linearize = C.bool(config.ForceLinearize)

	e.tx_instance, err = instantiate(rts.tx, unsafe.Pointer(e.tx_param))
	if err != nil {
		e.Free()
		return nil, err
	}

	return e, nil
}

func (e *EthdevInstance) Free() {
	if e.rx_instance != nil {
		e.rx_instance.Unregister()
	}

	if e.tx_instance != nil {
		e.tx_instance.Unregister()
	}

	C.free(unsafe.Pointer(e.rx_param))
	C.free(unsafe.Pointer(e.tx_param))
	C.free(unsafe.Pointer(e.cname))

	e.rx_param = nil
	e.tx_param = nil
	e.cname = nil

	e.rts.free()
}

func (e *EthdevInstance) Enable() error {
	if !e.enabled {
		e.dev.Start()

		if err := e.tx_instance.Enable(); err != nil {
			return err
		}

		if err := e.rx_instance.Enable(); err != nil {
			e.rx_instance.Disable()
			return err
		}

		e.enabled = true
	}
	return nil
}

func (e *EthdevInstance) Disable() {
	// XXX: Do we have to flush all mbufs in the tx queue
	// before disabling the interface?

	if e.enabled {
		e.dev.Stop()

		e.rx_instance.Disable()
		e.tx_instance.Disable()
		e.enabled = false
	}
}

//
// InterfaceInstance interface
//

func (e *EthdevInstance) SetMACAddress(mac net.HardwareAddr) error {
	oldmac := e.dev.MACAddr()

	if err := e.dev.SetDefaultMACAddr(mac); err != nil {
		return fmt.Errorf("SetMACAddress failed: %v", err)
	}

	if err := e.control(&controlMsg{cmd: ETHDEV_CMD_UPDATE_MAC}); err != nil {
		e.dev.SetDefaultMACAddr(oldmac)
		return fmt.Errorf("Refreshing self MAC address failed: %v", err)
	}

	return nil
}

func (e *EthdevInstance) MACAddress() net.HardwareAddr {
	return e.dev.MACAddr()
}

func (e *EthdevInstance) MTU() vswitch.MTU {
	mtu := e.dev.MTU()
	if mtu < 0 {
		return 0
	}
	return vswitch.MTU(mtu)
}

func (e *EthdevInstance) SetMTU(mtu vswitch.MTU) error {
	return e.dev.SetMTU(uint16(mtu))
}

func (e *EthdevInstance) InterfaceMode() vswitch.VLANMode {
	return e.mode
}

func (e *EthdevInstance) LinkStatus() bool {
	link := e.dev.Link(false)
	return link.StatusUp
}

type devcmd int

const (
	ETHDEV_CMD_ADD_VID              = devcmd(C.ETHDEV_CMD_ADD_VID)
	ETHDEV_CMD_DELETE_VID           = devcmd(C.ETHDEV_CMD_DELETE_VID)
	ETHDEV_CMD_SET_TRUNK_MODE       = devcmd(C.ETHDEV_CMD_SET_TRUNK_MODE)
	ETHDEV_CMD_SET_ACCESS_MODE      = devcmd(C.ETHDEV_CMD_SET_ACCESS_MODE)
	ETHDEV_CMD_SET_NATIVE_VID       = devcmd(C.ETHDEV_CMD_SET_NATIVE_VID)
	ETHDEV_CMD_SET_DST_SELF_FORWARD = devcmd(C.ETHDEV_CMD_SET_DST_SELF_FORWARD)
	ETHDEV_CMD_SET_DST_BC_FORWARD   = devcmd(C.ETHDEV_CMD_SET_DST_BC_FORWARD)
	ETHDEV_CMD_SET_DST_MC_FORWARD   = devcmd(C.ETHDEV_CMD_SET_DST_MC_FORWARD)
	ETHDEV_CMD_UPDATE_MAC           = devcmd(C.ETHDEV_CMD_UPDATE_MAC)
)

var cmdstr = map[devcmd]string{
	ETHDEV_CMD_ADD_VID:              "Add VID",
	ETHDEV_CMD_DELETE_VID:           "Delete VID",
	ETHDEV_CMD_SET_TRUNK_MODE:       "Set to TRUNK",
	ETHDEV_CMD_SET_ACCESS_MODE:      "Set to ACCESS",
	ETHDEV_CMD_SET_NATIVE_VID:       "Set Native VID",
	ETHDEV_CMD_SET_DST_SELF_FORWARD: "Set Dst Self Forward",
	ETHDEV_CMD_SET_DST_BC_FORWARD:   "Set Dst Broadcast Forward",
	ETHDEV_CMD_SET_DST_MC_FORWARD:   "Set Dst Multicast Forward",
	ETHDEV_CMD_UPDATE_MAC:           "Refresh self MAC address",
}

func (c devcmd) String() string {
	return cmdstr[c]
}

type controlMsg struct {
	cmd     devcmd
	vid     vswitch.VID
	out     *dpdk.Ring
	vif     vswitch.VIFIndex
	counter *vswitch.Counter
}

func (e *EthdevInstance) control(cmd *controlMsg) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	p := &e.tx_param.param
	p.cmd = C.ethdev_cmd_t(cmd.cmd)
	p.vid = C.int(cmd.vid)
	p.output = (*C.struct_rte_ring)(unsafe.Pointer(cmd.out))
	p.index = C.vifindex_t(cmd.vif)
	p.counter = (*C.struct_vsw_counter)(unsafe.Pointer(cmd.counter))

	rc, err := e.rx_instance.Control(unsafe.Pointer(p))
	if rc == false || err != nil {
		return fmt.Errorf("%v Failed: %v", cmd, err)
	}

	rc, err = e.tx_instance.Control(unsafe.Pointer(p))
	if rc == false || err != nil {
		return fmt.Errorf("%v Failed: %v", cmd, err)
	}

	return nil
}

func (e *EthdevInstance) SetInterfaceMode(mode vswitch.VLANMode) error {
	msg := &controlMsg{}

	if mode == vswitch.AccessMode {
		msg.cmd = ETHDEV_CMD_SET_ACCESS_MODE
	} else {
		msg.cmd = ETHDEV_CMD_SET_TRUNK_MODE
	}

	if err := e.control(msg); err != nil {
		return err
	}

	e.mode = mode
	return nil
}

func (e *EthdevInstance) AddVID(vid vswitch.VID) error {
	return nil
}

func (e *EthdevInstance) DeleteVID(vid vswitch.VID) error {
	return nil
}

func (e *EthdevInstance) SetNativeVID(vid vswitch.VID) error {
	if e.nativeVID != vid {
		// TODO: Need to update the native VID
		e.nativeVID = vid
	}
	return nil
}

//
// VIF Interface
//

func (e *EthdevInstance) NewVIF(vif *vswitch.VIF) (vswitch.VIFInstance, error) {
	ev := &EthdevVIFInstance{
		vif:     vif,
		iface:   e,
		noti:    vif.Rules().Notifier(),
		counter: vif.Counter(),
	}

	ev.notiCh = ev.noti.Listen()
	go ev.listener()

	return ev, nil
}

func (ev *EthdevVIFInstance) Free() {
	ev.noti.Close(ev.notiCh)
}

func (ev *EthdevVIFInstance) SetVRF(vrf *vswitch.VRF) {
}

func (ev *EthdevVIFInstance) listener() {
	for n := range ev.notiCh {
		rule, ok := n.Value.(vswitch.Rule)
		if !ok {
			continue
		}

		msg := &controlMsg{}

		switch rule.Match {
		case vswitch.MatchEthDstSelf:
			msg.cmd = ETHDEV_CMD_SET_DST_SELF_FORWARD
		case vswitch.MatchEthDstBC:
			msg.cmd = ETHDEV_CMD_SET_DST_BC_FORWARD
		case vswitch.MatchEthDstMC:
			msg.cmd = ETHDEV_CMD_SET_DST_MC_FORWARD
		default:
			continue
		}

		msg.vid = ev.vif.VID()
		if n.Type == notifier.Add {
			msg.out = rule.Ring
		}
		if err := ev.iface.control(msg); err != nil {
			log.Printf("%s failed: %v", msg.cmd, err)
		}
	}
}

func (ev *EthdevVIFInstance) Enable() error {
	msg := &controlMsg{
		cmd:     ETHDEV_CMD_ADD_VID,
		vid:     ev.vif.VID(),
		out:     ev.vif.Output(),
		vif:     ev.vif.Index(),
		counter: ev.counter,
	}
	if ev.iface.mode == vswitch.TrunkMode && msg.vid == ev.iface.nativeVID {
		msg.cmd = ETHDEV_CMD_SET_NATIVE_VID
	}
	return ev.iface.control(msg)
}

func (ev *EthdevVIFInstance) Disable() {
	ev.iface.control(&controlMsg{cmd: ETHDEV_CMD_DELETE_VID, vid: ev.vif.VID()})
}

///////////////////////////////////////////////////////
const (
	MbufLen = C.ETHDEV_MBUF_LEN
)

/*
 * Register module here
 */
func init() {
	if l, err := vlog.New(moduleName); err == nil {
		log = l
	} else {
		log.Fatalf("Can't create logger: %s", moduleName)
	}

	rp := &vswitch.RingParam{
		Count:    MbufLen,
		SocketId: dpdk.SOCKET_ID_ANY,
	}

	if err := vswitch.RegisterModule(moduleName, newEthdevInstance, rp, vswitch.TypeInterface); err != nil {
		log.Fatalf("Failed to register a module '%s': %v", moduleName, err)
		return
	}
}
