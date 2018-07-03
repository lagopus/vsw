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

package ethdev

/*
#cgo CFLAGS: -I${SRCDIR}/../../include -I/usr/local/include/dpdk -m64 -pthread -O3 -msse4.2
#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all -L/usr/local/lib -ldpdk

#include <rte_config.h>
#include <rte_ethdev.h>

#include "ethdev.h"

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
	"fmt"
	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/notifier"
	"github.com/lagopus/vsw/vswitch"
	"net"
	"sync"
	"unsafe"
)

const (
	moduleName = "ethdev"
)

type EthdevInstance struct {
	base        *vswitch.BaseInstance
	dev         *dpdk.EthDev
	rts         *ethdevRuntime
	rx_instance *vswitch.RuntimeInstance
	tx_instance *vswitch.RuntimeInstance
	rx_param    *C.struct_ethdev_rx_instance
	tx_param    *C.struct_ethdev_tx_instance
	cname       *C.char
	enabled     bool

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
	running bool
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
	RxCore uint `toml:"rx_core"`
	TxCore uint `toml:"tx_core"`
}

var config ethdevConfig

var defaultConfig = ethdevConfig{
	RxCore: 2,
	TxCore: 3,
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
	param := C.struct_ethdev_runtime_param{
		pool: (*C.struct_rte_mempool)(unsafe.Pointer(pool)),
	}

	rxOps := vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.ethdev_rx_runtime_ops))
	rx_rt, err := vswitch.NewRuntime(config.RxCore, "ethdev_rx", rxOps, unsafe.Pointer(&param))
	if err != nil {
		return nil, err
	}
	if err := rx_rt.Enable(); err != nil {
		return nil, err
	}

	txOps := vswitch.LagopusRuntimeOps(unsafe.Pointer(&C.ethdev_tx_runtime_ops))
	tx_rt, err := vswitch.NewRuntime(config.TxCore, "ethdev_tx", txOps, nil)
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

	// Limit numbers of rx/tx queues to 1 each
	if dev.Configure(1, 1, (*dpdk.EthConf)(unsafe.Pointer(C.get_port_conf()))) != 0 {
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
		dev:      dev,
		rts:      rts,
		rx_param: (*C.struct_ethdev_rx_instance)(C.malloc(C.sizeof_struct_ethdev_rx_instance)),
		tx_param: (*C.struct_ethdev_tx_instance)(C.malloc(C.sizeof_struct_ethdev_tx_instance)),
		mode:     vswitch.AccessMode,
		enabled:  false,
	}
	e.cname = C.CString(base.Name())

	// Prepare RX Instance
	e.rx_param.common.base.name = e.cname
	e.rx_param.common.base.outputs = &e.rx_param.common.o[0]
	e.rx_param.common.port_id = C.unsigned(dev.PortID())
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
	e.tx_param.common.port_id = C.unsigned(dev.PortID())
	e.tx_param.nb_tx_desc = MbufLen // XXX: Must be configurable

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

	if err := e.control(ETHDEV_CMD_UPDATE_MAC, 0, nil, 0); err != nil {
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

func (e *EthdevInstance) control(cmd devcmd, vid vswitch.VID, out *dpdk.Ring, index vswitch.VIFIndex) error {
	p := C.struct_ethdev_control_param{
		cmd:    C.ethdev_cmd_t(cmd),
		vid:    C.int(vid),
		output: (*C.struct_rte_ring)(unsafe.Pointer(out)),
		index:  C.vifindex_t(index),
	}

	rc, err := e.rx_instance.Control(unsafe.Pointer(&p))
	if rc == false || err != nil {
		return fmt.Errorf("%v Failed: %v", cmd, err)
	}

	rc, err = e.tx_instance.Control(unsafe.Pointer(&p))
	if rc == false || err != nil {
		return fmt.Errorf("%v Failed: %v", cmd, err)
	}

	return nil
}

func (e *EthdevInstance) SetInterfaceMode(mode vswitch.VLANMode) error {
	cmd := ETHDEV_CMD_SET_TRUNK_MODE
	if mode == vswitch.AccessMode {
		cmd = ETHDEV_CMD_SET_ACCESS_MODE
	}

	if err := e.control(cmd, 0, nil, 0); err != nil {
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
		vif:   vif,
		iface: e,
		noti:  vif.Rules().Notifier(),
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

		switch rule.Match {
		case vswitch.MATCH_ANY:
			// Default Output (The same as Output())

		case vswitch.MATCH_ETH_DST_SELF:
			if err := ev.iface.control(ETHDEV_CMD_SET_DST_SELF_FORWARD, ev.vif.VID(), rule.Ring, 0); err != nil {
				log.Printf("Setting dst self Forward failed: %v", err)
			}

		case vswitch.MATCH_ETH_DST_BC:
			if err := ev.iface.control(ETHDEV_CMD_SET_DST_BC_FORWARD, ev.vif.VID(), rule.Ring, 0); err != nil {
				log.Printf("Setting dst broadcast Forward failed: %v", err)
			}

		case vswitch.MATCH_ETH_DST_MC:
			if err := ev.iface.control(ETHDEV_CMD_SET_DST_MC_FORWARD, ev.vif.VID(), rule.Ring, 0); err != nil {
				log.Printf("Setting dst multicast Forward failed: %v", err)
			}
		}
	}
}

func (ev *EthdevVIFInstance) Enable() error {
	cmd := ETHDEV_CMD_ADD_VID
	vid := ev.vif.VID()
	if ev.iface.mode == vswitch.TrunkMode && vid == ev.iface.nativeVID {
		cmd = ETHDEV_CMD_SET_NATIVE_VID
	}
	return ev.iface.control(cmd, vid, ev.vif.Output(), ev.vif.Index())
}

func (ev *EthdevVIFInstance) Disable() {
	ev.iface.control(ETHDEV_CMD_DELETE_VID, ev.vif.VID(), nil, 0)
}

///////////////////////////////////////////////////////
const (
	MbufLen = C.ETHDEV_MBUF_LEN
)

/*
 * Register module here
 */
func init() {
	rp := &vswitch.RingParam{
		Count:    MbufLen,
		SocketId: dpdk.SOCKET_ID_ANY,
	}

	if err := vswitch.RegisterModule(moduleName, newEthdevInstance, rp, vswitch.TypeInterface); err != nil {
		log.Fatalf("Failed to register a module '%s': %v", moduleName, err)
		return
	}
}
