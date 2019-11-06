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

package dpdk

/*
#include <stdlib.h>
#include <stdbool.h>
#include <rte_config.h>
#include <rte_ethdev.h>
#include <rte_version.h>
#include <rte_eal.h>

static unsigned long check_iopl() {
	unsigned long reg;
	asm volatile ("pushf; pop %0" : "=r" (reg));
	return reg & 0x3000;
}

static bool eth_link_duplex(struct rte_eth_link *link) {
	return link->link_duplex == ETH_LINK_FULL_DUPLEX;
}

static bool eth_link_status(struct rte_eth_link *link) {
	return link->link_status == ETH_LINK_UP;
}

static uint16_t eth_dev_count() {
#if RTE_VER_YEAR < 18
       return rte_eth_dev_count();
#else
       return rte_eth_dev_count_avail();
#endif
}

*/
import "C"

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

type EthConf C.struct_rte_eth_conf
type EthRxConf C.struct_rte_eth_rxconf
type EthTxConf C.struct_rte_eth_txconf
type EthDevInfo C.struct_rte_eth_dev_info

type EthDev struct {
	port_id     uint16
	socket_id   int
	requireIOPL bool
}

type EthRxQueue struct {
	dev      *EthDev
	queue_id uint
}

type EthTxQueue struct {
	dev      *EthDev
	queue_id uint
}

func allocEthDev(port_id uint16) *EthDev {
	dev := &EthDev{port_id, int(C.rte_eth_dev_socket_id(C.uint16_t(port_id))), false}

	C.rte_eal_iopl_init()

	// IOPL is required for net_virito driver only.
	if dev.DevInfo().DriverName() == "net_virtio" {
		dev.requireIOPL = true
	}

	return dev
}

func EthDevOpen(port_id uint16) (*EthDev, error) {
	if int(C.rte_eth_dev_is_valid_port(C.uint16_t(port_id))) == 0 {
		return nil, fmt.Errorf("Invalid port ID: %v", port_id)
	}
	return allocEthDev(port_id), nil
}

func EthDevOpenByName(name string) (*EthDev, error) {
	pid, err := EthDevGetPortByName(name)
	if err != nil {
		return nil, err
	}
	return allocEthDev(pid), nil
}

func EthDevCount() uint {
	return uint(C.eth_dev_count())
}

func EthDevGetPortByName(name string) (uint16, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var cpid C.uint16_t
	if rc := int(C.rte_eth_dev_get_port_by_name(cname, &cpid)); rc < 0 {
		return 0, syscall.Errno(-rc)
	}
	return uint16(cpid), nil
}

func EthDevGetNameByPort(port_id uint16) (string, error) {
	var cname [C.RTE_ETH_NAME_MAX_LEN]C.char
	if rc := int(C.rte_eth_dev_get_name_by_port(C.uint16_t(port_id), &cname[0])); rc < 0 {
		return "", syscall.Errno(-rc)
	}
	return C.GoString(&cname[0]), nil
}

func (re *EthDev) PortID() uint16 {
	return re.port_id
}

func (re *EthDev) SocketID() int {
	return re.socket_id
}

// RequireIOPL returns if the PMD driver requires IOPL.
// Returns true if IOPL is required. False otherwise.
func (re *EthDev) RequireIOPL() bool {
	return re.requireIOPL
}

func (re *EthDev) checkIOPL() error {
	if !re.requireIOPL {
		return nil
	}
	if C.check_iopl() != 0 {
		return nil
	}
	if C.rte_eal_iopl_init() != 0 {
		return errors.New("rte_eal_iopl_init() failed.")
	}
	return nil
}

func (re *EthDev) Configure(nb_rx_queue, nb_tx_queue uint, eth_conf *EthConf) int {
	if err := re.checkIOPL(); err != nil {
		return -1
	}
	return int(C.rte_eth_dev_configure(C.uint16_t(re.port_id),
		C.uint16_t(nb_rx_queue), C.uint16_t(nb_tx_queue),
		(*C.struct_rte_eth_conf)(eth_conf)))
}

func (re *EthDev) RxQueueSetup(rx_queue_id, nb_rx_desc uint, socket_id int,
	rx_conf *EthRxConf, mb_pool *MemPool) *EthRxQueue {

	if int(C.rte_eth_rx_queue_setup(C.uint16_t(re.port_id),
		C.uint16_t(rx_queue_id), C.uint16_t(nb_rx_desc),
		C.unsigned(socket_id), (*C.struct_rte_eth_rxconf)(rx_conf),
		(*C.struct_rte_mempool)(mb_pool))) != 0 {
		return nil
	}

	return &EthRxQueue{
		dev:      re,
		queue_id: rx_queue_id,
	}
}

func (re *EthDev) TxQueueSetup(tx_queue_id, nb_tx_desc uint, socket_id int,
	tx_conf *EthTxConf) *EthTxQueue {

	if int(C.rte_eth_tx_queue_setup(C.uint16_t(re.port_id),
		C.uint16_t(tx_queue_id), C.uint16_t(nb_tx_desc),
		C.unsigned(socket_id), (*C.struct_rte_eth_txconf)(tx_conf))) != 0 {
		return nil
	}

	return &EthTxQueue{
		dev:      re,
		queue_id: tx_queue_id,
	}
}

func (re *EthDev) DevInfo() *EthDevInfo {
	if err := re.checkIOPL(); err != nil {
		return nil
	}
	var di EthDevInfo
	C.rte_eth_dev_info_get(C.uint16_t(re.port_id), (*C.struct_rte_eth_dev_info)(&di))
	return &di
}

func (re *EthDev) SetDefaultMACAddr(mac net.HardwareAddr) error {
	if err := re.checkIOPL(); err != nil {
		return err
	}

	rc := int(C.rte_eth_dev_default_mac_addr_set(C.uint16_t(re.port_id), (*C.struct_ether_addr)(unsafe.Pointer(&mac[0]))))
	switch rc {
	case -C.ENOTSUP:
		return errors.New("Hardware doesn't support setting MAC Address")
	case -C.EINVAL:
		return errors.New("Invalid MAC Address")
	}
	return nil
}

func (re *EthDev) MACAddr() net.HardwareAddr {
	addr := make([]byte, C.ETHER_ADDR_LEN)
	C.rte_eth_macaddr_get(C.uint16_t(re.port_id), (*C.struct_ether_addr)(unsafe.Pointer(&addr[0])))
	return (net.HardwareAddr)(addr)
}

func (re *EthDev) GetMaxQueues() (rxQueueMax, txQueueMax uint) {
	var dev_info C.struct_rte_eth_dev_info

	C.rte_eth_dev_info_get(C.uint16_t(re.port_id), &dev_info)

	rxQueueMax = uint(dev_info.max_rx_queues)
	txQueueMax = uint(dev_info.max_tx_queues)

	return
}

func (re *EthDev) MTU() int {
	var mtu C.uint16_t
	if C.rte_eth_dev_get_mtu(C.uint16_t(re.port_id), &mtu) == 0 {
		return int(mtu)
	}
	return -1
}

func (re *EthDev) SetMTU(mtu uint16) error {
	if rc := int(C.rte_eth_dev_set_mtu(C.uint16_t(re.port_id), C.uint16_t(mtu)-C.ETHER_HDR_LEN)); rc < 0 {
		return syscall.Errno(-rc)
	}
	return nil
}

func (re *EthDev) Promiscuous() bool {
	return C.rte_eth_promiscuous_get(C.uint16_t(re.port_id)) == 1
}

func (re *EthDev) SetPromiscuous(enable bool) {
	if enable {
		C.rte_eth_promiscuous_enable(C.uint16_t(re.port_id))
	} else {
		C.rte_eth_promiscuous_disable(C.uint16_t(re.port_id))
	}
}

func (re *EthDev) AllMulticast() bool {
	return C.rte_eth_allmulticast_get(C.uint16_t(re.port_id)) == 1
}

func (re *EthDev) SetAllMulticast(enable bool) {
	if enable {
		C.rte_eth_allmulticast_enable(C.uint16_t(re.port_id))
	} else {
		C.rte_eth_allmulticast_disable(C.uint16_t(re.port_id))
	}
}

func (re *EthDev) Start() int {
	if err := re.checkIOPL(); err != nil {
		return -1
	}
	return int(C.rte_eth_dev_start(C.uint16_t(re.port_id)))
}

func (re *EthDev) Stop() {
	if err := re.checkIOPL(); err != nil {
		return
	}
	C.rte_eth_dev_stop(C.uint16_t(re.port_id))
}

func (re *EthDev) SetLinkUp() int {
	return int(C.rte_eth_dev_set_link_up(C.uint16_t(re.port_id)))
}

func (re *EthDev) SetLinkDown() int {
	return int(C.rte_eth_dev_set_link_down(C.uint16_t(re.port_id)))
}

type EthStats struct {
	InPackets  uint64
	OutPackets uint64
	InBytes    uint64
	OutBytes   uint64
	InErrors   uint64
	OutErrors  uint64
}

func (re *EthDev) Stats() (*EthStats, error) {
	var stats C.struct_rte_eth_stats
	if rc := int(C.rte_eth_stats_get(C.uint16_t(re.port_id), &stats)); rc != 0 {
		return nil, syscall.Errno(-rc)
	}

	return &EthStats{
		InPackets:  uint64(stats.ipackets),
		OutPackets: uint64(stats.opackets),
		InBytes:    uint64(stats.ibytes),
		OutBytes:   uint64(stats.obytes),
		InErrors:   uint64(stats.ierrors),
		OutErrors:  uint64(stats.oerrors),
	}, nil
}

type EthLinkSpeed int

const (
	EthLinkSpeedNone = EthLinkSpeed(C.ETH_SPEED_NUM_NONE)
	EthLinkSpeed10M  = EthLinkSpeed(C.ETH_SPEED_NUM_10M)
	EthLinkSpeed100M = EthLinkSpeed(C.ETH_SPEED_NUM_100M)
	EthLinkSpeed1G   = EthLinkSpeed(C.ETH_SPEED_NUM_1G)
	EthLinkSpeed2_5G = EthLinkSpeed(C.ETH_SPEED_NUM_2_5G)
	EthLinkSpeed5G   = EthLinkSpeed(C.ETH_SPEED_NUM_5G)
	EthLinkSpeed10G  = EthLinkSpeed(C.ETH_SPEED_NUM_10G)
	EthLinkSpeed20G  = EthLinkSpeed(C.ETH_SPEED_NUM_20G)
	EthLinkSpeed25G  = EthLinkSpeed(C.ETH_SPEED_NUM_25G)
	EthLinkSpeed40G  = EthLinkSpeed(C.ETH_SPEED_NUM_40G)
	EthLinkSpeed50G  = EthLinkSpeed(C.ETH_SPEED_NUM_50G)
	EthLinkSpeed56G  = EthLinkSpeed(C.ETH_SPEED_NUM_56G)
	EthLinkSpeed100G = EthLinkSpeed(C.ETH_SPEED_NUM_100G)
)

func (e EthLinkSpeed) String() string {
	var speed = map[EthLinkSpeed]string{
		EthLinkSpeedNone: "Not defined",
		EthLinkSpeed10M:  "10 Mbps",
		EthLinkSpeed100M: "100 Mbps",
		EthLinkSpeed1G:   "1 Gbps",
		EthLinkSpeed2_5G: "2.5 Gbps",
		EthLinkSpeed5G:   "5 Gbps",
		EthLinkSpeed10G:  "10 Gbps",
		EthLinkSpeed20G:  "20 Gbps",
		EthLinkSpeed25G:  "25 Gbps",
		EthLinkSpeed40G:  "40 Gbps",
		EthLinkSpeed50G:  "50 Gbps",
		EthLinkSpeed56G:  "56 Gbps",
		EthLinkSpeed100G: "100 Gbps",
	}
	return speed[e]
}

type EthLink struct {
	Speed      EthLinkSpeed
	DuplexFull bool
	StatusUp   bool
}

func (re *EthDev) Link(wait bool) *EthLink {
	var link C.struct_rte_eth_link
	if wait {
		C.rte_eth_link_get(C.uint16_t(re.port_id), &link)
	} else {
		C.rte_eth_link_get_nowait(C.uint16_t(re.port_id), &link)
	}

	return &EthLink{
		Speed:      EthLinkSpeed(link.link_speed),
		DuplexFull: bool(C.eth_link_duplex(&link)),
		StatusUp:   bool(C.eth_link_status(&link)),
	}
}

func (rq *EthRxQueue) Burst(rx_pkts *unsafe.Pointer, nb_pkts uint) uint {
	return uint(C.rte_eth_rx_burst(C.uint16_t(rq.dev.port_id), C.uint16_t(rq.queue_id),
		(**C.struct_rte_mbuf)(unsafe.Pointer(rx_pkts)), C.uint16_t(nb_pkts)))
}

func (rq *EthTxQueue) Burst(tx_pkts *unsafe.Pointer, nb_pkts uint) uint {
	return uint(C.rte_eth_tx_burst(C.uint16_t(rq.dev.port_id), C.uint16_t(rq.queue_id),
		(**C.struct_rte_mbuf)(unsafe.Pointer(tx_pkts)), C.uint16_t(nb_pkts)))
}

func (di *EthDevInfo) DriverName() string {
	return C.GoString(di.driver_name)
}

func (di *EthDevInfo) DefaultRxConf() *EthRxConf {
	rc := di.default_rxconf
	return (*EthRxConf)(&rc)
}

func (di *EthDevInfo) DefaultTxConf() *EthTxConf {
	tc := di.default_txconf
	return (*EthTxConf)(&tc)
}

func (rc *EthRxConf) FreeThresh() uint16 {
	return uint16(rc.rx_free_thresh)
}

func (rc *EthRxConf) SetFreeThresh(t uint16) {
	rc.rx_free_thresh = C.uint16_t(t)
}

func (rc *EthRxConf) Drop() bool {
	return rc.rx_drop_en != 0
}

func (rc *EthRxConf) SetDrop(enable bool) {
	rc.rx_drop_en = bool2Cuint8(enable)
}

func (rc *EthRxConf) DeferredStart() bool {
	return rc.rx_deferred_start != 0
}

func (rc *EthRxConf) SetDeferredStart(enable bool) {
	rc.rx_deferred_start = bool2Cuint8(enable)
}

func bool2Cuint8(b bool) C.uint8_t {
	if b {
		return 1
	}
	return 0
}
