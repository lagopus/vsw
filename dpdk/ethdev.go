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

package dpdk

/*
#include <stdlib.h>
#include <rte_config.h>
#include <rte_ethdev.h>
*/
import "C"

import (
	"net"
	"syscall"
	"unsafe"
)

type EthConf C.struct_rte_eth_conf
type EthRxConf C.struct_rte_eth_rxconf
type EthTxConf C.struct_rte_eth_txconf
type EthDevInfo C.struct_rte_eth_dev_info

type EthDev struct {
	port_id uint
}

type EthRxQueue struct {
	dev      *EthDev
	queue_id uint
}

type EthTxQueue struct {
	dev      *EthDev
	queue_id uint
}

func EthDevOpen(port_id uint) *EthDev {
	if int(C.rte_eth_dev_is_valid_port(C.uint8_t(port_id))) == 0 {
		return nil
	}
	return &EthDev{port_id}
}

func EthDevCount() uint {
	return uint(C.rte_eth_dev_count())
}

func EthDevGetPortByName(name string) (uint, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var cpid C.uint8_t
	if rc := int(C.rte_eth_dev_get_port_by_name(cname, &cpid)); rc < 0 {
		return 0, syscall.Errno(-rc)
	}
	return uint(cpid), nil
}

func EthDevGetNameByPort(port_id uint) (string, error) {
	var cname [C.RTE_ETH_NAME_MAX_LEN]C.char
	if rc := int(C.rte_eth_dev_get_name_by_port(C.uint8_t(port_id), &cname[0])); rc < 0 {
		return "", syscall.Errno(-rc)
	}
	return C.GoString(&cname[0]), nil
}

func (re *EthDev) Configure(nb_rx_queue, nb_tx_queue uint, eth_conf *EthConf) int {
	return int(C.rte_eth_dev_configure(C.uint8_t(re.port_id),
		C.uint16_t(nb_rx_queue), C.uint16_t(nb_tx_queue),
		(*C.struct_rte_eth_conf)(eth_conf)))
}

func (re *EthDev) RxQueueSetup(rx_queue_id, nb_rx_desc, socket_id uint,
	rx_conf *EthRxConf, mb_pool *MemPool) *EthRxQueue {

	if int(C.rte_eth_rx_queue_setup(C.uint8_t(re.port_id),
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

func (re *EthDev) TxQueueSetup(tx_queue_id, nb_tx_desc, socket_id uint,
	tx_conf *EthTxConf) *EthTxQueue {

	if int(C.rte_eth_tx_queue_setup(C.uint8_t(re.port_id),
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
	var di EthDevInfo
	C.rte_eth_dev_info_get(C.uint8_t(re.port_id), (*C.struct_rte_eth_dev_info)(&di))
	return &di
}

func (re *EthDev) MacAddr() net.HardwareAddr {
	addr := make([]byte, C.ETHER_ADDR_LEN)
	C.rte_eth_macaddr_get(C.uint8_t(re.port_id), (*C.struct_ether_addr)(unsafe.Pointer(&addr[0])))
	return (net.HardwareAddr)(addr)
}

func (re *EthDev) GetMaxQueues() (rxQueueMax, txQueueMax uint) {
	var dev_info C.struct_rte_eth_dev_info

	C.rte_eth_dev_info_get(C.uint8_t(re.port_id), &dev_info)

	rxQueueMax = uint(dev_info.max_rx_queues)
	txQueueMax = uint(dev_info.max_tx_queues)

	return
}

func (re *EthDev) MTU() int {
	var mtu C.uint16_t
	if C.rte_eth_dev_get_mtu(C.uint8_t(re.port_id), &mtu) == 0 {
		return int(mtu)
	}
	return -1
}

func (re *EthDev) SetMTU(mtu uint16) int {
	return int(C.rte_eth_dev_set_mtu(C.uint8_t(re.port_id), C.uint16_t(mtu)))
}

func (re *EthDev) Promiscuous() bool {
	if C.rte_eth_promiscuous_get(C.uint8_t(re.port_id)) == 1 {
		return true
	}
	return false
}

func (re *EthDev) SetPromiscuous(enable bool) {
	if enable {
		C.rte_eth_promiscuous_enable(C.uint8_t(re.port_id))
	} else {
		C.rte_eth_promiscuous_disable(C.uint8_t(re.port_id))
	}
}

func (re *EthDev) AllMulticast() bool {
	if C.rte_eth_allmulticast_get(C.uint8_t(re.port_id)) == 1 {
		return true
	}
	return false
}

func (re *EthDev) SetAllMulticast(enable bool) {
	if enable {
		C.rte_eth_allmulticast_enable(C.uint8_t(re.port_id))
	} else {
		C.rte_eth_allmulticast_disable(C.uint8_t(re.port_id))
	}
}

func (re *EthDev) Start() int {
	return int(C.rte_eth_dev_start(C.uint8_t(re.port_id)))
}

func (re *EthDev) Stop() {
	C.rte_eth_dev_stop(C.uint8_t(re.port_id))
}

func (re *EthDev) SetLinkUp() int {
	return int(C.rte_eth_dev_set_link_up(C.uint8_t(re.port_id)))
}

func (re *EthDev) SetLinkDown() int {
	return int(C.rte_eth_dev_set_link_down(C.uint8_t(re.port_id)))
}

func (rq *EthRxQueue) Burst(rx_pkts *unsafe.Pointer, nb_pkts uint) uint {
	return uint(C.rte_eth_rx_burst(C.uint8_t(rq.dev.port_id), C.uint16_t(rq.queue_id),
		(**C.struct_rte_mbuf)(unsafe.Pointer(rx_pkts)), C.uint16_t(nb_pkts)))
}

func (rq *EthTxQueue) Burst(tx_pkts *unsafe.Pointer, nb_pkts uint) uint {
	return uint(C.rte_eth_tx_burst(C.uint8_t(rq.dev.port_id), C.uint16_t(rq.queue_id),
		(**C.struct_rte_mbuf)(unsafe.Pointer(tx_pkts)), C.uint16_t(nb_pkts)))
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
