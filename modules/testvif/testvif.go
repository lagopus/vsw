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

package testvif

import (
	"bytes"
	"errors"
	"net"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/vswitch"
)

var log = vswitch.Logger

// Statistics
type TestIFStats struct {
	RxCount    int // Packets Received
	RxDropped  int // Packets Couldn't Recv'd
	TxCount    int // Packets Sent (Outbound)
	TxDropped  int // Packets Couldn't Sent
	AuxCount   int // Packets Sent (Inbound)
	AuxDropped int // Packets Couldn't Sent
}

type TestIF struct {
	base     *vswitch.BaseInstance
	rx_chan  chan *dpdk.Mbuf // VIF.Output()  : chan -> testvif -> other module
	tx_chan  chan *dpdk.Mbuf // VIF.Outbound(): other module -> testvif -> chan
	aux_chan chan *dpdk.Mbuf // VIF.Inbound() : other module -> testvif -> chan
	stats    TestIFStats
	mtu      vswitch.MTU
	done     chan int
}

type TestVIF struct {
	testif  *TestIF
	vif     *vswitch.VIF
	running bool
}

/*
 * If you want to expose arbitrary struct to be used with Control(), define.
 */
type TestVifConfig struct {
}

const QueueLength = 32

func newTestIF(base *vswitch.BaseInstance) *TestIF {
	return &TestIF{
		base:    base,
		rx_chan: make(chan *dpdk.Mbuf),
		tx_chan: make(chan *dpdk.Mbuf, QueueLength),
		done:    make(chan int),
		mtu:     vswitch.DefaultMTU,
	}
}

// Test VIF factory
func newTestVIF(base *vswitch.BaseInstance, priv interface{}) (vswitch.Instance, error) {
	return newTestIF(base), nil
}

func newTestVIF2(base *vswitch.BaseInstance, priv interface{}) (vswitch.Instance, error) {
	ti := newTestIF(base)
	ti.aux_chan = make(chan *dpdk.Mbuf, QueueLength)
	return ti, nil
}

func (ti *TestIF) Free() {
}

func (ti *TestIF) Enable() error {
	return nil
}

func (ti *TestIF) Disable() {
}

func (ti *TestIF) SetMACAddress(mac net.HardwareAddr) error {
	return nil
}

func (ti *TestIF) MACAddress() net.HardwareAddr {
	return nil
}

func (ti *TestIF) MTU() vswitch.MTU {
	return ti.mtu
}

func (ti *TestIF) SetMTU(mtu vswitch.MTU) error {
	ti.mtu = mtu
	return nil
}

func (ti *TestIF) InterfaceMode() vswitch.VLANMode {
	return vswitch.AccessMode
}

func (ti *TestIF) SetInterfaceMode(mode vswitch.VLANMode) error {
	if mode != vswitch.AccessMode {
		return errors.New("Supports ACCESS mode only")
	}
	return nil
}

func (ti *TestIF) AddVID(vid vswitch.VID) error {
	return nil
}

func (ti *TestIF) DeleteVID(vid vswitch.VID) error {
	return nil
}

func (ti *TestIF) SetNativeVID(vid vswitch.VID) error {
	return nil
}

func (ti *TestIF) NewVIF(vif *vswitch.VIF) (vswitch.VIFInstance, error) {
	return &TestVIF{ti, vif, false}, nil
}

func (ti *TestIF) TxChan() chan *dpdk.Mbuf {
	return ti.tx_chan
}

func (ti *TestIF) RxChan() chan *dpdk.Mbuf {
	return ti.rx_chan
}

func (ti *TestIF) ResetStats() {
	ti.stats = TestIFStats{}
}

func (ti *TestIF) Stats() TestIFStats {
	return ti.stats
}

func (tv *TestVIF) Free() {
}

func (tv *TestVIF) SetVRF(vrf *vswitch.VRF) {
}

func (tv *TestVIF) dequeueMbufs(r *dpdk.Ring, ch chan *dpdk.Mbuf) int {
	mbufs := make([]*dpdk.Mbuf, QueueLength)
	vid := uint16(tv.vif.VID())

	txc := int(r.DequeueBurstMbufs(&mbufs))
	for i := 0; i < txc; i++ {
		if v := mbufs[i].VlanTCI(); v != vid {
			log.Printf("%s: Incorrect VID %d found. (Must be %d)", tv.vif.Name(), v, vid)
		}
		ch <- mbufs[i]
	}
	return txc
}

func (tv *TestVIF) Enable() error {
	log.Printf("%s: Enable()", tv.vif.Name())

	if tv.running {
		log.Printf("%s: already runnnig", tv.vif.Name())
		return nil
	}
	tv.running = true

	go func() {
		oring := tv.vif.Output()
		if oring == nil {
			log.Printf("%s: Output ring is not specified.", tv.vif.Name())
			return
		}

		index := tv.vif.Index()
		mac := tv.vif.MACAddress()
		vid := uint16(tv.vif.VID())

		for tv.running {
			select {
			case mbuf := <-tv.testif.rx_chan:
				mbuf.SetVlanTCI(vid)
				md := (*vswitch.Metadata)(mbuf.Metadata())
				md.SetInVIF(index)
				md.SetOutVIF(0)

				if bytes.Compare(mac, mbuf.EtherHdr().DstAddr()) == 0 {
					md.SetSelf(true)
				}

				if oring.EnqueueMbuf(mbuf) == 0 {
					tv.testif.stats.RxCount++
					log.Printf("%s: rx=1\n", tv.vif.Name())
				} else {
					log.Printf("%s: enquee failed.\n", tv.vif.Name())
					tv.testif.stats.RxDropped++
					mbuf.Free()
				}

			default:
				if tv.testif.aux_chan != nil {
					if cnt := tv.dequeueMbufs(tv.vif.Inbound(), tv.testif.tx_chan); cnt > 0 {
						log.Printf("%s: Inbound(): %d packet(s)", tv.vif.Name(), cnt)
						tv.testif.stats.AuxCount += cnt
					}
				}
				if cnt := tv.dequeueMbufs(tv.vif.Outbound(), tv.testif.tx_chan); cnt > 0 {
					log.Printf("%s: Outbound(): %d packet(s)", tv.vif.Name(), cnt)
					tv.testif.stats.TxCount += cnt
				}
			}
		}
		tv.testif.done <- 0
	}()

	return nil
}

func (tv *TestVIF) Disable() {
	log.Printf("%s: Disable()", tv.vif.Name())
	tv.running = false
	<-tv.testif.done
}

/*
 * Do module registration here.
 */
func init() {
	rp := &vswitch.RingParam{
		Count:          QueueLength,
		SocketId:       dpdk.SOCKET_ID_ANY,
		SecondaryInput: false,
	}

	if err := vswitch.RegisterModule("testvif", newTestVIF, rp, vswitch.TypeInterface); err != nil {
		log.Fatalf("Failed to register Test VIF class: %v", err)
	}

	rp.SecondaryInput = true
	if err := vswitch.RegisterModule("testvif2", newTestVIF2, rp, vswitch.TypeInterface); err != nil {
		log.Fatalf("Failed to register Test VIF 2 class: %v", err)
	}
}
