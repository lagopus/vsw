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
	"fmt"
	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/vswitch"
	"net"
)

const ouiPrefix = uint32(0x12345678)

var log = vswitch.Logger
var serial = 1

// Statistics
type TestVifStats struct {
	Tx_count   int // Packets Sent
	Rx_count   int // Packets Received
	Tx_dropped int // Packets Couldn't Sent
	Rx_dropped int // Packets Couldn't Recv'd
}

type TestVifModule struct {
	vswitch.ModuleService
	running bool
	tx_chan chan *dpdk.Mbuf
	rx_chan chan *dpdk.Mbuf
	stats   TestVifStats
	mac     net.HardwareAddr
	done    chan int
}

/*
 * If you want to expose arbitrary struct to be used with Control(), define.
 */
type TestVifConfig struct {
}

const QueueLength = 32

// Test VIF factory
func createTestVif(p *vswitch.ModuleParam) (vswitch.Module, error) {
	hastr := fmt.Sprintf("%04x.%04x.%04x",
		(ouiPrefix>>16)&0xffff, (ouiPrefix & 0xffff),
		serial)
	ha, err := net.ParseMAC(hastr)
	if err != nil {
		log.Printf("TestVif: Couldn' parse: '%s'\n", hastr)
		return nil, errors.New("Can't create module - bad MAC address.")
	}
	serial++
	module := &TestVifModule{
		ModuleService: vswitch.NewModuleService(p),
		running:       true,
		tx_chan:       make(chan *dpdk.Mbuf),
		rx_chan:       make(chan *dpdk.Mbuf, QueueLength),
		done:          make(chan int),
		mac:           ha,
	}
	return module, nil
}

func (tm *TestVifModule) Link() vswitch.LinkStatus {
	return vswitch.LinkUp
}

func (tm *TestVifModule) SetLink(ls vswitch.LinkStatus) bool {
	return vswitch.LinkUp == ls
}

func (tm *TestVifModule) Control(cmd string, v interface{}) interface{} {
	log.Printf("%s requestd", cmd)
	switch cmd {
	case "GET_TX_CHAN": // Mbufs to Test VIF output ring
		return tm.tx_chan

	case "GET_RX_CHAN": // Mbufs from Test VIF input ring
		return tm.rx_chan

	case "RESET_COUNTER":
		tm.stats = TestVifStats{}
		return true

	case "GET_STATS":
		return tm.stats

	case "SET_MAC_ADDRESS":
		ha, ok := v.(net.HardwareAddr)
		if !ok {
			log.Printf("%s: Invalid argument: %v (expected net.HardwareAddr)\n", tm.Name(), v)
			return false
		}
		tm.mac = ha

	case "GET_MAC_ADDRESS":
		return tm.mac

	default:
		log.Printf("unknown control: %s\n", cmd)
	}

	return false
}

func (tm *TestVifModule) Start() bool {
	log.Printf("%s: Start()", tm.Name())

	if !tm.running {
		log.Printf("%s: Terminated before start", tm.Name())
		close(tm.done)
		return false
	}

	log.Printf("%s: Registering Mac Address: %s", tm.Name(), tm.mac)
	tm.Vif().SetMacAddress(tm.mac)

	vifidx := tm.Vif().VifIndex()

	oring := tm.Rules().Output(vswitch.MATCH_ANY)
	if oring == nil {
		log.Printf("%s: Output ring is not specified.", tm.Name())
		close(tm.done)
		return false
	}

	iring := tm.Input()
	mbufs := make([]*dpdk.Mbuf, QueueLength)

	go func() {
		for tm.running {
			select {
			case mbuf := <-tm.tx_chan:
				md := (*vswitch.Metadata)(mbuf.Metadata())
				md.SetInVIF(vifidx)
				md.SetOutVIF(0)

				if bytes.Compare(tm.mac, mbuf.EtherHdr().DstAddr()) == 0 {
					md.SetSelf(true)
				}

				if oring.EnqueueMbuf(mbuf) == 0 {
					tm.stats.Tx_count++
					log.Printf("%s: tx=1\n", tm.Name())
				} else {
					log.Printf("%s: enquee failed.\n", tm.Name())
					tm.stats.Tx_dropped++
				}

			default:
				rxc := int(iring.DequeueBurstMbufs(&mbufs))
				for i := 0; i < rxc; i++ {
					tm.rx_chan <- mbufs[i]
				}
				if rxc > 0 {
					tm.stats.Rx_count += rxc
					log.Printf("%s: rx=%d\n", tm.Name(), rxc)
				}
			}
		}
		close(tm.done)
		close(tm.tx_chan)
		close(tm.rx_chan)
	}()

	return true
}

func (tm *TestVifModule) Stop() {
	log.Printf("%s: Stop()", tm.Name())
	tm.running = false
}

func (tm *TestVifModule) Wait() {
	log.Printf("%s: Wait()", tm.Name())
	<-tm.done
}

/*
 * Do module registration here.
 */
func init() {
	rp := &vswitch.RingParam{
		Count:    QueueLength,
		SocketId: dpdk.SOCKET_ID_ANY,
		Flags:    0,
	}

	if !vswitch.RegisterModule("testvif", createTestVif, rp, vswitch.TypeVif) {
		log.Fatalf("Failed to register Test VIF class.")
	}
}
