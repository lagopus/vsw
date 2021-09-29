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

package hostif

/*
#define MAX_HOSTIF_MBUFS 1024
*/
import "C"

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"unsafe"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/vswitch"

	pb "github.com/lagopus/vsw/modules/hostif/packets_io"
	vlog "github.com/lagopus/vsw/vswitch/log"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	moduleName        = "hostif"
	defaultPortNumber = 30020
)

var log = vswitch.Logger

// Config
type hostifConfigSection struct {
	Hostif hostifConfig
}

type hostifConfig struct {
	Port int
}

//
type HostifInstance struct {
	base    *vswitch.BaseInstance
	mutex   sync.Mutex
	enabled bool
}

type HostifService struct {
	instances map[string]*HostifInstance
	inputs    []*dpdk.Ring
	mutex     sync.Mutex
	server    *grpc.Server
	done      chan struct{}
	port      int
	serverRc  int
}

func (hs *HostifService) addInstance(hi *HostifInstance) {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	hs.instances[hi.base.Name()] = hi
	hs.inputs = append(hs.inputs, hi.base.Input())
}

func (hs *HostifService) deleteInstance(hi *HostifInstance) {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	delete(hostifService.instances, hi.base.Name())

	target := hi.base.Input()
	for i, v := range hs.inputs {
		if v == target {
			n := len(hs.inputs) - 1
			hs.inputs[i] = hs.inputs[n]
			hs.inputs[n] = nil
			hs.inputs = hs.inputs[:n]
			return
		}
	}
}

func (hs *HostifService) serverStart(sock net.Listener) {
	hs.server.Serve(sock)
	close(hs.done)
}

func (hs *HostifService) startService() error {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	hs.serverRc++

	// If the server is already up and running, do nothing.
	if hs.serverRc > 1 {
		return nil
	}

	// load config, if port is not set yet
	if hs.port < 0 {
		c := hostifConfigSection{hostifConfig{defaultPortNumber}}
		vswitch.GetConfig().Decode(&c)
		hs.port = c.Hostif.Port
	}

	sock, err := net.Listen("tcp", ":"+strconv.Itoa(hs.port))
	if err != nil {
		return err
	}

	hs.server = grpc.NewServer()
	pb.RegisterPacketsIoServer(hs.server, hs)
	go hs.serverStart(sock)
	return nil
}

func (hs *HostifService) stopService() {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	hs.serverRc--

	// If the server is still in use, do nothing.
	if hs.serverRc > 0 {
		return
	}

	hs.server.Stop()
	<-hs.done
}

func (hs *HostifService) SendBulk(ctx context.Context, pkts *pb.BulkPackets) (*pb.Result, error) {
	pool := vswitch.GetDpdkResource().Mempool

	if pkts.N > 0 {
		/* pkts to mbufs */
		for i := int64(0); i < pkts.N; i++ {
			vifname := pkts.Packets[i].GetSubifname()

			if vif := vswitch.GetVIFByName(vifname); vif != nil {
				if mbuf := pool.AllocMbuf(); mbuf != nil {
					mbuf.SetData(pkts.Packets[i].Data)
					md := (*vswitch.Metadata)(mbuf.Metadata())
					md.SetOutVIF(vif.Index())

					if vif.Input().Enqueue(unsafe.Pointer(mbuf)) != 0 {
						mbuf.Free()
					}
				} else {
					log.Printf("%s: AllocMbuf() failed", moduleName)
				}
			} else {
				log.Printf(`%s: rings["%s"] == nil`, moduleName, vifname)
			}
		}
	}
	return new(pb.Result), nil
}

func (hs *HostifService) RecvBulk(ctx context.Context, in *pb.Null) (*pb.BulkPackets, error) {
	mbufs := make([]*dpdk.Mbuf, 1024)
	bps := &pb.BulkPackets{}

	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	for _, iring := range hs.inputs {
		if rxc := iring.DequeueBurstMbufs(&mbufs); rxc > 0 {
			pkts := make([]*pb.Packet, rxc)
			for i := uint(0); i < rxc; i++ {
				m := mbufs[i]
				md := (*vswitch.Metadata)(m.Metadata())
				inVIF := vswitch.GetVIFByIndex(md.InVIF())
				if inVIF == nil {
					m.Free()
					continue
				}
				name := inVIF.Name()

				pkts[i] = &pb.Packet{
					Len:       uint32(m.DataLen()),
					Subifname: name,
					Data:      append([]byte(nil), m.Data()...),
				}

				m.Free()
			}
			bps.N += int64(rxc)
			bps.Packets = append(bps.Packets, pkts...)
		}
	}

	return bps, nil
}

var hostifService *HostifService

//
func newHostifInstance(base *vswitch.BaseInstance, i interface{}) (vswitch.Instance, error) {
	hi := &HostifInstance{base: base}
	hostifService.addInstance(hi)
	return hi, nil
}

func (hi *HostifInstance) Free() {
	hi.mutex.Lock()
	defer hi.mutex.Unlock()

	if hi.enabled {
		hostifService.stopService()
		hi.enabled = false
	}

	hostifService.deleteInstance(hi)
}

func (hi *HostifInstance) Enable() error {
	hi.mutex.Lock()
	defer hi.mutex.Unlock()

	// If the instance is already enabled, do nothing.
	if hi.enabled {
		return nil
	}

	log.Printf("%s: Start()", hi.base.Name())

	if err := hostifService.startService(); err != nil {
		return fmt.Errorf("%s: %v", hi.base.Name(), err)
	}
	hi.enabled = true
	return nil
}

func (hi *HostifInstance) Disable() {
	hi.mutex.Lock()
	defer hi.mutex.Unlock()

	if !hi.enabled {
		return
	}

	log.Printf("%s: Disable()", hi.base.Name())

	hostifService.stopService()
	hi.enabled = false
}

/*
 * Do module registration here.
 */
func init() {
	hostifService = &HostifService{
		instances: make(map[string]*HostifInstance),
		done:      make(chan struct{}),
		port:      -1,
	}

	if l, err := vlog.New(moduleName); err == nil {
		log = l
	} else {
		log.Fatalf("Can't create logger: %s", moduleName)
	}

	rp := &vswitch.RingParam{
		Count:    C.MAX_HOSTIF_MBUFS,
		SocketId: dpdk.SOCKET_ID_ANY,
	}

	if err := vswitch.RegisterModule(moduleName, newHostifInstance, rp, vswitch.TypeOther); err != nil {
		log.Fatalf("Failed to register hostif: %v", err)
	}
}
