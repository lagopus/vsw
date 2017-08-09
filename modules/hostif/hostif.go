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

package hostif

/*
#define MAX_HOSTIF_MBUFS 1024
*/
import "C"

import (
	"net"
	"unsafe"

	"github.com/lagopus/vsw/vswitch"
	"github.com/lagopus/vsw/dpdk"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	pb "github.com/lagopus/vsw/modules/hostif/packets_io"
)

var log = vswitch.Logger

type HostifModule struct {
	vswitch.ModuleService
	running bool
	done    chan int
	server *grpc.Server
}

/*
 * If you want to expose arbitrary struct to be used with Control(), define.
 */
type HostifConfig struct {
	Number int
	String string
	Array  []string
}

//
func createHostifModule(p *vswitch.ModuleParam) (vswitch.Module, error) {
	return &HostifModule{
		ModuleService: vswitch.NewModuleService(p),
		running:       true,
		done:          make(chan int),
	}, nil
}

func (him *HostifModule) Control(c string, v interface{}) interface{} {
	log.Printf("%s: Control(%v): Value=%v\n", him.Name(), c, v)
	return true
}

func (him *HostifModule) ServerStart(sock net.Listener) {
	him.server.Serve(sock)
	close(him.done)
}

func (him *HostifModule) Start() bool {
	log.Printf("%s: Start()", him.Name())

	if !him.running {
		log.Printf("%s: Terminated before start", him.Name())
		return false
	}
	sock, err := net.Listen("tcp", ":30020")
	if err != nil {
		log.Fatal(err)
	}
	him.server = grpc.NewServer()
	pb.RegisterPacketsIoServer(him.server, him)
	go him.ServerStart(sock)
	return true
}

func (him *HostifModule) SendBulk(ctx context.Context, pkts *pb.BulkPackets) (*pb.Result, error) {
	rings := make(map[string]*dpdk.Ring)
	vifids := make(map[string]vswitch.VifIndex)
	for _, rule := range him.Rules().SubRules(vswitch.MATCH_OUT_VIF) {
		vifid := (vswitch.VifIndex)(rule.Param[0])
		if vswitch.GetVifInfo(vifid) != nil {
			rings[vswitch.GetVifInfo(vifid).String()] = rule.Ring
			vifids[vswitch.GetVifInfo(vifid).String()] = vifid
		}
	}
	if pkts.N > 0 {
		dpdk := vswitch.GetDpdkResource()
		mbufs := dpdk.Mempool.AllocBulkMbufs(uint(pkts.N));
		/* pkts to mbufs */
		for i := int64(0); i < pkts.N; i++ {
			mbufs[i].SetData(pkts.Packets[i].Data)
			md := (*vswitch.Metadata)(mbufs[i].Metadata())
			vifname := pkts.Packets[i].GetSubifname()
			if rings[vifname] != nil {
				md.SetOutVIF(vifids[vifname])
				if rings[vifname].Enqueue(unsafe.Pointer(mbufs[i])) != 0 {
					mbufs[i].Free()
				}
			} else {
				log.Printf("rings[\"%s\"] == nil", vifname)
				mbufs[i].Free()
			}
		}
	}
	return new(pb.Result), nil
}

func (him *HostifModule) RecvBulk(ctx context.Context, in *pb.Null) (*pb.BulkPackets, error) {
	mbufs := make([]*dpdk.Mbuf, 1024)

	for _, iring := range [...]*dpdk.Ring{him.Input(), him.VifInput()} {
		if iring != nil {
			rxc := iring.DequeueBurstMbufs(&mbufs)
			if rxc > 0 {
				pkts := make([]*pb.Packet, rxc)
				for i := uint(0); i < rxc; i++ {
					m := mbufs[i]
					mlen := uint32(m.DataLen())
					pkts[i] = new(pb.Packet)
					pkts[i].Len = mlen
					md := (*vswitch.Metadata)(m.Metadata())
					pkts[i].Subifname = vswitch.GetVifInfo(md.InVIF()).String()
					for _,b := range m.Data() {
						pkts[i].Data = append(pkts[i].Data, b)
					}
				}
				bps := &pb.BulkPackets{
					N:       int64(rxc),
					Packets: pkts,
				}
				return bps, nil
			}
		}
	}
	bps := &pb.BulkPackets{}
	return bps, nil
}

func (him *HostifModule) Stop() {
	log.Printf("%s: Stop()", him.Name())
	him.running = false
	him.server.Stop()
}

func (him *HostifModule) Wait() {
	log.Printf("%s: Wait()", him.Name())
	<-him.done
}

/*
 * Do module registration here.
 */
func init() {
	rp := &vswitch.RingParam{
		Count:    C.MAX_HOSTIF_MBUFS,
		SocketId: dpdk.SOCKET_ID_ANY,
		Flags:    0,
	}

	if !vswitch.RegisterModule("hostif", createHostifModule, rp, vswitch.TypeOther) {
		log.Fatalf("Failed to register the class.")
	}
}
