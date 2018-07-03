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
	"fmt"
	"net"
	"unsafe"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/vswitch"

	pb "github.com/lagopus/vsw/modules/hostif/packets_io"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var log = vswitch.Logger

type HostifModule struct {
	base    *vswitch.BaseInstance
	running bool
	done    chan int
	server  *grpc.Server
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
func newHostifInstance(base *vswitch.BaseInstance, i interface{}) (vswitch.Instance, error) {
	return &HostifModule{
		base:    base,
		running: true,
		done:    make(chan int),
	}, nil
}

func (him *HostifModule) Free() {
}

func (him *HostifModule) ServerStart(sock net.Listener) {
	him.server.Serve(sock)
	close(him.done)
}

func (him *HostifModule) Enable() error {
	log.Printf("%s: Start()", him.base.Name())

	if !him.running {
		return fmt.Errorf("%s: Terminated before start", him.base.Name())
	}
	sock, err := net.Listen("tcp", ":30020")
	if err != nil {
		return fmt.Errorf("%s: %v", him.base.Name(), err)
	}
	him.server = grpc.NewServer()
	pb.RegisterPacketsIoServer(him.server, him)
	go him.ServerStart(sock)
	return nil
}

func (him *HostifModule) SendBulk(ctx context.Context, pkts *pb.BulkPackets) (*pb.Result, error) {
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
					log.Printf("%s: AllocMbuf() failed", him.base.Name())
				}
			} else {
				log.Printf(`%s: rings["%s"] == nil`, him.base.Name(), vifname)
			}
		}
	}
	return new(pb.Result), nil
}

func (him *HostifModule) RecvBulk(ctx context.Context, in *pb.Null) (*pb.BulkPackets, error) {
	mbufs := make([]*dpdk.Mbuf, 1024)

	iring := him.base.Input()

	rxc := iring.DequeueBurstMbufs(&mbufs)
	if rxc > 0 {
		pkts := make([]*pb.Packet, rxc)
		for i := uint(0); i < rxc; i++ {
			m := mbufs[i]
			md := (*vswitch.Metadata)(m.Metadata())
			name := vswitch.GetVIFByIndex(md.InVIF()).Name()

			pkts[i] = &pb.Packet{
				Len:       uint32(m.DataLen()),
				Subifname: name,
				Data:      append([]byte(nil), m.Data()...),
			}

			m.Free()
		}
		bps := &pb.BulkPackets{
			N:       int64(rxc),
			Packets: pkts,
		}
		return bps, nil
	}

	bps := &pb.BulkPackets{}
	return bps, nil
}

func (him *HostifModule) Disable() {
	log.Printf("%s: Disable()", him.base.Name())
	him.running = false
	him.server.Stop()
	<-him.done
}

/*
 * Do module registration here.
 */
func init() {
	rp := &vswitch.RingParam{
		Count:    C.MAX_HOSTIF_MBUFS,
		SocketId: dpdk.SOCKET_ID_ANY,
	}

	if err := vswitch.RegisterModule("hostif", newHostifInstance, rp, vswitch.TypeOther); err != nil {
		log.Fatalf("Failed to register hostif: %v", err)
	}
}
