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

package vrrp

import (
	"fmt"
	"github.com/lagopus/vsw/agents/vrrp/rpc"
	"github.com/lagopus/vsw/vswitch"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"net"
	"strings"
	"strconv"
)

const (
	name = "vrrp"
	port = ":30010"
)

var log = vswitch.Logger

type vrrp struct {
	server *grpc.Server
	errChannel chan error
}

func findVifInfo(name string) (*vswitch.VifInfo, error) {
	if idx := vswitch.GetVifIndex(name); idx > 0 {
		info := vswitch.GetVifInfo(idx)
		if info == nil {
			return nil, fmt.Errorf("VifInfo not found: %s(%d)", name, idx)
		}

		return info, nil
	} else {
		return nil, fmt.Errorf("VifInfo not found: %s", name)
	}
}

func splitAddrPrefix(str string) (net.IP, net.IPMask, error) {
	if strings.Contains(str, "/") == false {
		return nil, nil, fmt.Errorf("invalid param")
	}

	buf := strings.Split(str, "/")

	if mask, err := strconv.Atoi(buf[1]); err == nil {
		return net.ParseIP(buf[0]), net.CIDRMask(mask, 32), nil
	} else {
		return nil, nil, err
	}

}

func (v *vrrp) addIPAddr(vifinfo *rpc.VifInfo) error {
	for _, entry := range vifinfo.Entries {
		if info, err := findVifInfo(entry.Name); err == nil {
			if ip, mask, err := splitAddrPrefix(entry.Addr); err == nil  {
				addr := vswitch.IPAddr{ip, mask}
				if info.IPAddrs.AddIPAddr(addr) == false {
					return fmt.Errorf("Vif add ipaddr failed: %s", addr.String())
				}
			} else {
				return err
			}


		} else {
			return err
		}
	}

	return nil
}

func (v *vrrp) deleteIPAddr(vifinfo *rpc.VifInfo) error {
	for _, entry := range vifinfo.Entries {
		if info, err := findVifInfo(entry.Name); err == nil {
			if ip, mask, err := splitAddrPrefix(entry.Addr); err == nil  {
				addr := vswitch.IPAddr{ip, mask}
				if info.IPAddrs.DeleteIPAddr(addr) == false {
					return fmt.Errorf("Vif add ipaddr failed: %s", addr.String())
				}
			} else {
				return err
			}
		} else {
			return err
		}
	}

	return nil
}

// GetVifInfo Get VifInfo
func (v *vrrp) GetVifInfo(_ context.Context, vifinfo *rpc.VifInfo) (*rpc.VifInfo, error) {
	log.Printf("GetVifInfo param: %v", vifinfo)

	if vifinfo == nil {
		log.Print("GetVifInfo failed: invalid VifInfo param")
		return nil, fmt.Errorf("invalid VifInfo param")
	}

	for _, entry := range vifinfo.Entries {
		if info, err := findVifInfo(entry.Name); err == nil {
			if info.MacAddress() != nil {
				entry.Addr = info.MacAddress().String()
			} else {
				log.Print("GetVifInfo failed: vif mac address is nil")
				return nil, fmt.Errorf("Vif mac address is nil: %s", info.String())
			}
		} else {
			log.Printf("GetVifInfo failed: %v", err)
			return nil, err
		}
	}

	log.Printf("GetVifInfo result: %v", vifinfo)

	return vifinfo, nil
}

// ToMaster Configuration to master
func (v *vrrp) ToMaster(_ context.Context, vifinfo *rpc.VifInfo) (*rpc.Reply, error) {
	log.Printf("ToMaster param: %v", vifinfo)

	if vifinfo == nil {
		log.Print("ToMaster failed: invalid VifInfo param")
		return nil, fmt.Errorf("invalid VifInfo param")
	}

	if err := v.addIPAddr(vifinfo); err == nil {
		log.Print("ToMaster success")
		return &rpc.Reply{Code: rpc.ResultCode_SUCCESS}, nil
	} else {
		log.Printf("ToMaster failed: %v", err)
		return nil, err
	}
}

// ToBackup Configuration to backup
func (v *vrrp) ToBackup(_ context.Context, vifinfo *rpc.VifInfo) (*rpc.Reply, error) {
	log.Printf("ToBackup param: %v", vifinfo)

	if vifinfo == nil {
		log.Print("ToBackup failed: invalid VifInfo param")
		return nil, fmt.Errorf("invalid VifInfo param")
	}

	if err := v.deleteIPAddr(vifinfo); err == nil {
		log.Print("ToBackup success")
		return &rpc.Reply{Code: rpc.ResultCode_SUCCESS}, nil
	} else {
		log.Printf("ToBackup failed: %v", err)
		return nil, err
	}
}

// Start Start VRRP DataPlane Agent.
func (v *vrrp) Start() bool {
	log.Printf("Start vrrp agent.")

	rpc.RegisterVrrpServer(v.server, v)

	go func() {
		lis, err := net.Listen("tcp", port)
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
			v.errChannel <- err
		}

		log.Printf("vrrp agent start: localhost:%s", port)

		if err := v.server.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
			v.errChannel <- err
		}
	}()

	return true
}

// Stop Stop VRRP DataPlane Agent.
func (v *vrrp) Stop() {
	v.server.Stop()
	log.Printf("Stops vrrp agent.")
	return
}

func (v *vrrp) String() string {
	return name
}

func init() {
	vrrp := &vrrp{
		server: grpc.NewServer(),
		errChannel: make(chan error),
	}
	vswitch.RegisterAgent(vrrp)
}
