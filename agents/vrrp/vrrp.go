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
	"net"
	"strconv"
	"strings"

	"github.com/lagopus/vsw/agents/vrrp/rpc"
	"github.com/lagopus/vsw/vswitch"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	name = "vrrp"
	port = ":30010"
)

type vrrp struct {
	server     *grpc.Server
	errChannel chan error
}

func findVIF(name string) (*vswitch.VIF, error) {
	if vif := vswitch.GetVIFByName(name); vif != nil {
		return vif, nil
	}
	return nil, fmt.Errorf("VifInfo not found: %s", name)
}

func splitAddrPrefix(str string) (net.IP, net.IPMask, error) {
	if strings.Contains(str, "/") == false {
		return nil, nil, fmt.Errorf("invalid param")
	}

	buf := strings.Split(str, "/")

	var mask int
	var err error
	if mask, err = strconv.Atoi(buf[1]); err == nil {
		return net.ParseIP(buf[0]), net.CIDRMask(mask, 32), nil
	}
	return nil, nil, err
}

func getVIFIPAddr(entry *rpc.VifEntry) (*vswitch.VIF, *vswitch.IPAddr, error) {
	var vif *vswitch.VIF
	var addr vswitch.IPAddr
	var err error
	if vif, err = findVIF(entry.Name); err != nil {
		return vif, &addr, err
	}
	if addr.IP, addr.Mask, err = splitAddrPrefix(entry.Vaddr); err != nil {
		return vif, &addr, err
	}
	return vif, &addr, nil
}

func (v *vrrp) existVIFIPAddr(ip *vswitch.IPAddr, vif *vswitch.VIF) bool {
	ipAddrs := vif.IPAddrs.ListIPAddrs()
	for _, ipAddr := range ipAddrs {
		if ip.Equal(ipAddr) {
			return true
		}
	}
	return false
}

func (v *vrrp) addIPAddr(vifinfo *rpc.VifInfo) error {
	for _, entry := range vifinfo.Entries {
		if entry.Vaddr == entry.Phyaddr {
			continue
		}
		var vif *vswitch.VIF
		var addr *vswitch.IPAddr
		var err error
		if vif, addr, err = getVIFIPAddr(entry); err != nil {
			return err
		}
		if v.existVIFIPAddr(addr, vif) {
			continue
		}
		if err = vif.IPAddrs.AddIPAddr(*addr); err != nil {
			return fmt.Errorf("Vif add ipaddr failed: %v, %s",
				err, addr.String())
		}
	}
	return nil
}

func (v *vrrp) deleteIPAddr(vifinfo *rpc.VifInfo) error {
	for _, entry := range vifinfo.Entries {
		if entry.Vaddr == entry.Phyaddr {
			continue
		}
		var vif *vswitch.VIF
		var addr *vswitch.IPAddr
		var err error
		if vif, addr, err = getVIFIPAddr(entry); err != nil {
			return err
		}
		if !v.existVIFIPAddr(addr, vif) {
			continue
		}
		if err = vif.IPAddrs.DeleteIPAddr(*addr); err != nil {
			return fmt.Errorf("Vif delete ipaddr failed: %v, %s",
				err, addr.String())
		}
	}
	return nil
}

// GetVifInfo Get VifInfo
func (v *vrrp) GetVifInfo(_ context.Context, vifinfo *rpc.VifInfo) (*rpc.VifInfo, error) {
	Logger.Debug(0, "GetVifInfo param: %v", vifinfo)

	if vifinfo == nil {
		Logger.Err("GetVifInfo failed: invalid VifInfo param")
		return nil, fmt.Errorf("invalid VifInfo param")
	}

	for _, entry := range vifinfo.Entries {
		if vif, err := findVIF(entry.Name); err == nil {
			if vif.MACAddress() != nil {
				entry.Vaddr = vif.MACAddress().String()
			} else {
				Logger.Err("GetVifInfo failed: vif mac address is nil")
				return nil, fmt.Errorf("Vif mac address is nil: %v", vif)
			}
		} else {
			Logger.Err("GetVifInfo failed: %v", err)
			return nil, err
		}
	}

	Logger.Debug(0, "GetVifInfo result: %v", vifinfo)

	return vifinfo, nil
}

// ToMaster Configuration to master
func (v *vrrp) ToMaster(_ context.Context, vifinfo *rpc.VifInfo) (*rpc.Reply, error) {
	Logger.Debug(0, "ToMaster param: %v", vifinfo)

	if vifinfo == nil {
		Logger.Err("ToMaster failed: invalid VifInfo param")
		return nil, fmt.Errorf("invalid VifInfo param")
	}

	var err error
	if err = v.addIPAddr(vifinfo); err == nil {
		Logger.Debug(0, "ToMaster success")
		return &rpc.Reply{Code: rpc.ResultCode_SUCCESS}, nil
	}
	Logger.Err("ToMaster failed: %v", err)
	return nil, err
}

// ToBackup Configuration to backup
func (v *vrrp) ToBackup(_ context.Context, vifinfo *rpc.VifInfo) (*rpc.Reply, error) {
	Logger.Debug(0, "ToBackup param: %v", vifinfo)

	if vifinfo == nil {
		Logger.Err("ToBackup failed: invalid VifInfo param")
		return nil, fmt.Errorf("invalid VifInfo param")
	}

	var err error
	if err = v.deleteIPAddr(vifinfo); err == nil {
		Logger.Debug(0, "ToBackup success")
		return &rpc.Reply{Code: rpc.ResultCode_SUCCESS}, nil
	}
	Logger.Err("ToBackup failed: %v", err)
	return nil, err
}

// Enable Enable VRRP DataPlane Agent.
func (v *vrrp) Enable() error {
	Logger.Info("Enable vrrp agent.")

	rpc.RegisterVrrpServer(v.server, v)

	go func() {
		lis, err := net.Listen("tcp", port)
		if err != nil {
			Logger.Fatalf("failed to listen: %v", err)
			v.errChannel <- err
		}

		Logger.Debug(0, "vrrp agent start: localhost:%s", port)

		if err := v.server.Serve(lis); err != nil {
			Logger.Fatalf("failed to serve: %v", err)
			v.errChannel <- err
		}
	}()

	return nil
}

// Disable Disable VRRP DataPlane Agent.
func (v *vrrp) Disable() {
	v.server.Stop()
	Logger.Info("Disable vrrp agent.")
	return
}

func (v *vrrp) String() string {
	return name
}

func init() {
	vrrp := &vrrp{
		server:     grpc.NewServer(),
		errChannel: make(chan error),
	}
	vswitch.RegisterAgent(vrrp)
}
