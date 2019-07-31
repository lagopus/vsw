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

package tunnel

/*
#include "l2tun.h"
#include "l3tun.h"
*/
import "C"

import (
	"net"

	"github.com/lagopus/vsw/vswitch"
)

//
// L3
//

func createL3SetAddressTypeCmdParam(addressType vswitch.AddressFamily) *C.struct_l3tun_control_param {
	return &C.struct_l3tun_control_param{
		cmd:          C.l3tun_cmd_t(C.L3TUN_CMD_SET_ADDRESS_TYPE),
		address_type: C.uint16_t(uint16(addressType)),
	}
}

func createL3SetLocalAddressCmdParam(localAddr net.IP) *C.struct_l3tun_control_param {
	return &C.struct_l3tun_control_param{
		cmd:        C.l3tun_cmd_t(C.L3TUN_CMD_SET_LOCAL_ADDR),
		local_addr: ip2ipAddr(localAddr),
	}
}

func createL3SetRemoteAddressCmdParam(remoteAddr net.IP) *C.struct_l3tun_control_param {
	return &C.struct_l3tun_control_param{
		cmd:         C.l3tun_cmd_t(C.L3TUN_CMD_SET_REMOTE_ADDR),
		remote_addr: ip2ipAddr(remoteAddr),
	}
}

func createL3SetHopLimitCmdParam(hopLimit uint8) *C.struct_l3tun_control_param {
	return &C.struct_l3tun_control_param{
		cmd:       C.l3tun_cmd_t(C.L3TUN_CMD_SET_HOP_LIMIT),
		hop_limit: C.uint8_t(hopLimit),
	}
}

func createL3SetTOSCmdParam(tos int8) *C.struct_l3tun_control_param {
	return &C.struct_l3tun_control_param{
		cmd: C.l3tun_cmd_t(C.L3TUN_CMD_SET_TOS),
		tos: C.int8_t(tos),
	}
}

func createL3SetEnableCmdParam(addressType vswitch.AddressFamily,
	localAddr net.IP, remoteAddr net.IP, hopLimit uint8, tos int8,
	inboudOutput *C.struct_rte_ring, outboudOutput *C.struct_rte_ring) *C.struct_l3tun_control_param {
	return &C.struct_l3tun_control_param{
		cmd:             C.l3tun_cmd_t(C.L3TUN_CMD_SET_ENABLE),
		address_type:    C.uint16_t(uint16(addressType)),
		local_addr:      ip2ipAddr(localAddr),
		remote_addr:     ip2ipAddr(remoteAddr),
		hop_limit:       C.uint8_t(hopLimit),
		tos:             C.int8_t(tos),
		inbound_output:  inboudOutput,
		outbound_output: outboudOutput,
	}
}

func createL3SetDisableCmdParam() *C.struct_l3tun_control_param {
	return &C.struct_l3tun_control_param{
		cmd: C.l3tun_cmd_t(C.L3TUN_CMD_SET_DISABLE),
	}
}

//
// L2
//

func createL2SetAddressTypeCmdParam(addressType vswitch.AddressFamily) *C.struct_l2tun_control_param {
	return &C.struct_l2tun_control_param{
		cmd:          C.l2tun_cmd_t(C.L2TUN_CMD_SET_ADDRESS_TYPE),
		address_type: C.uint16_t(uint16(addressType)),
	}
}

func createL2SetLocalAddressCmdParam(localAddr net.IP) *C.struct_l2tun_control_param {
	return &C.struct_l2tun_control_param{
		cmd:        C.l2tun_cmd_t(C.L2TUN_CMD_SET_LOCAL_ADDR),
		local_addr: ip2ipAddr(localAddr),
	}
}

func createL2SetRemoteAddressesCmdParam(remoteAddrs []net.IP) *C.struct_l2tun_control_param {
	ipAddrs := C.struct_ip_addrs{}
	for i, remoteAddr := range remoteAddrs {
		ipAddrs.addrs[i] = ip2ipAddr(remoteAddr)
		ipAddrs.size = C.uint16_t(i + 1)
	}

	return &C.struct_l2tun_control_param{
		cmd:          C.l2tun_cmd_t(C.L2TUN_CMD_SET_REMOTE_ADDRS),
		remote_addrs: ipAddrs,
	}
}

func createL2SetHopLimitCmdParam(hopLimit uint8) *C.struct_l2tun_control_param {
	return &C.struct_l2tun_control_param{
		cmd:       C.l2tun_cmd_t(C.L2TUN_CMD_SET_HOP_LIMIT),
		hop_limit: C.uint8_t(hopLimit),
	}
}

func createL2SetTOSCmdParam(tos uint8) *C.struct_l2tun_control_param {
	return &C.struct_l2tun_control_param{
		cmd: C.l2tun_cmd_t(C.L2TUN_CMD_SET_TOS),
		tos: C.uint8_t(tos),
	}
}

func createL2SetVLANModeCmdParam(mode vswitch.VLANMode) *C.struct_l2tun_control_param {
	trunk := false
	if mode == vswitch.TrunkMode {
		trunk = true
	}

	return &C.struct_l2tun_control_param{
		cmd:   C.l2tun_cmd_t(C.L2TUN_CMD_SET_TRUNK_MODE),
		trunk: C.bool(trunk),
	}
}

func createL2SetVNICmdParam(vni uint32) *C.struct_l2tun_control_param {
	return &C.struct_l2tun_control_param{
		cmd: C.l2tun_cmd_t(C.L2TUN_CMD_SET_VNI),
		vni: C.uint32_t(vni),
	}
}

func createL2SetEnableCmdParam(index vswitch.VIFIndex, addressType vswitch.AddressFamily,
	localAddr net.IP, remoteAddrs []net.IP, hopLimit uint8, tos uint8,
	inboundOutput *C.struct_rte_ring, outboundOutput *C.struct_rte_ring,
	vid vswitch.VID, mode vswitch.VLANMode, vni uint32,
	inboundStats *C.struct_tunnel_stats,
	outboundStats *C.struct_tunnel_stats) *C.struct_l2tun_control_param {
	trunk := false
	if mode == vswitch.TrunkMode {
		trunk = true
	}

	ipAddrs := C.struct_ip_addrs{}
	for i, remoteAddr := range remoteAddrs {
		ipAddrs.addrs[i] = ip2ipAddr(remoteAddr)
		ipAddrs.size = C.uint16_t(i + 1)
	}

	return &C.struct_l2tun_control_param{
		cmd:             C.l2tun_cmd_t(C.L2TUN_CMD_SET_ENABLE),
		index:           C.vifindex_t(index),
		address_type:    C.uint16_t(uint16(addressType)),
		local_addr:      ip2ipAddr(localAddr),
		remote_addrs:    ipAddrs,
		hop_limit:       C.uint8_t(hopLimit),
		tos:             C.uint8_t(tos),
		vid:             C.uint16_t(uint16(vid)),
		inbound_output:  inboundOutput,
		outbound_output: outboundOutput,
		trunk:           C.bool(trunk),
		vni:             C.uint32_t(vni),
		inbound_stats:   inboundStats,
		outbound_stats:  outboundStats,
	}
}

func createL2SetDisableCmdParam(index vswitch.VIFIndex,
	vid vswitch.VID) *C.struct_l2tun_control_param {
	return &C.struct_l2tun_control_param{
		cmd:   C.l2tun_cmd_t(C.L2TUN_CMD_SET_DISABLE),
		index: C.vifindex_t(index),
		vid:   C.uint16_t(uint16(vid)),
	}
}
