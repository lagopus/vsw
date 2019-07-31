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

package vxlan

// #include "lagopus_apis.h"
// #include "vxlan_includes.h"
// #include "fdb.h"
import "C"

const (
	// ModuleName TUNNEL_MODULE_NAME.
	ModuleName string = C.TUNNEL_MODULE_NAME
	// VXLANModuleName VXLAN_MODULE_NAME.
	VXLANModuleName string = C.VXLAN_MODULE_NAME
)

const (
	// L2tunCmdLearn L2TUN_CMD_FDB_LEARN.
	L2tunCmdLearn L2tunCmd = C.L2TUN_CMD_FDB_LEARN
	// L2tunCmdDel L2TUN_CMD_FDB_DEL.
	L2tunCmdDel L2tunCmd = C.L2TUN_CMD_FDB_DEL
	// L2tunCmdClear L2TUN_CMD_FDB_CLEAR.
	L2tunCmdClear L2tunCmd = C.L2TUN_CMD_FDB_CLEAR
	// L2tunCmdAging L2TUN_CMD_FDB_AGING.
	L2tunCmdAging L2tunCmd = C.L2TUN_CMD_FDB_AGING
)

// ControlParam struct l2tun_control_param.
type ControlParam C.struct_l2tun_control_param

// ControlFunc Control func.
type ControlFunc func(*ControlParam) error

// L2tunCmd l2tun_cmd_t.
type L2tunCmd C.l2tun_cmd_t
