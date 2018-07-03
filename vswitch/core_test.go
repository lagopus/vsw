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

package vswitch

import (
	"flag"
	"fmt"
	"os"
	"testing"
)

type opcode int

const (
	OpInvalid opcode = iota
	OpEnable
	OpDisable
	OpFree
	OpNewVIF
	OpMACAddress
	OpSetMACAddress
	OpMTU
	OpSetMTU
	OpInterfaceMode
	OpSetInterfaceMode
	OpAddVID
	OpDeleteVID
	OpAddVIF
	OpDeleteVIF
	OpSetNativeVID
	OpVIFFree
	OpVIFEnable
	OpVIFDisable
	OpVIFSetVRF
)

var opstr = map[opcode]string{
	OpInvalid:          "INVALID OP",
	OpEnable:           "Enable",
	OpDisable:          "Disable",
	OpFree:             "Free",
	OpNewVIF:           "NewVIF",
	OpMACAddress:       "MACAddress",
	OpSetMACAddress:    "SetMACAddress",
	OpMTU:              "MTU",
	OpSetMTU:           "SetMTU",
	OpInterfaceMode:    "InterfaceMode",
	OpSetInterfaceMode: "SetInterfaceMode",
	OpAddVID:           "AddVID",
	OpDeleteVID:        "DeleteVID",
	OpAddVIF:           "AddVIF",
	OpDeleteVIF:        "DeleteVIF",
	OpSetNativeVID:     "SetNativeVID",
	OpVIFFree:          "VIF.Free",
	OpVIFEnable:        "VIF.Enable",
	OpVIFDisable:       "VIF.Disable",
}

func (o opcode) String() string {
	return opstr[o]
}

func (o opcode) Expect(ch chan opcode) error {
	for {
		select {
		case rc := <-ch:
			if rc == o {
				return nil
			}
			return fmt.Errorf("Expected %v. Got %v", o, rc)
		default:
			return fmt.Errorf("Instance not called.")
		}
	}

}

func TestMain(m *testing.M) {
	Init("../vsw.conf")

	flag.Parse()
	os.Exit(m.Run())
}
