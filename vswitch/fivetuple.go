//
// Copyright 2019 Nippon Telegraph and Telephone Corporation.
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

import "fmt"

// PortRange represents a range of port numbers.
// For *, Start is 0,
// For single port, Start is non-zero number.
// For a range, Start is non-zero, and End is a number larger than Start.
type PortRange struct {
	Start uint16
	End   uint16
}

func (pr *PortRange) String() string {
	if pr.Start == 0 {
		return "*"
	}

	if pr.End == 0 {
		return fmt.Sprintf("%d", pr.Start)
	}

	return fmt.Sprintf("%d-%d", pr.Start, pr.End)
}

func (pr *PortRange) Equal(target *PortRange) bool {
	if target == nil {
		return false
	}
	return pr.Start == target.Start && pr.End == target.End
}

func (pr *PortRange) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%d..%d\"", pr.Start, pr.End)), nil
}

// FiveTuple represetns 5-Tuple
type FiveTuple struct {
	SrcIP   IPAddr    // Source IP address. AnyIPAddr is specified for *.
	DstIP   IPAddr    // Destination IP address. AnyIPAddr is specified for *.
	SrcPort PortRange // Source Port number.
	DstPort PortRange // Destination Port number.
	Proto   IPProto   // IP protoco number.
}

func (ft *FiveTuple) String() string {
	str := fmt.Sprintf("SrcIP: %v, SrcPort: %v, DstIP: %v, DstPort %v, Proto: ",
		ft.SrcIP, &ft.SrcPort, ft.DstIP, &ft.DstPort)

	if ft.Proto == IPP_ANY {
		str += "*"
	} else {
		str += fmt.Sprintf("%v(%d)", ft.Proto, ft.Proto)
	}

	return str
}

// NewFiveTuple creates a new FiveTuple with default value.
// Default is { SrcIP: 0.0.0.0/0,  DstIP: 0.0.0.0/0, SrcPort: *, DsPort: *,  Proto: * }.
func NewFiveTuple() *FiveTuple {
	return &FiveTuple{SrcIP: AnyIPAddr, DstIP: AnyIPAddr, Proto: IPP_ANY}
}
