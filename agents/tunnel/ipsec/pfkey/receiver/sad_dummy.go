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
// +build test

package receiver

import (
	"net"

	// XXX
	"github.com/lagopus/vsw/agents/tunnel/ipsec/sad"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
)

func reserveSA(selector *sad.SASelector, spi uint32) error {
	return nil
}

func addSA(selector *sad.SASelector, sa *sad.SAValue) error {
	return nil
}

func findSA(selector *sad.SASelector) (*sad.SAValue, error) {
	return &sad.SAValue{}, nil
}

func cloneSA(selector *sad.SASelector) sad.SAD {
	return sad.SAD{}
}

func enableSA(selector *sad.SASelector, dir ipsec.DirectionType) error {
	return nil
}

func findSAByIP(selector *sad.SASelector, local net.IP, remote net.IP) (*sad.SAValue, error) {
	return &sad.SAValue{}, nil
}

func findSPIbyIP(selector *sad.SASelector, local net.IP, remote net.IP) (uint32, error) {
	return 1, nil
}

func deleteSA(selector *sad.SASelector) {
}
