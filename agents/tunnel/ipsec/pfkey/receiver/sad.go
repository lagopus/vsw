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
// +build !test

package receiver

import (
	"net"

	// XXX
	"github.com/lagopus/vsw/agents/tunnel/ipsec/sad"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
)

var mgrs [2]*sad.Mgr

func init() {
	sad.RegisterSadbExpire(sadbExpire)
	sad.RegisterSadbAcquire(sadbAcquire)
	mgrs[0] = sad.GetMgr(ipsec.DirectionTypeIn)
	mgrs[1] = sad.GetMgr(ipsec.DirectionTypeOut)
}

func reserveSA(selector *sad.SASelector, spi uint32) error {
	err := mgrs[0].ReserveSA(selector)
	if err != nil {
		return err
	}
	err = mgrs[1].ReserveSA(selector)
	if err != nil {
		mgrs[0].DeleteSA(selector)
		return err
	}

	return nil
}

func addSA(selector *sad.SASelector, sa *sad.SAValue) error {
	err := mgrs[0].AddSA(selector, sa)
	if err != nil {
		return err
	}
	err = mgrs[1].AddSA(selector, sa)
	if err != nil {
		mgrs[0].DeleteSA(selector)
		return err
	}

	return nil
}

func findSA(selector *sad.SASelector) (*sad.SAValue, error) {
	// find mgrs[0] only.
	sav, err := mgrs[0].FindSA(selector)
	if err != nil {
		return nil, err
	}
	return sav, nil
}

func cloneSA(selector *sad.SASelector) sad.SAD {
	return mgrs[0].CloneSAD(selector)
}

func enableSA(selector *sad.SASelector, dir ipsec.DirectionType) error {
	// find mgrs[0] only.
	mgr := sad.GetMgr(dir)
	return mgr.EnableSA(selector) // ready to push for C
}

func findSAByIP(selector *sad.SASelector, local net.IP, remote net.IP) (*sad.SAValue, error) {
	// find mgrs[0] only.
	_, sav, err := mgrs[0].FindSAbyIP(selector, local, remote)
	if err != nil {
		return nil, err
	}
	return sav, nil
}

func findSPIbyIP(selector *sad.SASelector, local net.IP, remote net.IP) (uint32, error) {
	// find mgrs[0] only.
	spi, _, err := mgrs[0].FindSAbyIP(selector, local, remote)
	if err != nil {
		// RFC4303 2.1.  Security Parameters Index (SPI)
		// The SPI value of zero (0)
		// is reserved for local, implementation-specific use and MUST NOT be
		// sent on the wire.  (For example, a key management implementation
		// might use the zero SPI value to mean "No Security Association Exists"
		return 0, err
	}
	return uint32(spi), nil
}

func deleteSA(selector *sad.SASelector) {
	mgrs[0].DeleteSA(selector)
	mgrs[1].DeleteSA(selector)
}
