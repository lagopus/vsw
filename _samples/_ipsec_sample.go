//
// Copyright 2018 Nippon Telegraph and Telephone Corporation.
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

package main

import (
	_ "github.com/lagopus/vsw/agents/tunnel/ipsec"
	_ "github.com/lagopus/vsw/modules/tunnel"
	"github.com/lagopus/vsw/vswitch"
)

func ipsec_sample() error {
	var if0, if1, ifTunnel0 *vswitch.Interface
	var if0_0, if1_0, ifTunnel0_0 *vswitch.VIF
	var err error

	// if0/if0-0.
	if if0, err = vswitch.NewInterface("dpdk", "if0", dev["if0"]); err != nil {
		return err
	}
	if err = if0.SetMTU(1518); err != nil {
		return err
	}
	if err = if0.Enable(); err != nil {
		return err
	}

	if if0_0, err = if0.NewVIF(0); err != nil {
		return err
	}
	if err = if0_0.Enable(); err != nil {
		return err
	}

	// if1/if1-0.
	if if1, err = vswitch.NewInterface("dpdk", "if1", dev["if1"]); err != nil {
		return err
	}
	if err = if1.SetMTU(1518); err != nil {
		return err
	}
	if err = if1.Enable(); err != nil {
		return err
	}

	if if1_0, err = if1.NewVIF(0); err != nil {
		return err
	}
	if err = if1_0.Enable(); err != nil {
		return err
	}

	// IPsec Tunnel.
	if ifTunnel0, err = vswitch.NewInterface("tunnel", "ifTunnel0", nil); err != nil {
		return err
	}
	if err = ifTunnel0.Enable(); err != nil {
		return err
	}

	tunnel := vswitch.NewTunnel()
	tunnel.SetEncapsMethod(vswitch.EncapsMethodDirect)
	tunnel.SetSecurity(vswitch.SecurityIPSec)
	if ifTunnel0_0, err = ifTunnel0.NewTunnel(0, tunnel); err != nil {
		return err
	}

	// set TTL.
	tifTunnel0_0 := ifTunnel0_0.Tunnel()
	tifTunnel0_0.SetHopLimit(100)

	if err = ifTunnel0_0.Enable(); err != nil {
		return err
	}

	// dummy.
	// VRF.
	/*
		var vrf *vswitch.DummyVRF
		if vrf, err = vswitch.NewDummyVRF("dummyVRF"); err != nil {
			return err
		}
		if err = vrf.AddVIF(if0_0); err != nil {
			return err
		}
		if err = vrf.AddVIF(if1_0); err != nil {
			return err
		}
		if err = vrf.AddVIF(ifTunnel0_0); err != nil {
			return err
		}
		if err = vrf.Enable(); err != nil {
			return err
		}
	*/

	return nil
}
