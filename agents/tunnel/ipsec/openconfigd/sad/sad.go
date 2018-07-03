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

package sad

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/lagopus/vsw/agents/tunnel/ipsec/config"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/sad"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/vswitch"
)

var (
	mgrs [2]*sad.Mgr // 0: for Inbound, 1: for outbound
)

func init() {
	mgrs = [2]*sad.Mgr{
		sad.GetMgr(ipsec.DirectionTypeIn),
		sad.GetMgr(ipsec.DirectionTypeOut),
	}
}

func vSA2SAvMode(sa *vswitch.SA, sav *sad.SAValue) error {
	// Precondition: LocalEPIP, RemoteEPIP converted before Mode.
	isIPv4Fn := func(ip net.IP) bool {
		return (ip == nil || ip.To4() != nil)
	}

	switch sa.Mode {
	case vswitch.ModeTunnel:
		if isIPv4Fn(sav.LocalEPIP.IP) && isIPv4Fn(sav.RemoteEPIP.IP) {
			sav.Flags = ipsec.IP4Tunnel
		} else {
			sav.Flags = ipsec.IP6Tunnel
		}
	default:
		return fmt.Errorf("Unsupported mode: %v\n", sa.Mode)
	}

	return nil
}

var cipherAlgos = map[vswitch.ESPEncrypt]string{
	vswitch.EncryptNULL: "null",
	vswitch.EncryptAES:  "aes-128-cbc",
}

func vSA2SAvCipherAlgo(sa *vswitch.SA, sav *sad.SAValue) error {
	if algoStr, ok := cipherAlgos[sa.Encrypt]; ok {
		algos := config.CipherAlgos()
		if a, ok := algos[algoStr]; ok {
			// algo type.
			sav.CipherAlgo = a

			var algoValue ipsec.CipherAlgoValues
			if value, ok := ipsec.SupportedCipherAlgo[a]; ok {
				algoValue = value
			} else {
				return fmt.Errorf("Unsupported CipherAlgo: %v\n", sa.Encrypt)
			}

			// Null Algo doesn't have AlgoKey.
			if sav.CipherAlgo == ipsec.CipherAlgoTypeNull {
				if len(sa.EncKey) != 0 {
					return fmt.Errorf("Bad CipherAlgo key length: %v\n", sa.EncKey)
				}
				return nil
			}

			// key
			if key, err := config.ParseHexKey(sa.EncKey, ""); err == nil {
				sav.CipherKey = key
			} else {
				return err
			}

			if uint16(len(sav.CipherKey)) != algoValue.KeyLen {
				return fmt.Errorf("Bad CipherAlgo key length: %v\n", sa.EncKey)
			}
		} else {
			return fmt.Errorf("Unsupported CipherAlgo: %v\n", sa.Encrypt)
		}
	} else {
		return fmt.Errorf("Unsupported CipherAlgo: %v\n", sa.Encrypt)
	}

	return nil
}

var authAlgos = map[vswitch.ESPAuth]string{
	vswitch.AuthNULL: "null",
	vswitch.AuthSHA1: "sha1-hmac",
}

func vSA2SAvAuthAlgo(sa *vswitch.SA, sav *sad.SAValue) error {
	if algoStr, ok := authAlgos[sa.Auth]; ok {
		algos := config.AuthAlgos()
		if a, ok := algos[algoStr]; ok {
			// algo type.
			sav.AuthAlgo = a

			var algoValue ipsec.AuthAlgoValues
			if value, ok := ipsec.SupportedAuthAlgo[a]; ok {
				algoValue = value
			} else {
				return fmt.Errorf("Unsupported AuthAlgo: %v\n", sa.Auth)
			}

			// Null Algo doesn't have AlgoKey.
			if sav.AuthAlgo == ipsec.AuthAlgoTypeNull {
				if len(sa.AuthKey) != 0 {
					return fmt.Errorf("Bad AuthAlgo key length: %v\n", sa.AuthKey)
				}
				return nil
			}

			// key.
			if key, err := config.ParseHexKey(sa.AuthKey, ""); err == nil {
				sav.AuthKey = key
			} else {
				return err
			}

			if uint16(len(sav.AuthKey)) != algoValue.KeyLen {
				return fmt.Errorf("Bad AuthAlgo key length: %v\n", sa.EncKey)
			}
		} else {
			return fmt.Errorf("Unsupported AuthAlgo: %v\n", sa.Encrypt)
		}
	} else {
		return fmt.Errorf("Unsupported AuthAlgo: %v\n", sa.Encrypt)
	}

	return nil
}

func vSA2SAvAeadAlgo(sa *vswitch.SA, sav *sad.SAValue) error {
	return nil
}

func vSA2SAvLocalEPIP(sa *vswitch.SA, sav *sad.SAValue) error {
	if sa.LocalPeer == nil {
		return nil
	}

	ip := sa.LocalPeer
	sav.LocalEPIP = net.IPNet{
		IP: ip,
		// Mask is unused.
		Mask: net.CIDRMask(len(ip)*8, len(ip)*8),
	}
	return nil
}

func vSA2SAvRemoteEPIP(sa *vswitch.SA, sav *sad.SAValue) error {
	if sa.RemotePeer == nil {
		return nil
	}

	ip := sa.RemotePeer
	sav.RemoteEPIP = net.IPNet{
		IP: ip,
		// Mask is unused.
		Mask: net.CIDRMask(len(ip)*8, len(ip)*8),
	}
	return nil
}

func vSA2SAvLifeTimeHard(sa *vswitch.SA, sav *sad.SAValue) error {
	if sa.LifeTimeInSeconds == 0 {
		// 0 is unlimited.
		return nil
	}

	now := time.Now()
	sav.LifeTimeHard = now.Add(time.Duration(sa.LifeTimeInSeconds) * time.Second)
	return nil
}

func vSA2SAvLifeTimeByteHard(sa *vswitch.SA, sav *sad.SAValue) error {
	// 0 is unlimited.
	sav.LifeTimeByteHard = uint64(sa.LifeTimeInByte)
	return nil
}

func vSA2SAvProtocol(sa *vswitch.SA, sav *sad.SAValue) error {
	// Note: ESP only, cf. yang.
	sav.Protocol = ipsec.SecurityProtocolTypeESP
	return nil
}

func vSA2SAv(sa *vswitch.SA, sav *sad.SAValue) error {
	// Cipher algo.
	if err := vSA2SAvCipherAlgo(sa, sav); err != nil {
		return err
	}
	// Auth algo.
	if err := vSA2SAvAuthAlgo(sa, sav); err != nil {
		return err
	}
	// TODO: Aead algo.

	// LocalEPIP.
	if err := vSA2SAvLocalEPIP(sa, sav); err != nil {
		return err
	}
	// RemoteEPIP.
	if err := vSA2SAvRemoteEPIP(sa, sav); err != nil {
		return err
	}
	// Protocol.
	if err := vSA2SAvProtocol(sa, sav); err != nil {
		return err
	}
	// LifeTimeHard.
	if err := vSA2SAvLifeTimeHard(sa, sav); err != nil {
		return err
	}
	// LifeTimeByteHard.
	if err := vSA2SAvLifeTimeByteHard(sa, sav); err != nil {
		return err
	}
	// Mode. Precondition: LocalEPIP, RemoteEPIP converted before Mode.
	if err := vSA2SAvMode(sa, sav); err != nil {
		return err
	}

	return nil
}

// public.

// AddSA Addd SA.
func AddSA(vrf *vswitch.VRF, sa *vswitch.SA) {
	log.Printf("Add SA: %v", sa)

	selector := &sad.SASelector{
		VRFIndex: vrf.Index(),
		SPI:      sad.SPI(sa.SPI),
	}
	value := &sad.SAValue{}
	if err := vSA2SAv(sa, value); err != nil {
		log.Printf("SA: Error: %v\n", err)
		return
	}

	for _, mgr := range mgrs {
		if err := mgr.AddSA(selector, value); err != nil {
			log.Printf("Add SA: Error: %v\n", err)
			return
		}
		if err := mgr.EnableSA(selector); err != nil {
			log.Printf("Enable SA: Error: %v\n", err)
			return
		}
	}
}

// DeleteSA Delete SA.
func DeleteSA(vrf *vswitch.VRF, sa *vswitch.SA) {
	log.Printf("Delete SA: %v", sa)

	selector := &sad.SASelector{
		VRFIndex: vrf.Index(),
		SPI:      sad.SPI(sa.SPI),
	}

	for _, mgr := range mgrs {
		if err := mgr.DeleteSA(selector); err != nil {
			log.Printf("Delete SA: Error: %v\n", err)
			return
		}
	}
}

// UpdateSA Update SA.
func UpdateSA(vrf *vswitch.VRF, sa *vswitch.SA) {
	log.Printf("Update SA: %v", sa)

	selector := &sad.SASelector{
		VRFIndex: vrf.Index(),
		SPI:      sad.SPI(sa.SPI),
	}
	value := &sad.SAValue{}
	if err := vSA2SAv(sa, value); err != nil {
		log.Printf("SA: Error: %v\n", err)
		return
	}

	for _, mgr := range mgrs {
		if err := mgr.UpdateSA(selector, value); err != nil {
			log.Printf("Update SA: Error: %v\n", err)
			return
		}
		if err := mgr.EnableSA(selector); err != nil {
			log.Printf("Enable SA: Error: %v\n", err)
			return
		}
	}
}
