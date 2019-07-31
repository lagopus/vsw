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

package sad

import (
	"fmt"
	"net"
	"time"

	"github.com/lagopus/vsw/agents/tunnel/ipsec/config"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/sad"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/modules/tunnel/log"
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

func vSA2SAvEncap(sa *vswitch.SA, sav *sad.SAValue) error {
	switch sa.EncapProtocol {
	case vswitch.IPP_UDP:
		sav.EncapProtocol = ipsec.EncapProtoUDP
		sav.EncapType = ipsec.UDPEncapESPinUDP
		sav.EncapSrcPort = sa.EncapSrcPort
		sav.EncapDstPort = sa.EncapDstPort
	case vswitch.IPP_NONE:
		sav.EncapProtocol = ipsec.EncapProtoNone
	default:
		return fmt.Errorf("Bad encap protocol: %v", sa.EncapProtocol)
	}
	return nil
}

func vSA2SAvMode(sa *vswitch.SA, sav *sad.SAValue) error {
	// Precondition: LocalEPIP, RemoteEPIP converted before Mode.
	isIPv4Fn := func(ip net.IP) bool {
		return (ip == nil || ip.To4() != nil)
	}

	switch sa.Mode {
	case vswitch.ModeTunnel:
		if isIPv4Fn(sav.LocalEPIP) && isIPv4Fn(sav.RemoteEPIP) {
			sav.Flags = ipsec.IP4Tunnel
		} else if !isIPv4Fn(sav.LocalEPIP) && !isIPv4Fn(sav.RemoteEPIP) {
			sav.Flags = ipsec.IP6Tunnel
		} else {
			return fmt.Errorf("Bad IP version: local: %v, remote: %v",
				sav.LocalEPIP, sav.RemoteEPIP)
		}
	default:
		return fmt.Errorf("Unsupported mode: %v", sa.Mode)
	}

	return nil
}

// Convert map for Cipher algos.
var cipherAlgos = map[vswitch.ESPEncrypt]ipsec.CipherAlgoType{
	vswitch.EncryptNULL: ipsec.CipherAlgoTypeNull,
	vswitch.EncryptAES:  ipsec.CipherAlgoTypeAes128Cbc,
}

// Convert map for AEAD algos.
var aeadAlgos = map[vswitch.ESPEncrypt]ipsec.AeadAlgoType{
	vswitch.EncryptGCM: ipsec.AeadAlgoTypeAes128Gcm,
}

func vSA2SAvCipherAlgo(sa *vswitch.SA, sav *sad.SAValue) error {
	var savKey *[]byte
	var algoKeyLen uint16

	if a, ok := cipherAlgos[sa.Encrypt]; ok {
		// Cipher algo type.
		sav.CipherAlgoType = a

		if value, ok := ipsec.SupportedCipherAlgoByType[a]; ok {
			savKey = &sav.CipherKey
			algoKeyLen = value.KeyLen
		} else {
			return fmt.Errorf("Unsupported Cipher algo: %v", sa.Encrypt)
		}
	} else if a, ok := aeadAlgos[sa.Encrypt]; ok {
		// AEAD algo type.
		sav.AeadAlgoType = a

		if value, ok := ipsec.SupportedAeadAlgoByType[a]; ok {
			savKey = &sav.AeadKey
			algoKeyLen = value.KeyLen
		} else {
			return fmt.Errorf("Unsupported AEAD algo: %v", sa.Encrypt)
		}
	} else {
		return fmt.Errorf("Unsupported Cipher/AEAD algo: %v", sa.Encrypt)
	}

	// Null Algo doesn't have AlgoKey.
	if sav.CipherAlgoType == ipsec.CipherAlgoTypeNull {
		if len(sa.EncKey) != 0 {
			return fmt.Errorf("Bad Cipher algo key length: %v", sa.EncKey)
		}
		return nil
	}

	// key
	if key, err := config.ParseHexKey(sa.EncKey, ""); err == nil {
		*savKey = key
	} else {
		return err
	}

	if uint16(len(*savKey)) != algoKeyLen {
		return fmt.Errorf("Bad Cipher/AEAD algo key length: %v", sa.EncKey)
	}

	return nil
}

// Convert map for Auth algos.
var authAlgos = map[vswitch.ESPAuth]ipsec.AuthAlgoType{
	vswitch.AuthNULL: ipsec.AuthAlgoTypeNull,
	vswitch.AuthSHA1: ipsec.AuthAlgoTypeSha1Hmac,
}

func vSA2SAvAuthAlgo(sa *vswitch.SA, sav *sad.SAValue) error {
	if sav.AeadAlgoType != ipsec.AeadAlgoTypeUnknown {
		// AeadAlgo doesn't have to specify AuthAlgo.
		return nil
	}

	if a, ok := authAlgos[sa.Auth]; ok {
		// algo type.
		sav.AuthAlgoType = a

		var algoValue *ipsec.AuthAlgoValues
		if value, ok := ipsec.SupportedAuthAlgoByType[a]; ok {
			algoValue = value
		} else {
			return fmt.Errorf("Unsupported AuthAlgo: %v", sa.Auth)
		}

		// Null Algo doesn't have AlgoKey.
		if sav.AuthAlgoType == ipsec.AuthAlgoTypeNull {
			if len(sa.AuthKey) != 0 {
				return fmt.Errorf("Bad AuthAlgo key length: %v", sa.AuthKey)
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
			return fmt.Errorf("Bad AuthAlgo key length: %v", sa.EncKey)
		}
	} else {
		return fmt.Errorf("Unsupported AuthAlgo: %v", sa.Encrypt)
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

	sav.LocalEPIP = sa.LocalPeer

	return nil
}

func vSA2SAvRemoteEPIP(sa *vswitch.SA, sav *sad.SAValue) error {
	if sa.RemotePeer == nil {
		return nil
	}

	sav.RemoteEPIP = sa.RemotePeer

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
	// Cipher/AEAD algo.
	if err := vSA2SAvCipherAlgo(sa, sav); err != nil {
		return err
	}

	// Precondition: CipherAlgo converted before AuthAlgo.
	// Auth algo.
	if err := vSA2SAvAuthAlgo(sa, sav); err != nil {
		return err
	}

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

	// Encap (NAT-T).
	if err := vSA2SAvEncap(sa, sav); err != nil {
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
	log.Logger.Info("Add SA: %v", sa)

	selector := &sad.SASelector{
		VRFIndex: vrf.Index(),
		SPI:      sad.SPI(sa.SPI),
	}
	value := &sad.SAValue{}
	if err := vSA2SAv(sa, value); err != nil {
		log.Logger.Err("SA: Error: %v", err)
		return
	}

	for _, mgr := range mgrs {
		if err := mgr.AddSA(selector, value); err != nil {
			log.Logger.Err("Add SA: Error: %v", err)
			return
		}
		if err := mgr.EnableSA(selector); err != nil {
			log.Logger.Err("Enable SA: Error: %v", err)
			return
		}
	}
}

// DeleteSA Delete SA.
func DeleteSA(vrf *vswitch.VRF, sa *vswitch.SA) {
	log.Logger.Info("Delete SA: %v", sa)

	selector := &sad.SASelector{
		VRFIndex: vrf.Index(),
		SPI:      sad.SPI(sa.SPI),
	}

	for _, mgr := range mgrs {
		if err := mgr.DeleteSA(selector); err != nil {
			log.Logger.Err("Delete SA: Error: %v", err)
			return
		}
	}
}

// UpdateSA Update SA.
func UpdateSA(vrf *vswitch.VRF, sa *vswitch.SA) {
	log.Logger.Info("Update SA: %v", sa)

	selector := &sad.SASelector{
		VRFIndex: vrf.Index(),
		SPI:      sad.SPI(sa.SPI),
	}
	value := &sad.SAValue{}
	if err := vSA2SAv(sa, value); err != nil {
		log.Logger.Err("SA: Error: %v", err)
		return
	}

	for _, mgr := range mgrs {
		if err := mgr.UpdateSA(selector, value); err != nil {
			log.Logger.Err("Update SA: Error: %v", err)
			return
		}
		if err := mgr.EnableSA(selector); err != nil {
			log.Logger.Err("Enable SA: Error: %v", err)
			return
		}
	}
}
