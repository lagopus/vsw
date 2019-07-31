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

package ipsec

// #include <rte_random.h>
// #include "sa.h"
import "C"
import (
	"fmt"
	"hash/fnv"
	"net"
	"unsafe"
)

// CSA struct ipsec_sa.
type CSA C.struct_ipsec_sa

// SAFlag sa flag
type SAFlag uint16

// bitfield?
const (
	IP4Tunnel SAFlag = C.IP4_TUNNEL
	IP6Tunnel SAFlag = C.IP6_TUNNEL
	Transport SAFlag = C.TRANSPORT
)

// CSAValue Values in SAD.
type CSAValue struct {
	CipherAlgoType CipherAlgoType // Cypher Algorithm Identifier
	CipherKey      []byte         // Key for Encriptiton
	AuthAlgoType   AuthAlgoType   // Authentication Algorithm Identifier
	AuthKey        []byte         // Key for Authentication
	AeadAlgoType   AeadAlgoType   // AEAD Algorithm Identifier
	AeadKey        []byte         // Key for AEAD
	LocalEPIP      net.IP         // Local Endpoint IP addr
	RemoteEPIP     net.IP         // Remote Endpoint IP addr
	EncapType      EncapType      // Type of encap , For NAT-T
	EncapProtocol  EncapProtoType // EncapProtocol(Not encap or UDP), For NAT-T
	EncapSrcPort   uint16         // EncapSrcPort, For NAT-T
	EncapDstPort   uint16         // EncapDstPort, For NAT-T
	Flags          SAFlag         // flag
}

func ip2ipAddr(from net.IP) (to C.struct_ip_addr) {
	// struct ip_addr is seem to [16]byte in Go
	from4 := from.To4()
	if from4 != nil { // IPv4
		copy(to.ip[:], []byte{from4[3], from4[2], from4[1], from4[0]})
	} else { // IPv6
		copy(to.ip[:], from[:])
	}
	return
}

func bytes2keyArr(from []byte) (to [C.MAX_KEY_SIZE]C.uint8_t, err error) {
	if C.MAX_KEY_SIZE < len(from) {
		err = fmt.Errorf("invalid keylen: %d > %d", len(from), C.MAX_KEY_SIZE)
		return
	}
	for i, v := range from {
		to[i] = (C.uint8_t)(v)
	}
	return
}

func ipAddr2ipNet(ver int, from C.struct_ip_addr, mask []byte) (to net.IPNet) {
	if ver == 4 {
		to.IP = net.IPv4(from.ip[0], from.ip[1], from.ip[2], from.ip[3])
	} else {
		copy(to.IP[:], from.ip[:])
	}
	to.Mask = mask
	return
}

func (sav *CSAValue) sav2saCipherAlgo(csa *C.struct_ipsec_sa) error {
	var err error

	if civ, exists := SupportedCipherAlgoByType[sav.CipherAlgoType]; exists {
		csa.cipher_algo = (C.enum_rte_crypto_cipher_algorithm)(civ.Algo)
		if (int)(civ.KeyLen) == len(sav.CipherKey) {
			csa.block_size = (C.uint16_t)(civ.BlockSize)
			csa.iv_len = (C.uint16_t)(civ.IvLen)
			switch civ.Algo {
			case CipherAlgoAesCbc, CipherAlgo3desCbc:
				csa.cipher_key_len = (C.uint16_t)(civ.KeyLen)
				csa.cipher_key, err = bytes2keyArr(sav.CipherKey)
				if err != nil {
					return err
				}
				csa.salt = (C.uint32_t)(C.rte_rand())
			case CipherAlgoAesCtr:
				csa.cipher_key_len = (C.uint16_t)(civ.KeyLen - 4)
				csa.cipher_key, err = bytes2keyArr(sav.CipherKey)
				if err != nil {
					return err
				}
				C.memcpy(unsafe.Pointer(&csa.salt),
					unsafe.Pointer(&csa.cipher_key[csa.cipher_key_len]), 4)
			}
		} else {
			return fmt.Errorf("invalid cipher keylen: %d, required: %d, algo: %d",
				len(sav.CipherKey), civ.KeyLen, sav.CipherAlgoType)
		}
	} else {
		return fmt.Errorf("cipher algorithm not supported %d", sav.CipherAlgoType)
	}

	return nil
}

func (sav *CSAValue) sav2saAuthAlgo(csa *C.struct_ipsec_sa) error {
	if aiv, exists := SupportedAuthAlgoByType[sav.AuthAlgoType]; exists {
		csa.auth_algo = (C.enum_rte_crypto_auth_algorithm)(aiv.Algo)
		aKey, err := bytes2keyArr(sav.AuthKey)
		if err != nil {
			return err
		}

		csa.digest_len = (C.uint16_t)(aiv.DigestLen)
		if aiv.KeyNotReq {
			csa.auth_key_len = (C.uint16_t)(aiv.KeyLen) // may 0
		} else if (int)(aiv.KeyLen) == len(sav.AuthKey) {
			csa.auth_key_len = (C.uint16_t)(aiv.KeyLen)
			csa.auth_key = aKey
		} else {
			return fmt.Errorf("invalid auth keylen: %d, required: %d, algo: %d",
				len(sav.AuthKey), aiv.KeyLen, sav.AuthAlgoType)
		}
	} else {
		return fmt.Errorf("auth algorithm not supported %d", sav.AuthAlgoType)
	}

	return nil
}

func (sav *CSAValue) sav2saAeadAlgo(csa *C.struct_ipsec_sa) error {
	var err error

	if aiv, exists := SupportedAeadAlgoByType[sav.AeadAlgoType]; exists {
		csa.aead_algo = (C.enum_rte_crypto_aead_algorithm)(aiv.Algo)
		if (int)(aiv.KeyLen) == len(sav.AeadKey) {
			csa.block_size = (C.uint16_t)(aiv.BlockSize)
			csa.iv_len = (C.uint16_t)(aiv.IvLen)
			csa.digest_len = (C.uint16_t)(aiv.DigestLen)
			csa.aad_len = (C.uint16_t)(aiv.AadLen)

			switch aiv.Algo {
			case AeadAlgoGcm:
				csa.cipher_key_len = (C.uint16_t)(aiv.KeyLen - 4)
				csa.cipher_key, err = bytes2keyArr(sav.AeadKey)
				if err != nil {
					return err
				}
				C.memcpy(unsafe.Pointer(&csa.salt),
					unsafe.Pointer(&csa.cipher_key[csa.cipher_key_len]), 4)
			}
		} else {
			return fmt.Errorf("invalid aead keylen: %d, required: %d, algo: %d",
				len(sav.AeadKey), aiv.KeyLen, sav.AeadAlgoType)
		}
	} else {
		return fmt.Errorf("aead algorithm not supported %d", sav.AeadAlgoType)
	}

	return nil
}

// Sav2sa convert SAValue to struct ipsec_sa in C
func (sav *CSAValue) Sav2sa(spi CSPI) (CSA, error) {
	var err error
	ret := C.struct_ipsec_sa{}
	ret.spi = (C.uint32_t)(spi)
	ret.flags = (C.uint16_t)(sav.Flags)

	// cipher/auth algo.
	if sav.CipherAlgoType != CipherAlgoTypeUnknown &&
		sav.AuthAlgoType != AuthAlgoTypeUnknown {
		// cipher algo.
		if err = sav.sav2saCipherAlgo(&ret); err != nil {
			return CSA(ret), err
		}
		// auth algo
		if err = sav.sav2saAuthAlgo(&ret); err != nil {
			return CSA(ret), err
		}
	} else if sav.AeadAlgoType != AeadAlgoTypeUnknown {
		// aead algo
		if err = sav.sav2saAeadAlgo(&ret); err != nil {
			return CSA(ret), err
		}
	} else {
		return CSA(ret), fmt.Errorf("Invalid algorithm: cipher = %d, auth = %d, aead = %d",
			sav.CipherAlgoType, sav.AuthAlgoType, sav.AeadAlgoType)
	}

	ret.src = ip2ipAddr(sav.LocalEPIP)
	ret.dst = ip2ipAddr(sav.RemoteEPIP)

	ret.encap_proto = C.uint8_t(sav.EncapProtocol)
	ret.encap_src_port = C.uint16_t(sav.EncapSrcPort)
	ret.encap_dst_port = C.uint16_t(sav.EncapDstPort)

	// generate hash.
	hash := fnv.New64a()
	str := fmt.Sprintf("%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v",
		ret.spi, ret.cipher_algo, ret.auth_algo,
		ret.aead_algo, ret.digest_len,
		ret.iv_len, ret.block_size,
		ret.flags, ret.src, ret.dst,
		ret.encap_proto, ret.encap_src_port, ret.encap_dst_port,
		ret.cipher_key, ret.cipher_key_len,
		ret.auth_key, ret.auth_key_len,
		ret.aad_len)
	_, _ = hash.Write([]byte(str))
	ret.hash = C.uint64_t(hash.Sum64())

	// Notes:
	// * Fields not used on Go side.
	//    ret.cdev_id_qp         => created by C.create_session
	//    ret.crypto_session     => created by C.create_session
	//    ret.xforms             => filled at C.sa_add_rules
	//    ret.seq                => increased in C.esp_outbound
	//
	// * Lifetimes are not used in C side. (lifetime is managed on Go side)
	//    sav.LifeTimeHard
	//    sav.LifeTimeSoft
	//    sav.LifeTimeByteHard
	//    sav.LifeTimeByteSoft

	// TBD:
	//   sav.Protocol
	//   sav.State
	return CSA(ret), nil
}
