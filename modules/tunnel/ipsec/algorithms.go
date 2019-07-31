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

// #include "sa.h"
// #include "rte_crypto_sym.h"
import "C"
import (
	"unsafe"

	"github.com/lagopus/vsw/modules/tunnel/log"
)

const (
	// UnknownAlgorithm Unknown.
	UnknownAlgorithm = C.UNKNOWN_ALGORITHM
)

// CipherAlgo Cipher algorithm type.
type CipherAlgo C.enum_rte_crypto_cipher_algorithm

// see: dpdk-XX.XX/lib/librte_cryptodev/rte_crypto_sym.h
//  => enum rte_crypto_cipher_algorithm
const (
	// NULL cipher algorithm. No mode applies to the NULL algorithm.
	CipherAlgoNull       CipherAlgo = C.RTE_CRYPTO_CIPHER_NULL
	CipherAlgo3desCbc    CipherAlgo = C.RTE_CRYPTO_CIPHER_3DES_CBC    // Triple DES in CBC mode
	CipherAlgo3desCtr    CipherAlgo = C.RTE_CRYPTO_CIPHER_3DES_CTR    // Triple DES in CTR mode
	CipherAlgo3desEcb    CipherAlgo = C.RTE_CRYPTO_CIPHER_3DES_ECB    // Triple DES in ECB mode
	CipherAlgoAesCbc     CipherAlgo = C.RTE_CRYPTO_CIPHER_AES_CBC     // AES in CBC mode
	CipherAlgoAesCtr     CipherAlgo = C.RTE_CRYPTO_CIPHER_AES_CTR     // AES in Counter mode
	CipherAlgoAesEcb     CipherAlgo = C.RTE_CRYPTO_CIPHER_AES_ECB     // AES in ECB mode
	CipherAlgoAesF8      CipherAlgo = C.RTE_CRYPTO_CIPHER_AES_F8      // AES in F8 mode
	CipherAlgoAesXts     CipherAlgo = C.RTE_CRYPTO_CIPHER_AES_XTS     // AES in XTS mode
	CipherAlgoArc4       CipherAlgo = C.RTE_CRYPTO_CIPHER_ARC4        // (A)RC4 cipher
	CipherAlgoKasumiF8   CipherAlgo = C.RTE_CRYPTO_CIPHER_KASUMI_F8   // KASUMI in F8 mode
	CipherAlgoSnow3gUea2 CipherAlgo = C.RTE_CRYPTO_CIPHER_SNOW3G_UEA2 // SNOW 3G in UEA2 mode
	CipherAlgoZucEea3    CipherAlgo = C.RTE_CRYPTO_CIPHER_ZUC_EEA3    // ZUC in EEA3 mode
)
const cipherAlgoMax = uint(C.RTE_CRYPTO_CIPHER_LIST_END)

// CipherAlgoType Type of CipherAlgo (alog-name + key-len).
type CipherAlgoType C.enum_cipher_algo_type

const (
	// CipherAlgoTypeUnknown Unknown.
	CipherAlgoTypeUnknown CipherAlgoType = C.CIPHER_ALGO_UNKNOWN
	// CipherAlgoTypeNull NULL.
	CipherAlgoTypeNull CipherAlgoType = C.CIPHER_ALGO_NULL
	// CipherAlgoTypeAes256Cbc AES-256-CBC.
	CipherAlgoTypeAes256Cbc CipherAlgoType = C.CIPHER_ALGO_AES_256_CBC
	// CipherAlgoTypeAes128Cbc AES-128-CBC.
	CipherAlgoTypeAes128Cbc CipherAlgoType = C.CIPHER_ALGO_AES_128_CBC
	// CipherAlgoTypeAes128Ctr AES-128-CTR.
	CipherAlgoTypeAes128Ctr CipherAlgoType = C.CIPHER_ALGO_AES_128_CTR
	// CipherAlgoType3desCbc 3DES-CBC
	CipherAlgoType3desCbc CipherAlgoType = C.CIPHER_ALGO_3DES_CBC
)

// AlgoValues Common fields of CipherAlgoValues and AeadAlgoValues.
type AlgoValues struct {
	IvLen     uint16
	BlockSize uint16
	KeyLen    uint16
	Keyword   string
}

// CipherAlgoValues -- cipher algorithm's values
type CipherAlgoValues struct {
	Algo CipherAlgo
	Type CipherAlgoType
	AlgoValues
}

// CipherAlgoInfo Cipher  algorithm info.
type CipherAlgoInfo struct {
	MaxKeyLen uint16
	MinKeyLen uint16
	Algos     map[uint16]*CipherAlgoValues
}

// AuthAlgo Auth algorithm type.
type AuthAlgo C.enum_rte_crypto_auth_algorithm

// see: dpdk-XX.XX/lib/librte_cryptodev/rte_crypto_sym.h
//  => enum rte_crypto_auth_algorithm
const (
	// NULL hash
	AuthAlgoNull       AuthAlgo = C.RTE_CRYPTO_AUTH_NULL
	AuthAlgoAesCbcMac  AuthAlgo = C.RTE_CRYPTO_AUTH_AES_CBC_MAC  // AES-CBC-MAC
	AuthAlgoAesCmac    AuthAlgo = C.RTE_CRYPTO_AUTH_AES_CMAC     // AES CMAC
	AuthAlgoAesGmac    AuthAlgo = C.RTE_CRYPTO_AUTH_AES_GMAC     // AES GMAC
	AuthAlgoAesXcbcMac AuthAlgo = C.RTE_CRYPTO_AUTH_AES_XCBC_MAC // AES XCBC
	AuthAlgoKasumiF9   AuthAlgo = C.RTE_CRYPTO_AUTH_KASUMI_F9    // KASUMI in F9 mode
	AuthAlgoMd5        AuthAlgo = C.RTE_CRYPTO_AUTH_MD5          // MD5
	AuthAlgoMd5Hmac    AuthAlgo = C.RTE_CRYPTO_AUTH_MD5_HMAC     // HMAC using MD5
	AuthAlgoSha1       AuthAlgo = C.RTE_CRYPTO_AUTH_SHA1         // 128 bit SHA
	AuthAlgoSha1Hmac   AuthAlgo = C.RTE_CRYPTO_AUTH_SHA1_HMAC    // HMAC using 128 bit SHA
	AuthAlgoSha224     AuthAlgo = C.RTE_CRYPTO_AUTH_SHA224       // 224 bit SHA
	AuthAlgoSha224Hmac AuthAlgo = C.RTE_CRYPTO_AUTH_SHA224_HMAC  // HMAC using 224 bit SHA
	AuthAlgoSha256     AuthAlgo = C.RTE_CRYPTO_AUTH_SHA256       // 256 bit SHA
	AuthAlgoSha256Hmac AuthAlgo = C.RTE_CRYPTO_AUTH_SHA256_HMAC  // HMAC using 256 bit SHA
	AuthAlgoSha384     AuthAlgo = C.RTE_CRYPTO_AUTH_SHA384       // 384 bit SHA
	AuthAlgoSha384Hmac AuthAlgo = C.RTE_CRYPTO_AUTH_SHA384_HMAC  // HMAC using 384 bit SHA
	AuthAlgoSha512     AuthAlgo = C.RTE_CRYPTO_AUTH_SHA512       // 512 bit SHA
	AuthAlgoSha512Hmac AuthAlgo = C.RTE_CRYPTO_AUTH_SHA512_HMAC  // HMAC using 512 bit SHA
	AuthAlgoSnow3gUia2 AuthAlgo = C.RTE_CRYPTO_AUTH_SNOW3G_UIA2  // SNOW 3G in UIA2 mode
	AuthAlgoZucEia3    AuthAlgo = C.RTE_CRYPTO_AUTH_ZUC_EIA3     // ZUC in EIA3 mode
)
const authAlgoMax = uint(C.RTE_CRYPTO_AUTH_LIST_END)

// AuthAlgoType Type of AuthAlgo (alog-name + key-len).
type AuthAlgoType C.enum_auth_algo_type

const (
	// AuthAlgoTypeUnknown Unknown.
	AuthAlgoTypeUnknown AuthAlgoType = C.AUTH_ALGO_UNKNOWN
	// AuthAlgoTypeNull NULL.
	AuthAlgoTypeNull AuthAlgoType = C.AUTH_ALGO_NULL
	// AuthAlgoTypeSha1Hmac SHA1-HMAC.
	AuthAlgoTypeSha1Hmac AuthAlgoType = C.AUTH_ALGO_SHA1_HMAC
	// AuthAlgoTypeSha256Hmac SHA256-HMAC.
	AuthAlgoTypeSha256Hmac AuthAlgoType = C.AUTH_ALGO_SHA256_HMAC
)

// AuthAlgoValues -- auth algorithm's values
type AuthAlgoValues struct {
	Algo      AuthAlgo
	Type      AuthAlgoType
	DigestLen uint16
	KeyLen    uint16
	KeyNotReq bool
	Keyword   string
}

// AuthAlgoInfo Auth algorithm info.
type AuthAlgoInfo struct {
	MaxKeyLen uint16
	MinKeyLen uint16
	Algos     map[uint16]*AuthAlgoValues
}

// AeadAlgo Auth algorithm type.
type AeadAlgo C.enum_rte_crypto_aead_algorithm

// see: dpdk-XX.XX/lib/librte_cryptodev/rte_crypto_sym.h
//  => enum rte_crypto_aead_algorithm
const (
	AeadAlgoCcm AeadAlgo = C.RTE_CRYPTO_AEAD_AES_CCM // AES-CCM
	AeadAlgoGcm AeadAlgo = C.RTE_CRYPTO_AEAD_AES_GCM // AES-GCM
)
const aeadAlgoMax = uint(C.RTE_CRYPTO_AEAD_LIST_END)

// AeadAlgoType Type of AeadAlgo (alog-name + key-len).
type AeadAlgoType C.enum_aead_algo_type

const (
	// AeadAlgoTypeUnknown Unknown.
	AeadAlgoTypeUnknown AeadAlgoType = C.AEAD_ALGO_UNKNOWN
	// AeadAlgoTypeAes128Gcm AES-128-GCM.
	AeadAlgoTypeAes128Gcm AeadAlgoType = C.AEAD_ALGO_AES_128_GCM
)

// AeadAlgoValues -- AEAD algorithm's values
type AeadAlgoValues struct {
	Algo      AeadAlgo
	Type      AeadAlgoType
	DigestLen uint16
	AadLen    uint8
	AlgoValues
}

// AeadAlgoInfo AEAD algorithm info.
type AeadAlgoInfo struct {
	MaxKeyLen uint16
	MinKeyLen uint16
	Algos     map[uint16]*AeadAlgoValues
}

// SupportedCipherAlgo supported cipher algorithm
var SupportedCipherAlgo map[CipherAlgo]*CipherAlgoInfo

// SupportedCipherAlgoByType supported cipher algorithm by type.
var SupportedCipherAlgoByType map[CipherAlgoType]*CipherAlgoValues

// SupportedAuthAlgo supported auth algorithm
var SupportedAuthAlgo map[AuthAlgo]*AuthAlgoInfo

// SupportedAuthAlgoByType supported auth algorithm by type.
var SupportedAuthAlgoByType map[AuthAlgoType]*AuthAlgoValues

// SupportedAeadAlgo supported AEAD algorithm
var SupportedAeadAlgo map[AeadAlgo]*AeadAlgoInfo

// SupportedAeadAlgoByType supported AEAD algorithm by type.
var SupportedAeadAlgoByType map[AeadAlgoType]*AeadAlgoValues

func init() {
	// set Supported Algo
	setSupportedCipherAlgo()
	setSupportedAuthAlgo()
	setSupportedAeadAlgo()
	log.Logger.Info("Supported %d cipher algos, %d auth algos, %d aead algos",
		len(SupportedCipherAlgoByType),
		len(SupportedAuthAlgoByType),
		len(SupportedAeadAlgoByType))
}

// setSupportedCipherAlgo Set Supported CipherAlgos.
func setSupportedCipherAlgo() {
	spa := map[CipherAlgo]*CipherAlgoInfo{}
	spaByType := map[CipherAlgoType]*CipherAlgoValues{}

	len := C.size_t(0)
	algos := C.get_supported_cipher_algos(&len)
	slice := (*[1 << 30]C.struct_supported_cipher_algo)(unsafe.Pointer(algos))[:len]
	for _, a := range slice {
		algo := CipherAlgo(a.algo)
		atype := CipherAlgoType(a.atype)
		v := &CipherAlgoValues{
			Algo: algo,
			Type: atype,
			AlgoValues: AlgoValues{
				IvLen:     uint16(a.iv_len),
				BlockSize: uint16(a.block_size),
				KeyLen:    uint16(a.key_len),
				Keyword:   C.GoString(a.keyword),
			},
		}

		spaByType[atype] = v

		if info, ok := spa[algo]; ok {
			// already exists.
			info.Algos[v.KeyLen] = v
			if info.MaxKeyLen < v.KeyLen {
				info.MaxKeyLen = v.KeyLen
			}
			if info.MinKeyLen > v.KeyLen {
				info.MinKeyLen = v.KeyLen
			}
		} else {
			// not found.
			info := &CipherAlgoInfo{
				MaxKeyLen: v.KeyLen,
				MinKeyLen: v.KeyLen,
				Algos: map[uint16]*CipherAlgoValues{
					v.KeyLen: v,
				},
			}
			spa[algo] = info
		}
	}

	SupportedCipherAlgo = spa
	SupportedCipherAlgoByType = spaByType
}

// setSupportedAuthAlgo Set Supported AuthAlgos.
func setSupportedAuthAlgo() {
	spa := map[AuthAlgo]*AuthAlgoInfo{}
	spaByType := map[AuthAlgoType]*AuthAlgoValues{}

	len := C.size_t(0)
	algos := C.get_supported_auth_algos(&len)
	slice := (*[1 << 30]C.struct_supported_auth_algo)(unsafe.Pointer(algos))[:len]
	for _, a := range slice {
		algo := AuthAlgo(a.algo)
		atype := AuthAlgoType(a.atype)

		keyLen := uint16(0)
		if a.key_not_req != 1 {
			keyLen = uint16(a.key_len)
		}
		v := &AuthAlgoValues{
			Algo:      algo,
			Type:      atype,
			DigestLen: uint16(a.digest_len),
			KeyLen:    keyLen,
			KeyNotReq: (a.key_not_req == 1),
			Keyword:   C.GoString(a.keyword),
		}

		spaByType[atype] = v

		if info, ok := spa[algo]; ok {
			// already exists.
			info.Algos[v.KeyLen] = v
			if info.MaxKeyLen > v.KeyLen {
				info.MaxKeyLen = v.KeyLen
			}
			if info.MinKeyLen < v.KeyLen {
				info.MinKeyLen = v.KeyLen
			}
		} else {
			// not found.
			info := &AuthAlgoInfo{
				MaxKeyLen: v.KeyLen,
				MinKeyLen: v.KeyLen,
				Algos: map[uint16]*AuthAlgoValues{
					v.KeyLen: v,
				},
			}
			spa[algo] = info
		}
	}

	SupportedAuthAlgo = spa
	SupportedAuthAlgoByType = spaByType
}

// setSupportedAeadAlgo Set Supported CipherAlgos.
func setSupportedAeadAlgo() {
	spa := map[AeadAlgo]*AeadAlgoInfo{}
	spaByType := map[AeadAlgoType]*AeadAlgoValues{}

	len := C.size_t(0)
	algos := C.get_supported_aead_algos(&len)
	slice := (*[1 << 30]C.struct_supported_aead_algo)(unsafe.Pointer(algos))[:len]
	for _, a := range slice {
		algo := AeadAlgo(a.algo)
		atype := AeadAlgoType(a.atype)
		v := &AeadAlgoValues{
			Algo:      algo,
			Type:      atype,
			DigestLen: uint16(a.digest_len),
			AadLen:    uint8(a.aad_len),
			AlgoValues: AlgoValues{
				IvLen:     uint16(a.iv_len),
				BlockSize: uint16(a.block_size),
				KeyLen:    uint16(a.key_len),
				Keyword:   C.GoString(a.keyword),
			},
		}

		spaByType[atype] = v

		if info, ok := spa[algo]; ok {
			// already exists.
			info.Algos[v.KeyLen] = v
			if info.MaxKeyLen > v.KeyLen {
				info.MaxKeyLen = v.KeyLen
			}
			if info.MinKeyLen < v.KeyLen {
				info.MinKeyLen = v.KeyLen
			}
		} else {
			// not found.
			info := &AeadAlgoInfo{
				MaxKeyLen: v.KeyLen,
				MinKeyLen: v.KeyLen,
				Algos: map[uint16]*AeadAlgoValues{
					v.KeyLen: v,
				},
			}
			spa[algo] = info
		}
	}

	SupportedAeadAlgo = spa
	SupportedAeadAlgoByType = spaByType
}
