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

package ipsec

// #include "sa.h"
// #include "rte_crypto_sym.h"
import "C"
import (
	"log"
	"unsafe"
)

// CipherAlgoType Cipher algorithm type.
type CipherAlgoType C.enum_rte_crypto_cipher_algorithm

// see: dpdk-XX.XX/lib/librte_cryptodev/rte_crypto_sym.h
//  => enum rte_crypto_cipher_algorithm
const (
	// NULL cipher algorithm. No mode applies to the NULL algorithm.
	CipherAlgoTypeNull       CipherAlgoType = C.RTE_CRYPTO_CIPHER_NULL
	CipherAlgoType3desCbc    CipherAlgoType = C.RTE_CRYPTO_CIPHER_3DES_CBC    // Triple DES in CBC mode
	CipherAlgoType3desCtr    CipherAlgoType = C.RTE_CRYPTO_CIPHER_3DES_CTR    // Triple DES in CTR mode
	CipherAlgoType3desEcb    CipherAlgoType = C.RTE_CRYPTO_CIPHER_3DES_ECB    // Triple DES in ECB mode
	CipherAlgoTypeAesCbc     CipherAlgoType = C.RTE_CRYPTO_CIPHER_AES_CBC     // AES in CBC mode
	CipherAlgoTypeAesCtr     CipherAlgoType = C.RTE_CRYPTO_CIPHER_AES_CTR     // AES in Counter mode
	CipherAlgoTypeAesEcb     CipherAlgoType = C.RTE_CRYPTO_CIPHER_AES_ECB     // AES in ECB mode
	CipherAlgoTypeAesF8      CipherAlgoType = C.RTE_CRYPTO_CIPHER_AES_F8      // AES in F8 mode
	CipherAlgoTypeAesXts     CipherAlgoType = C.RTE_CRYPTO_CIPHER_AES_XTS     // AES in XTS mode
	CipherAlgoTypeArc4       CipherAlgoType = C.RTE_CRYPTO_CIPHER_ARC4        // (A)RC4 cipher
	CipherAlgoTypeKasumiF8   CipherAlgoType = C.RTE_CRYPTO_CIPHER_KASUMI_F8   // KASUMI in F8 mode
	CipherAlgoTypeSnow3gUea2 CipherAlgoType = C.RTE_CRYPTO_CIPHER_SNOW3G_UEA2 // SNOW 3G in UEA2 mode
	CipherAlgoTypeZucEea3    CipherAlgoType = C.RTE_CRYPTO_CIPHER_ZUC_EEA3    // ZUC in EEA3 mode
)
const cipherAlgoTypeMax = uint(C.RTE_CRYPTO_CIPHER_LIST_END)

// CipherAlgoValues -- cipher algorithm's values
type CipherAlgoValues struct {
	IvLen     uint16
	BlockSize uint16
	KeyLen    uint16
	Keyword   string
}

// AuthAlgoType Auth algorithm type.
type AuthAlgoType C.enum_rte_crypto_auth_algorithm

// see: dpdk-XX.XX/lib/librte_cryptodev/rte_crypto_sym.h
//  => enum rte_crypto_auth_algorithm
const (
	// NULL hash
	AuthAlgoTypeNull       AuthAlgoType = C.RTE_CRYPTO_AUTH_NULL
	AuthAlgoTypeAesCbcMac  AuthAlgoType = C.RTE_CRYPTO_AUTH_AES_CBC_MAC  // AES-CBC-MAC
	AuthAlgoTypeAesCmac    AuthAlgoType = C.RTE_CRYPTO_AUTH_AES_CMAC     // AES CMAC
	AuthAlgoTypeAesGmac    AuthAlgoType = C.RTE_CRYPTO_AUTH_AES_GMAC     // AES GMAC
	AuthAlgoTypeAesXcbcMac AuthAlgoType = C.RTE_CRYPTO_AUTH_AES_XCBC_MAC // AES XCBC
	AuthAlgoTypeKasumiF9   AuthAlgoType = C.RTE_CRYPTO_AUTH_KASUMI_F9    // KASUMI in F9 mode
	AuthAlgoTypeMd5        AuthAlgoType = C.RTE_CRYPTO_AUTH_MD5          // MD5
	AuthAlgoTypeMd5Hmac    AuthAlgoType = C.RTE_CRYPTO_AUTH_MD5_HMAC     // HMAC using MD5
	AuthAlgoTypeSha1       AuthAlgoType = C.RTE_CRYPTO_AUTH_SHA1         // 128 bit SHA
	AuthAlgoTypeSha1Hmac   AuthAlgoType = C.RTE_CRYPTO_AUTH_SHA1_HMAC    // HMAC using 128 bit SHA
	AuthAlgoTypeSha224     AuthAlgoType = C.RTE_CRYPTO_AUTH_SHA224       // 224 bit SHA
	AuthAlgoTypeSha224Hmac AuthAlgoType = C.RTE_CRYPTO_AUTH_SHA224_HMAC  // HMAC using 224 bit SHA
	AuthAlgoTypeSha256     AuthAlgoType = C.RTE_CRYPTO_AUTH_SHA256       // 256 bit SHA
	AuthAlgoTypeSha256Hmac AuthAlgoType = C.RTE_CRYPTO_AUTH_SHA256_HMAC  // HMAC using 256 bit SHA
	AuthAlgoTypeSha384     AuthAlgoType = C.RTE_CRYPTO_AUTH_SHA384       // 384 bit SHA
	AuthAlgoTypeSha384Hmac AuthAlgoType = C.RTE_CRYPTO_AUTH_SHA384_HMAC  // HMAC using 384 bit SHA
	AuthAlgoTypeSha512     AuthAlgoType = C.RTE_CRYPTO_AUTH_SHA512       // 512 bit SHA
	AuthAlgoTypeSha512Hmac AuthAlgoType = C.RTE_CRYPTO_AUTH_SHA512_HMAC  // HMAC using 512 bit SHA
	AuthAlgoTypeSnow3gUia2 AuthAlgoType = C.RTE_CRYPTO_AUTH_SNOW3G_UIA2  // SNOW 3G in UIA2 mode
	AuthAlgoTypeZucEia3    AuthAlgoType = C.RTE_CRYPTO_AUTH_ZUC_EIA3     // ZUC in EIA3 mode
)
const authAlgoTypeMax = uint(C.RTE_CRYPTO_AUTH_LIST_END)

// AuthAlgoValues -- auth algorithm's values
type AuthAlgoValues struct {
	DigestLen uint16
	KeyLen    uint16
	KeyNotReq bool
	Keyword   string
}

// AeadAlgoType Auth algorithm type.
type AeadAlgoType C.enum_rte_crypto_aead_algorithm

// see: dpdk-XX.XX/lib/librte_cryptodev/rte_crypto_sym.h
//  => enum rte_crypto_aead_algorithm
const (
	AeadAlgoTypeCcm AeadAlgoType = C.RTE_CRYPTO_AEAD_AES_CCM // AES-CCM
	AeadAlgoTypeGcm AeadAlgoType = C.RTE_CRYPTO_AEAD_AES_GCM // AES-GCM
)
const aeadAlgoTypeMax = uint(C.RTE_CRYPTO_AEAD_LIST_END)

// AeadAlgoValues -- AEAD algorithm's values
type AeadAlgoValues struct {
	CipherAlgoValues
	DigestLen uint16
	AadLen    uint8
}

// SupportedCipherAlgo supported cipher algorithm
var SupportedCipherAlgo map[CipherAlgoType]CipherAlgoValues

// SupportedAuthAlgo supported auth algorithm
var SupportedAuthAlgo map[AuthAlgoType]AuthAlgoValues

// SupportedAeadAlgo supported AEAD algorithm
var SupportedAeadAlgo map[AeadAlgoType]AeadAlgoValues

func init() {
	// get Supported Algo
	SupportedCipherAlgo = getSupportedCipherAlgo()
	SupportedAuthAlgo = getSupportedAuthAlgo()
	SupportedAeadAlgo = getSupportedAeadAlgo()
	log.Printf("Supported %d cipher algos, %d auth algos, %d aead algos.\n",
		len(SupportedCipherAlgo), len(SupportedAuthAlgo), len(SupportedAeadAlgo))
}

// GetSupportedCipherAlgo Get Supported CipherAlgos.
func getSupportedCipherAlgo() map[CipherAlgoType]CipherAlgoValues {
	ret := map[CipherAlgoType]CipherAlgoValues{}
	len := C.size_t(0)
	algos := C.get_supported_cipher_algos(&len)
	slice := (*[1 << 30]C.struct_supported_cipher_algo)(unsafe.Pointer(algos))[:len]
	for _, a := range slice {
		k := CipherAlgoType(a.algo)
		v := CipherAlgoValues{
			IvLen:     uint16(a.iv_len),
			BlockSize: uint16(a.block_size),
			KeyLen:    uint16(a.key_len),
			Keyword:   C.GoString(a.keyword),
		}
		ret[k] = v
	}
	return ret
}

// GetSupportedAuthAlgo Get Supported AuthAlgos.
func getSupportedAuthAlgo() map[AuthAlgoType]AuthAlgoValues {
	ret := map[AuthAlgoType]AuthAlgoValues{}
	len := C.size_t(0)
	algos := C.get_supported_auth_algos(&len)
	slice := (*[1 << 30]C.struct_supported_auth_algo)(unsafe.Pointer(algos))[:len]
	for _, a := range slice {
		k := AuthAlgoType(a.algo)
		v := AuthAlgoValues{
			DigestLen: uint16(a.digest_len),
			KeyLen:    uint16(a.key_len),
			KeyNotReq: (a.key_not_req == 1),
			Keyword:   C.GoString(a.keyword),
		}
		ret[k] = v
	}
	return ret
}

// GetSupportedAeadAlgo Get Supported CipherAlgos.
func getSupportedAeadAlgo() map[AeadAlgoType]AeadAlgoValues {
	ret := map[AeadAlgoType]AeadAlgoValues{}
	len := C.size_t(0)
	algos := C.get_supported_aead_algos(&len)
	slice := (*[1 << 30]C.struct_supported_aead_algo)(unsafe.Pointer(algos))[:len]
	for _, a := range slice {
		k := AeadAlgoType(a.algo)
		v := AeadAlgoValues{
			CipherAlgoValues: CipherAlgoValues{
				IvLen:     uint16(a.iv_len),
				BlockSize: uint16(a.block_size),
				KeyLen:    uint16(a.key_len),
				Keyword:   C.GoString(a.keyword),
			},
			DigestLen: uint16(a.digest_len),
			AadLen:    uint8(a.aad_len),
		}
		ret[k] = v
	}
	return ret
}
