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

package receiver

import (
	"github.com/lagopus/vsw/agents/tunnel/ipsec/pfkey"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
)

var encTbl = map[uint8]ipsec.CipherAlgo{
	pfkey.SADB_EALG_NONE:     ipsec.CipherAlgoNull,
	pfkey.SADB_EALG_NULL:     ipsec.CipherAlgoNull,
	pfkey.SADB_X_EALG_AESCBC: ipsec.CipherAlgoAesCbc,
	pfkey.SADB_X_EALG_AESCTR: ipsec.CipherAlgoAesCtr,
	pfkey.SADB_EALG_3DESCBC:  ipsec.CipherAlgo3desCbc,
}

var aeadTbl = map[uint8]ipsec.AeadAlgo{
	pfkey.SADB_X_EALG_AES_GCM_ICV16: ipsec.AeadAlgoGcm,
}

var authTbl = map[uint8]ipsec.AuthAlgo{
	pfkey.SADB_AALG_NONE:           ipsec.AuthAlgoNull,
	pfkey.SADB_X_AALG_NULL:         ipsec.AuthAlgoNull,
	pfkey.SADB_AALG_SHA1HMAC:       ipsec.AuthAlgoSha1Hmac,
	pfkey.SADB_X_AALG_SHA2_256HMAC: ipsec.AuthAlgoSha256Hmac,
}

var encRTbl = map[ipsec.CipherAlgoType]uint8{
	ipsec.CipherAlgoTypeNull:      pfkey.SADB_EALG_NULL,
	ipsec.CipherAlgoTypeAes128Cbc: pfkey.SADB_X_EALG_AESCBC,
	ipsec.CipherAlgoTypeAes256Cbc: pfkey.SADB_X_EALG_AESCBC,
	ipsec.CipherAlgoTypeAes128Ctr: pfkey.SADB_X_EALG_AESCTR,
	ipsec.CipherAlgoType3desCbc:   pfkey.SADB_EALG_3DESCBC,
}

var authRTbl = map[ipsec.AuthAlgoType]uint8{
	ipsec.AuthAlgoTypeNull:       pfkey.SADB_X_AALG_NULL,
	ipsec.AuthAlgoTypeSha1Hmac:   pfkey.SADB_AALG_SHA1HMAC,
	ipsec.AuthAlgoTypeSha256Hmac: pfkey.SADB_X_AALG_SHA2_256HMAC,
}

var aeadRTbl = map[ipsec.AeadAlgoType]uint8{
	ipsec.AeadAlgoTypeAes128Gcm: pfkey.SADB_X_EALG_AES_GCM_ICV16,
}
