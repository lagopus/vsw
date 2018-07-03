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

package pfkey

const (
	PF_KEY_V2                  = 2
	PFKEYV2_REVISION           = 199806
	SADB_RESERVED              = 0
	SADB_GETSPI                = 1
	SADB_UPDATE                = 2
	SADB_ADD                   = 3
	SADB_DELETE                = 4
	SADB_GET                   = 5
	SADB_ACQUIRE               = 6
	SADB_REGISTER              = 7
	SADB_EXPIRE                = 8
	SADB_FLUSH                 = 9
	SADB_DUMP                  = 10
	SADB_X_PROMISC             = 11
	SADB_X_PCHANGE             = 12
	SADB_X_SPDUPDATE           = 13
	SADB_X_SPDADD              = 14
	SADB_X_SPDDELETE           = 15
	SADB_X_SPDGET              = 16
	SADB_X_SPDACQUIRE          = 17
	SADB_X_SPDDUMP             = 18
	SADB_X_SPDFLUSH            = 19
	SADB_X_SPDSETIDX           = 20
	SADB_X_SPDEXPIRE           = 21
	SADB_X_SPDDELETE2          = 22
	SADB_X_NAT_T_NEW_MAPPING   = 23
	SADB_X_MIGRATE             = 24
	SADB_MAX                   = 24
	SADB_SAFLAGS_PFS           = 1
	SADB_SAFLAGS_NOPMTUDISC    = 0x20000000
	SADB_SAFLAGS_DECAP_DSCP    = 0x40000000
	SADB_SAFLAGS_NOECN         = 0x80000000
	SADB_SASTATE_LARVAL        = 0
	SADB_SASTATE_MATURE        = 1
	SADB_SASTATE_DYING         = 2
	SADB_SASTATE_DEAD          = 3
	SADB_SASTATE_MAX           = 3
	SADB_SATYPE_UNSPEC         = 0
	SADB_SATYPE_AH             = 2
	SADB_SATYPE_ESP            = 3
	SADB_SATYPE_RSVP           = 5
	SADB_SATYPE_OSPFV2         = 6
	SADB_SATYPE_RIPV2          = 7
	SADB_SATYPE_MIP            = 8
	SADB_X_SATYPE_IPCOMP       = 9
	SADB_SATYPE_MAX            = 9
	SADB_AALG_NONE             = 0
	SADB_AALG_MD5HMAC          = 2
	SADB_AALG_SHA1HMAC         = 3
	SADB_X_AALG_SHA2_256HMAC   = 5
	SADB_X_AALG_SHA2_384HMAC   = 6
	SADB_X_AALG_SHA2_512HMAC   = 7
	SADB_X_AALG_RIPEMD160HMAC  = 8
	SADB_X_AALG_AES_XCBC_MAC   = 9
	SADB_X_AALG_NULL           = 251
	SADB_AALG_MAX              = 251
	SADB_EALG_NONE             = 0
	SADB_EALG_DESCBC           = 2
	SADB_EALG_3DESCBC          = 3
	SADB_X_EALG_CASTCBC        = 6
	SADB_X_EALG_BLOWFISHCBC    = 7
	SADB_EALG_NULL             = 11
	SADB_X_EALG_AESCBC         = 12
	SADB_X_EALG_AESCTR         = 13
	SADB_X_EALG_AES_CCM_ICV8   = 14
	SADB_X_EALG_AES_CCM_ICV12  = 15
	SADB_X_EALG_AES_CCM_ICV16  = 16
	SADB_X_EALG_AES_GCM_ICV8   = 18
	SADB_X_EALG_AES_GCM_ICV12  = 19
	SADB_X_EALG_AES_GCM_ICV16  = 20
	SADB_X_EALG_CAMELLIACBC    = 22
	SADB_X_EALG_NULL_AES_GMAC  = 23
	SADB_EALG_MAX              = 253
	SADB_X_EALG_SERPENTCBC     = 252
	SADB_X_EALG_TWOFISHCBC     = 253
	SADB_X_CALG_NONE           = 0
	SADB_X_CALG_OUI            = 1
	SADB_X_CALG_DEFLATE        = 2
	SADB_X_CALG_LZS            = 3
	SADB_X_CALG_LZJH           = 4
	SADB_X_CALG_MAX            = 4
	SADB_EXT_RESERVED          = 0
	SADB_EXT_SA                = 1
	SADB_EXT_LIFETIME_CURRENT  = 2
	SADB_EXT_LIFETIME_HARD     = 3
	SADB_EXT_LIFETIME_SOFT     = 4
	SADB_EXT_ADDRESS_SRC       = 5
	SADB_EXT_ADDRESS_DST       = 6
	SADB_EXT_ADDRESS_PROXY     = 7
	SADB_EXT_KEY_AUTH          = 8
	SADB_EXT_KEY_ENCRYPT       = 9
	SADB_EXT_IDENTITY_SRC      = 10
	SADB_EXT_IDENTITY_DST      = 11
	SADB_EXT_SENSITIVITY       = 12
	SADB_EXT_PROPOSAL          = 13
	SADB_EXT_SUPPORTED_AUTH    = 14
	SADB_EXT_SUPPORTED_ENCRYPT = 15
	SADB_EXT_SPIRANGE          = 16
	SADB_X_EXT_KMPRIVATE       = 17
	SADB_X_EXT_POLICY          = 18
	SADB_X_EXT_SA2             = 19
	SADB_X_EXT_NAT_T_TYPE      = 20
	SADB_X_EXT_NAT_T_SPORT     = 21
	SADB_X_EXT_NAT_T_DPORT     = 22
	SADB_X_EXT_NAT_T_OA        = 23
	SADB_X_EXT_SEC_CTX         = 24
	SADB_X_EXT_KMADDRESS       = 25
	SADB_X_EXT_FILTER          = 26
	SADB_EXT_MAX               = 26
	SADB_IDENTTYPE_RESERVED    = 0
	SADB_IDENTTYPE_PREFIX      = 1
	SADB_IDENTTYPE_FQDN        = 2
	SADB_IDENTTYPE_USERFQDN    = 3
	SADB_IDENTTYPE_MAX         = 3
	IPSEC_MODE_ANY             = 0 /* We do not support this for SA */
	IPSEC_MODE_TRANSPORT       = 1
	IPSEC_MODE_TUNNEL          = 2
	IPSEC_MODE_BEET            = 3
	IPSEC_DIR_ANY              = 0
	IPSEC_DIR_INBOUND          = 1
	IPSEC_DIR_OUTBOUND         = 2
	IPSEC_DIR_FWD              = 3 /* It is our own */
	IPSEC_DIR_MAX              = 4
	IPSEC_DIR_INVALID          = 5
	IPSEC_POLICY_DISCARD       = 0
	IPSEC_POLICY_NONE          = 1
	IPSEC_POLICY_IPSEC         = 2
	IPSEC_POLICY_ENTRUST       = 3
	IPSEC_POLICY_BYPASS        = 4
	IPSEC_LEVEL_DEFAULT        = 0
	IPSEC_LEVEL_USE            = 1
	IPSEC_LEVEL_REQUIRE        = 2
	IPSEC_LEVEL_UNIQUE         = 3
	IPSEC_MANUAL_REQID_MAX     = 0x3ff
	IPSEC_REPLAYWSIZE          = 32
)

var SadbMsgTypes = [...]string{
	0:  "SADB_RESERVED",
	1:  "SADB_GETSPI",
	2:  "SADB_UPDATE",
	3:  "SADB_ADD",
	4:  "SADB_DELETE",
	5:  "SADB_GET",
	6:  "SADB_ACQUIRE",
	7:  "SADB_REGISTER",
	8:  "SADB_EXPIRE",
	9:  "SADB_FLUSH",
	10: "SADB_DUMP",
	11: "SADB_X_PROMISC",
	12: "SADB_X_PCHANGE",
	13: "SADB_X_SPDUPDATE",
	14: "SADB_X_SPDADD",
	15: "SADB_X_SPDDELETE",
	16: "SADB_X_SPDGET",
	17: "SADB_X_SPDACQUIRE",
	18: "SADB_X_SPDDUMP",
	19: "SADB_X_SPDFLUSH",
	20: "SADB_X_SPDSETIDX",
	21: "SADB_X_SPDEXPIRE",
	22: "SADB_X_SPDDELETE2",
	23: "SADB_X_NAT_T_NEW_MAPPING",
	24: "SADB_X_MIGRATE",
	25: "SADB_MAX",
}
