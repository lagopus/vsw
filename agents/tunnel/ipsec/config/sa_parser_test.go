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

package config

import (
	"strings"
	"testing"

	"github.com/lagopus/vsw/agents/tunnel/ipsec/sad"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/stretchr/testify/suite"
)

type testSAParserTestSuite struct {
	suite.Suite
}

func (suite *testSAParserTestSuite) TestParseCbcSha1Hmac() {
	/*
		expectedValue := &sad.SAValue{
			CipherAlgoType: ipsec.CipherAlgoTypeAes128Cbc,
			CipherKey: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			AuthAlgoType: ipsec.AuthAlgoTypeSha1Hmac,
			AuthKey: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
				0x00, 0x11, 0x22, 0x33},
			LocalEPIP: net.IPNet{
				IP:   net.ParseIP("172.16.1.1").To4(),
				Mask: net.CIDRMask(32, 32),
			},
			RemoteEPIP: net.IPNet{
				IP:   net.ParseIP("172.16.1.2").To4(),
				Mask: net.CIDRMask(32, 32),
			},
			EncapType:     2,  // UDP_ENCAP_ESPINUDP
			EncapProtocol: 17, // UDP
			EncapSrcPort:  4500,
			EncapDstPort:  4500,
			Flags:         ipsec.IP4Tunnel,
		}
	*/

	confStr := "out 1 vrf 1 cipher_algo aes-128-cbc " +
		"cipher_key 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff " +
		"auth_algo sha1-hmac auth_key " +
		"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33 " +
		"mode ipv4-tunnel udp 4500 4500 src 172.16.1.1 dst 172.16.1.2"
	mgr := sad.GetMgr(ipsec.DirectionTypeOut)

	err := saParser.Parse(strings.Fields(confStr))
	suite.Empty(err)

	// not check expectedValue == sa value.
	// inStat is internally generated. So do not compare.

	// delete.
	selector := &sad.SASelector{
		VRFIndex: 1,
		SPI:      1,
	}
	_ = mgr.DeleteSA(selector)
}

func (suite *testSAParserTestSuite) TestParseGcm128() {
	/*
		expectedValue := &sad.SAValue{
			AeadAlgoType: ipsec.AeadAlgoTypeAes128Gcm,
			AeadKey: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33},
			LocalEPIP: net.IPNet{
				IP:   net.ParseIP("172.16.1.1").To4(),
				Mask: net.CIDRMask(32, 32),
			},
			RemoteEPIP: net.IPNet{
				IP:   net.ParseIP("172.16.1.2").To4(),
				Mask: net.CIDRMask(32, 32),
			},
			Flags: ipsec.IP4Tunnel,
		}
	*/

	confStr := "out 2 vrf 1 aead_algo aes-128-gcm " +
		"aead_key 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33 " +
		"mode ipv4-tunnel src 172.16.1.1 dst 172.16.1.2"
	mgr := sad.GetMgr(ipsec.DirectionTypeOut)

	err := saParser.Parse(strings.Fields(confStr))
	suite.Empty(err)

	// not check expectedValue == sa value.
	// inStat is internally generated. So do not compare.

	// delete.
	selector := &sad.SASelector{
		VRFIndex: 1,
		SPI:      2,
	}
	_ = mgr.DeleteSA(selector)
}

func (suite *testSAParserTestSuite) TestParse3DESCBC() {
	/*
		expectedValue := &sad.SAValue{
			CipherAlgoType: ipsec.CipherAlgoType3desCbc,
			CipherKey: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
			AuthAlgoType: ipsec.AuthAlgoTypeSha1Hmac,
			AuthKey: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
				0x00, 0x11, 0x22, 0x33},
			LocalEPIP: net.IPNet{
				IP:   net.ParseIP("172.16.1.1").To4(),
				Mask: net.CIDRMask(32, 32),
			},
				RemoteEPIP: net.IPNet{
					IP:   net.ParseIP("172.16.1.2").To4(),
					Mask: net.CIDRMask(32, 32),
				},
			Flags: ipsec.IP4Tunnel,
		}
	*/

	confStr := "out 3 vrf 1 cipher_algo 3des-cbc " +
		"cipher_key 00:11:22:33:44:55:66:77:88:99:" +
		"aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77 " +
		"auth_algo sha1-hmac auth_key " +
		"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33 " +
		"mode ipv4-tunnel udp 4500 4500 src 172.16.1.1 dst 172.16.1.2"
	mgr := sad.GetMgr(ipsec.DirectionTypeOut)

	err := saParser.Parse(strings.Fields(confStr))
	suite.Empty(err)

	// not check expectedValue == sa value.
	// inStat is internally generated. So do not compare.

	// delete.
	selector := &sad.SASelector{
		VRFIndex: 1,
		SPI:      3,
	}
	_ = mgr.DeleteSA(selector)
}

func (suite *testSAParserTestSuite) TestParseErrorBadParam() {
	// Bad param length.
	confStr := "out"
	err := saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")

	// Bad required parameter(out).
	confStr = "hoge 1 cipher_algo"
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "unrecognizable input: hoge")

	// Bad required parameter(SPI).
	confStr = "out hoge cipher_algo"
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"hoge\": invalid syntax")

	// Bad param.
	confStr = "out 1 hoge"
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "unrecognizable input: hoge")

	// not cipher_algo param.
	confStr = "out 1 " +
		"auth_algo sha1-hmac auth_key " +
		"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33 " +
		"mode ipv4-tunnel src 172.16.1.1 dst 172.16.1.2"
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "missing cipher options")

	// not auth_algo param.
	confStr = "out 1 cipher_algo aes-128-cbc " +
		"cipher_key 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff " +
		"mode ipv4-tunnel src 172.16.1.1 dst 172.16.1.2"
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "missing auth options")

	// cipher_algo. auth_algo, aead_algo params.
	confStr = "out 1 vrf 1 aead_algo aes-128-gcm " +
		"aead_key 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33 " +
		"cipher_algo aes-128-cbc " +
		"cipher_key 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff " +
		"auth_algo sha1-hmac auth_key " +
		"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33 " +
		"mode ipv4-tunnel src 172.16.1.1 dst 172.16.1.2"
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "missing aead options")

	// not algo params.
	confStr = "out 1 vrf 1 " +
		"mode ipv4-tunnel src 172.16.1.1 dst 172.16.1.2"
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "missing aead options")

	// not mode param.
	confStr = "out 1 cipher_algo aes-128-cbc " +
		"cipher_key 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff " +
		"auth_algo sha1-hmac auth_key " +
		"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33"
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "missing mode option")
}

func (suite *testSAParserTestSuite) TestParseErrorCipherAlgo() {
	// Bad algo.
	confStr := "out 1 cipher_algo hoge "
	err := saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "unrecognizable input: hoge")

	// Empty value.
	confStr = "out 1 cipher_algo "
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSAParserTestSuite) TestParseErrorCipherKey() {
	// Bad key.
	confStr := "out 1 cipher_algo aes-128-cbc " +
		"cipher_key hoge "
	err := saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "encoding/hex: invalid byte: U+0068 'h'")

	// out of range.
	confStr = "out 1 cipher_algo aes-128-cbc " +
		"cipher_key 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee "
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "unrecognizable input: "+
		"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee")

	// out of range.
	confStr = "out 1 cipher_algo aes-128-cbc " +
		"cipher_key 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00"
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "unrecognizable input: "+
		"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00")

	// Empty value.
	confStr = "out 1 cipher_algo aes-128-cbc " +
		"cipher_key "
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSAParserTestSuite) TestParseErrorAuthAlgo() {
	// Bad algo.
	confStr := "out 1 auth_algo hoge "
	err := saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "unrecognizable input: hoge")

	// Empty value.
	confStr = "out 1 auth_algo "
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSAParserTestSuite) TestParseErrorAuthKey() {
	// Bad key.
	confStr := "out 1 auth_algo sha1-hmac " +
		"auth_key hoge "
	err := saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "encoding/hex: invalid byte: U+0068 'h'")

	// out of range.
	confStr = "out 1 auth_algo sha1-hmac " +
		"auth_key 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22"
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "unrecognizable input: "+
		"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22")

	// out of range.
	confStr = "out 1 auth_algo sha1-hmac " +
		"auth_key 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:00"
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "unrecognizable input: "+
		"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:00")

	// Empty value.
	confStr = "out 1 auth_algo sha1-hmac " +
		"auth_key "
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSAParserTestSuite) TestParseErrorAeadAlgo() {
	// Bad algo.
	confStr := "out 1 aead_algo hoge "
	err := saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "unrecognizable input: hoge")

	// Empty value.
	confStr = "out 1 aead_algo "
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSAParserTestSuite) TestParseErrorAeadKey() {
	// Bad key.
	confStr := "out 1 aead_algo aes-128-gcm " +
		"aead_key hoge "
	err := saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "encoding/hex: invalid byte: U+0068 'h'")

	// out of range.
	confStr = "out 1 aead_algo aes-128-gcm " +
		"aead_key 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44"
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "unrecognizable input: "+
		"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44")

	// out of range.
	confStr = "out 1 aead_algo aes-128-gcm " +
		"aead_key 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22"
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "unrecognizable input: "+
		"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22")

	// Empty value.
	confStr = "out 1 aead_algo aes-128-gcm " +
		"aead_key "
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSAParserTestSuite) TestParseErrorMode() {
	// Bad mode.
	confStr := "out 1 mode hoge"
	err := saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "unrecognizable input: hoge")

	// Empty value.
	confStr = "out 1 mode "
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSAParserTestSuite) TestParseErrorSrcIP() {
	// Bad IP.
	confStr := "out 1 mode ipv4-tunnel src 172.16.1.1000"
	err := saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Invalid IP address: 172.16.1.1000")

	// Empty value.
	confStr = "out 1 mode ipv4-tunnel src "
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSAParserTestSuite) TestParseErrorDstIP() {
	// Bad IP.
	confStr := "out 1 mode ipv4-tunnel dst 172.16.2.1000"
	err := saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Invalid IP address: 172.16.2.1000")

	// Empty value.
	confStr = "out 1 mode ipv4-tunnel dst "
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSAParserTestSuite) TestParseErrorVRF() {
	// Bad vrf.
	confStr := "out 1 vrf hoge"
	err := saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"hoge\": invalid syntax")

	// Out of range.
	confStr = "out 1 vrf 256"
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"256\": value out of range")

	// Empty value.
	confStr = "out 1 vrf "
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testSAParserTestSuite) TestParseErrorUDP() {
	// Bad UDP port.
	confStr := "out 1 udp hoge"
	err := saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"hoge\": invalid syntax")

	// Out of range.
	confStr = "out 1 udp 65536"
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"65536\": value out of range")

	// Empty value.
	confStr = "out 1 udp "
	err = saParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func TestSAParserTestSuites(t *testing.T) {
	suite.Run(t, new(testSAParserTestSuite))
}
