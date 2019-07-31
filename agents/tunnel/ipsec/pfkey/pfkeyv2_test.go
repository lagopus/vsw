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

package pfkey

import (
	"bytes"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/suite"
)

type PFKeyv2TestSuit struct {
	suite.Suite
}

func Test_PFKeyv2TestSuite(t *testing.T) {
	suite.Run(t, new(PFKeyv2TestSuit))
}

/*
00000000: 02 03 00 03 22 00 00 00 55 01 00 00 37 00 00 00
00000010: 02 00 01 00 c8 ca c0 29 20 01 03 0c 00 00 00 00
00000020: 04 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00
00000030: 10 0e 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000040: 04 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00
00000050: c5 0b 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000060: 04 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00
00000070: 1d 7d 80 58 00 00 00 00 00 00 00 00 00 00 00 00
00000080: 03 00 05 00 00 20 00 00 02 00 00 00 ac 10 01 0c
00000090: 00 00 00 00 00 00 00 00 03 00 06 00 00 20 00 00
000000a0: 02 00 00 00 ac 10 01 0d 00 00 00 00 00 00 00 00
000000b0: 03 00 07 00 ff 00 00 00 02 00 00 00 00 00 00 00
000000c0: 00 00 00 00 00 00 00 00 04 00 08 00 a0 00 00 00
000000d0: 82 45 2e b8 73 29 e9 11 11 f8 2c ba 26 86 56 f4
000000e0: e1 7a f6 5b 00 00 00 00 03 00 09 00 80 00 00 00
000000f0: 34 f4 6b f2 07 2d 86 b8 f6 74 e8 78 57 d2 0e e6
00000100: 02 00 13 00 02 00 00 00 00 00 00 00 01 00 00 00
sadb_msg{ version=2 type=3 errno=0 satype=3
  len=34 reserved=0 seq=341 pid=55
sadb_ext{ len=2 type=1 }
sadb_sa{ spi=3368730665 replay=32 state=1
  auth=3 encrypt=12 flags=0x00000000 }
sadb_ext{ len=4 type=3 }
sadb_lifetime{ alloc=0, bytes=0
  addtime=3600, usetime=0 }
sadb_ext{ len=4 type=4 }
sadb_lifetime{ alloc=0, bytes=0
  addtime=3013, usetime=0 }
sadb_ext{ len=4 type=2 }
sadb_lifetime{ alloc=0, bytes=0
  addtime=1484815645, usetime=0 }
sadb_ext{ len=3 type=5 }
sadb_address{ proto=0 prefixlen=32 reserved=0x0000 }
sockaddr{ len=16 family=2 port=0
 ac10010c  }
sadb_ext{ len=3 type=6 }
sadb_address{ proto=0 prefixlen=32 reserved=0x0000 }
sockaddr{ len=16 family=2 port=0
 ac10010d  }
sadb_ext{ len=3 type=7 }
sadb_address{ proto=255 prefixlen=0 reserved=0x0000 }
sockaddr{ len=16 family=2 port=0
 00000000  }
sadb_ext{ len=4 type=8 }
sadb_key{ bits=160 reserved=0
  key= 00000000 01000000 00000000 00000000 00000000 }
sadb_ext{ len=3 type=9 }
sadb_key{ bits=128 reserved=0
  key= 00000000 00000000 00000000 00000000 }
sadb_ext{ len=2 type=19 }
sadb_x_sa2{ mode=2 reqid=1
  reserved1=0 reserved2=0 sequence=0 }
*/

func (s *PFKeyv2TestSuit) TestDeserializeSadbMsg() {
	b := []byte{0x02, 0x03, 0x00, 0x03, 0x22, 0x00, 0x00, 0x00, 0x55, 0x01, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00}
	r := bytes.NewReader(b)
	smsg := SadbMsg{}
	err := smsg.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := SadbMsg{2, 3, 0, 3, 34, 0, 341, 55}
	s.Assert().Equal(smsgOK, smsg)
}

func (s *PFKeyv2TestSuit) TestSerializeSadbMsg() {
	w := bytes.Buffer{}
	smsg := SadbMsg{2, 3, 0, 3, 34, 0, 341, 55}
	err := smsg.Serialize(&w)
	s.Assert().NoError(err)

	b := []byte{0x02, 0x03, 0x00, 0x03, 0x22, 0x00, 0x00, 0x00, 0x55, 0x01, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00}
	s.Assert().Equal(b, w.Bytes())
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbMsgWithError() {
	b := []byte{0x02, 0x03, 0x00, 0x03}
	r := bytes.NewReader(b)
	smsg := SadbMsg{}
	err := smsg.Deserialize(r)
	s.Assert().Error(err)
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbExt() {
	b := []byte{0x02, 0x00, 0x01, 0x00}
	r := bytes.NewReader(b)
	smsg := SadbExt{}
	err := smsg.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := SadbExt{2, 1}
	s.Assert().Equal(smsgOK, smsg)
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbExtWithError() {
	b := []byte{0x02, 0x00}
	r := bytes.NewReader(b)
	smsg := SadbExt{}
	err := smsg.Deserialize(r)
	s.Assert().Error(err)
}

func (s *PFKeyv2TestSuit) TestSerializeSadbExt() {
	w := bytes.Buffer{}
	smsg := SadbExt{2, 1}
	err := smsg.Serialize(&w)
	s.Assert().NoError(err)

	b := []byte{0x02, 0x00, 0x01, 0x00}
	s.Assert().Equal(b, w.Bytes())
}

func (s *PFKeyv2TestSuit) TestSerializeSadbExtWithError() {
	w := bytes.Buffer{}
	smsg := SadbExt{2, 1}
	err := smsg.Serialize(&w)
	s.Assert().NoError(err)

	b := []byte{0x02, 0x00, 0x01, 0x10}
	s.Assert().NotEqual(b, w.Bytes())
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbSa() {
	b := []byte{0xc8, 0xca, 0xc0, 0x29, 0x20, 0x01, 0x03, 0x0c, 0x00, 0x00, 0x00, 0x00}
	r := bytes.NewReader(b)
	smsg := SadbSa{}
	err := smsg.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := SadbSa{3368730665, 32, 1, 3, 12, 0}
	s.Assert().Equal(smsgOK, smsg)
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbSaWithError() {
	b := []byte{0x02, 0x00}
	r := bytes.NewReader(b)
	smsg := SadbSa{}
	err := smsg.Deserialize(r)
	s.Assert().Error(err)
}

func (s *PFKeyv2TestSuit) TestSerializeSadbSa() {
	w := bytes.Buffer{}
	smsg := SadbSa{3368730665, 32, 1, 3, 12, 0}
	//b := []byte{SadbSaMsgLen / 8, 00, SADB_EXT_SA, 00, 0xc8, 0xca, 0xc0, 0x29, 0x20, 0x01, 0x03, 0x0c, 0x00, 0x00, 0x00, 0x00}
	b := []byte{0xc8, 0xca, 0xc0, 0x29, 0x20, 0x01, 0x03, 0x0c, 0x00, 0x00, 0x00, 0x00}
	err := smsg.Serialize(&w)
	s.Assert().NoError(err)
	s.Assert().Equal(b, w.Bytes())
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbLifetime() {
	b := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	r := bytes.NewReader(b)
	smsg := SadbLifetime{}
	err := smsg.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := SadbLifetime{0, 0, 3600, 0}
	s.Assert().Equal(smsgOK, smsg)
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbLifetimeWithError() {
	b := []byte{0x02, 0x00}
	r := bytes.NewReader(b)
	smsg := SadbLifetime{}
	err := smsg.Deserialize(r)
	s.Assert().Error(err)
}

func (s *PFKeyv2TestSuit) TestSerializeSadbLifetime() {
	w := bytes.Buffer{}
	smsg := SadbLifetime{0, 0, 3600, 0}
	err := smsg.Serialize(&w)
	s.Assert().NoError(err)

	b := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	s.Assert().Equal(b, w.Bytes())
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbAddress() {
	b := []byte{0x00, 0x20, 0x00, 0x00}
	r := bytes.NewReader(b)
	smsg := &SadbAddress{}
	err := smsg.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := SadbAddress{0, 32, 0}
	s.Assert().Equal(smsgOK, *smsg)
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbAddressWithError() {
	b := []byte{0x02, 0x00}
	r := bytes.NewReader(b)
	smsg := &SadbAddress{}
	err := smsg.Deserialize(r)
	s.Assert().Error(err)
}

func (s *PFKeyv2TestSuit) TestSerializeSadbAddress() {
	smsg := SadbAddress{0, 32, 0}
	buf := bytes.Buffer{}
	err := smsg.Serialize(&buf)
	s.Assert().NoError(err)

	b := []byte{0x00, 0x20, 0x00, 0x00}
	s.Assert().Equal(b, buf.Bytes())
}

func (s *PFKeyv2TestSuit) TestDeserializeSockaddrInet4() {
	b := []byte{
		0x02, 0x00, 0x00, 0x50, 0xac, 0x10, 0x01, 0x0c,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	r := bytes.NewReader(b)
	smsg := &sockaddrInet4{}
	err := smsg.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := sockaddrInet4{syscall.SockaddrInet4{Port: 80, Addr: [4]byte{0xac, 0x10, 0x01, 0x0c}}}
	s.Assert().Equal(smsgOK, *smsg)
}

func (s *PFKeyv2TestSuit) TestSerializeSockaddrInet4() {
	smsg := sockaddrInet4{syscall.SockaddrInet4{Port: 80, Addr: [4]byte{0xac, 0x10, 0x01, 0x0c}}}
	buf := bytes.Buffer{}
	err := smsg.Serialize(&buf)
	s.Assert().NoError(err)

	b := []byte{
		0x02, 0x00, 0x00, 0x50, 0xac, 0x10, 0x01, 0x0c,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	s.Assert().Equal(b, buf.Bytes())
}

func (s *PFKeyv2TestSuit) TestDeserializeSockaddrInet6() {
	b := []byte{
		0x0a, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	}
	r := bytes.NewReader(b)
	smsg := &sockaddrInet6{}
	err := smsg.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := sockaddrInet6{syscall.SockaddrInet6{Port: 80,
		Addr: [16]byte{
			0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		}}}
	s.Assert().Equal(smsgOK, *smsg)
}

func (s *PFKeyv2TestSuit) TestSerializeSockaddrInet6() {
	smsg := sockaddrInet6{syscall.SockaddrInet6{Port: 80,
		Addr: [16]byte{
			0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		}}}
	buf := bytes.Buffer{}
	err := smsg.Serialize(&buf)
	s.Assert().NoError(err)

	b := []byte{
		0x0a, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	}
	s.Assert().Equal(b, buf.Bytes())
}

func (s *PFKeyv2TestSuit) TestDeserializeAddrPair() {
	b := []byte{
		0x00, 0x20, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x50, 0xac, 0x10, 0x01, 0x0c,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	r := bytes.NewReader(b)
	smsg := &AddrPair{SadbAddrLen: 3}
	err := smsg.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := AddrPair{
		Addr:        SadbAddress{0, 32, 0},
		SockAddr:    &sockaddrInet4{syscall.SockaddrInet4{Port: 80, Addr: [4]byte{0xac, 0x10, 0x01, 0x0c}}},
		SadbAddrLen: 3,
	}
	s.Assert().Equal(smsgOK, *smsg)
}

func (s *PFKeyv2TestSuit) TestSerializeAddrPair() {
	smsg := AddrPair{
		Addr:        SadbAddress{0, 32, 0},
		SockAddr:    &sockaddrInet4{syscall.SockaddrInet4{Port: 80, Addr: [4]byte{0xac, 0x10, 0x01, 0x0c}}},
		SadbAddrLen: 3,
	}
	buf := bytes.Buffer{}
	err := smsg.Serialize(&buf)
	s.Assert().NoError(err)

	b := []byte{
		0x00, 0x20, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x50, 0xac, 0x10, 0x01, 0x0c,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	s.Assert().Equal(b, buf.Bytes())
}

func (s *PFKeyv2TestSuit) TestAddrPairToIPNet4() {
	smsg := AddrPair{
		Addr:        SadbAddress{0, 24, 0},
		SockAddr:    &sockaddrInet4{syscall.SockaddrInet4{Port: 80, Addr: [4]byte{0xac, 0x10, 0x01, 0x0c}}},
		SadbAddrLen: 3,
	}
	ipnetOK := net.IPNet{
		IP:   net.IPv4(0xac, 0x10, 0x01, 0x0c),
		Mask: net.CIDRMask(24, 32),
	}
	s.Assert().Equal(ipnetOK, *smsg.ToIPNet())
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbKey() {
	b := []byte{0xa0, 0x00, 0x00, 0x00}
	r := bytes.NewReader(b)
	smsg := &SadbKey{}
	err := smsg.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := SadbKey{160, 0}
	s.Assert().Equal(smsgOK, *smsg)
}

func (s *PFKeyv2TestSuit) TestSerializeSadbKey() {
	buf := bytes.Buffer{}
	smsg := SadbKey{160, 0}
	err := smsg.Serialize(&buf)
	s.Assert().NoError(err)

	b := []byte{0xa0, 0x00, 0x00, 0x00}
	s.Assert().Equal(b, buf.Bytes())
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbKeyWithError() {
	b := []byte{0x02, 0x00}
	r := bytes.NewReader(b)
	smsg := &SadbKey{}
	err := smsg.Deserialize(r)
	s.Assert().Error(err)
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbKeyWithKey() {
	b := []byte{
		0xa0, 0x00, 0x00, 0x00,
		0x82, 0x45, 0x2e, 0xb8, 0x73, 0x29, 0xe9, 0x11,
		0x11, 0xf8, 0x2c, 0xba, 0x26, 0x86, 0x56, 0xf4,
		0xe1, 0x7a, 0xf6, 0x5b, 0x00, 0x00, 0x00, 0x00,
	}
	r := bytes.NewReader(b)
	sext := KeyPair{SadbKeyLen: 4}
	err := sext.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := SadbKey{160, 0}
	s.Assert().Equal(smsgOK, sext.SadbKey)
	keyOK := &[]byte{
		0x82, 0x45, 0x2e, 0xb8, 0x73, 0x29, 0xe9, 0x11,
		0x11, 0xf8, 0x2c, 0xba, 0x26, 0x86, 0x56, 0xf4,
		0xe1, 0x7a, 0xf6, 0x5b, 0x00, 0x00, 0x00, 0x00,
	}
	s.Assert().Equal(keyOK, sext.Key)
}

func (s *PFKeyv2TestSuit) TestSerializeSadbKeyWithKey() {
	smsg := KeyPair{
		SadbKey: SadbKey{160, 0},
		Key: &[]byte{
			0x82, 0x45, 0x2e, 0xb8, 0x73, 0x29, 0xe9, 0x11,
			0x11, 0xf8, 0x2c, 0xba, 0x26, 0x86, 0x56, 0xf4,
			0xe1, 0x7a, 0xf6, 0x5b, 0x00, 0x00, 0x00, 0x00,
		},
	}
	buf := bytes.Buffer{}
	err := smsg.Serialize(&buf)
	s.Assert().NoError(err)

	b := []byte{
		0xa0, 0x00, 0x00, 0x00,
		0x82, 0x45, 0x2e, 0xb8, 0x73, 0x29, 0xe9, 0x11,
		0x11, 0xf8, 0x2c, 0xba, 0x26, 0x86, 0x56, 0xf4,
		0xe1, 0x7a, 0xf6, 0x5b, 0x00, 0x00, 0x00, 0x00,
	}
	s.Assert().Equal(b, buf.Bytes())
}

func (s *PFKeyv2TestSuit) TestSerializeSupportedAlgPair() {
	smsg := SupportedAlgPair{
		Sup: SadbSupported{0},
		Alg: []SadbAlg{
			{0, 1, 2, 3, 4},
			{5, 6, 7, 8, 9},
		},
	}
	buf := bytes.Buffer{}
	err := smsg.Serialize(&buf)
	s.Assert().NoError(err)

	b := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00,
		0x05, 0x06, 0x07, 0x00, 0x08, 0x00, 0x09, 0x00,
	}
	s.Assert().Equal(b, buf.Bytes())
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbXSa2() {
	b := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	r := bytes.NewReader(b)
	smsg := SadbXSa2{}
	err := smsg.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := SadbXSa2{2, 0, 0, 0, 1}
	s.Assert().Equal(smsgOK, smsg)
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbXSa2WithError() {
	b := []byte{0x02, 0x00}
	smsg := SadbXSa2{}
	r := bytes.NewReader(b)
	err := smsg.Deserialize(r)
	s.Assert().Error(err)
}

func (s *PFKeyv2TestSuit) TestSerializeSadbXSa2() {
	smsg := SadbXSa2{2, 0, 0, 0, 1}
	buf := bytes.Buffer{}
	err := smsg.Serialize(&buf)
	s.Assert().NoError(err)

	b := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	s.Assert().Equal(b, buf.Bytes())
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbSPIRange() {
	b := []byte{0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0xcf, 0x00, 0x00, 0x00, 0x00}
	r := bytes.NewReader(b)
	smsg := &SadbSPIRange{}
	err := smsg.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := SadbSPIRange{0xc0000000, 0xcfffffff, 0}
	s.Assert().Equal(smsgOK, *smsg)
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbSadbSPIRangeWithError() {
	b := []byte{0x02, 0x00}
	r := bytes.NewReader(b)
	smsg := &SadbSPIRange{}
	err := smsg.Deserialize(r)
	s.Assert().Error(err)
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbXPolicy() {
	b := []byte{
		0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xea, 0x05, 0x00,
	}
	r := bytes.NewReader(b)
	smsg := SadbXPolicy{}
	err := smsg.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := SadbXPolicy{0, 2, 0, 0, 387712}
	s.Assert().Equal(smsgOK, smsg)
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbXPolicyWithError() {
	b := []byte{0x02, 0x00}
	smsg := SadbXPolicy{}
	r := bytes.NewReader(b)
	err := smsg.Deserialize(r)
	s.Assert().Error(err)
}

func (s *PFKeyv2TestSuit) TestSerializeSadbXPolicy() {
	smsg := SadbXPolicy{0, 2, 0, 0, 387712}
	buf := bytes.Buffer{}
	err := smsg.Serialize(&buf)
	s.Assert().NoError(err)

	b := []byte{
		0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xea, 0x05, 0x00,
	}
	s.Assert().Equal(b, buf.Bytes())
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbXIpsecrequest() {
	b := []byte{
		0x30, 0x00, 0x32, 0x00, 0x02, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	r := bytes.NewReader(b)
	smsg := SadbXIpsecrequest{}
	err := smsg.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := SadbXIpsecrequest{48, 50, 2, 3, 0, 1, 0}
	s.Assert().Equal(smsgOK, smsg)
}

func (s *PFKeyv2TestSuit) TestSerializeSadbXIpsecrequest() {
	smsg := SadbXIpsecrequest{48, 50, 2, 3, 0, 1, 0}
	buf := bytes.Buffer{}
	err := smsg.Serialize(&buf)
	s.Assert().NoError(err)

	b := []byte{
		0x30, 0x00, 0x32, 0x00, 0x02, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	s.Assert().Equal(b, buf.Bytes())
}

func (s *PFKeyv2TestSuit) TestDeserializePolicy() {
	b := []byte{
		0x02, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
		0x30, 0x00, 0x32, 0x00, 0x02, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0xac, 0x10, 0x01, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0xac, 0x10, 0x01, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	r := bytes.NewReader(b)
	smsg := Policy{SadbXPolicyLen: 6}
	err := smsg.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := Policy{
		Policy:         SadbXPolicy{2, 3, 0, 1, 2},
		IpsecRequest:   SadbXIpsecrequest{48, 50, 2, 3, 0, 1, 0},
		TunnelSrcAddr:  &sockaddrInet4{syscall.SockaddrInet4{Addr: [4]byte{0xac, 0x10, 0x01, 0x0c}}},
		TunnelDstAddr:  &sockaddrInet4{syscall.SockaddrInet4{Addr: [4]byte{0xac, 0x10, 0x01, 0x0d}}},
		SadbXPolicyLen: 6,
	}
	s.Assert().Equal(smsgOK, smsg)
}

func (s *PFKeyv2TestSuit) TestSerializePolicy() {
	smsg := Policy{
		Policy:         SadbXPolicy{2, 3, 0, 1, 2},
		IpsecRequest:   SadbXIpsecrequest{48, 50, 2, 3, 0, 1, 0},
		TunnelSrcAddr:  &sockaddrInet4{syscall.SockaddrInet4{Addr: [4]byte{0xac, 0x10, 0x01, 0x0c}}},
		TunnelDstAddr:  &sockaddrInet4{syscall.SockaddrInet4{Addr: [4]byte{0xac, 0x10, 0x01, 0x0d}}},
		SadbXPolicyLen: 6,
	}
	buf := bytes.Buffer{}
	err := smsg.Serialize(&buf)
	s.Assert().NoError(err)

	b := []byte{
		0x02, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
		0x30, 0x00, 0x32, 0x00, 0x02, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0xac, 0x10, 0x01, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0xac, 0x10, 0x01, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	s.Assert().Equal(b, buf.Bytes())
}

func (s *PFKeyv2TestSuit) TestSerializeSadbMsgReply() {
	w := bytes.Buffer{}
	sadbMsg := SadbMsg{2, 3, 1, 3, 0, 0, 341, 55}
	smsg := SadbMsgTransport{
		SadbMsg: &sadbMsg,
	}
	err := smsg.Serialize(&w)
	s.Assert().NoError(err)

	b := []byte{0x02, 0x03, 0x01, 0x03, 0x02, 0x00, 0x00, 0x00, 0x55, 0x01, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00}
	s.Assert().Equal(b, w.Bytes())
}

func (s *PFKeyv2TestSuit) TestSerializeSadbMsgReplySadbGetSPIMsg() {
	w := bytes.Buffer{}
	sadbMsg := SadbMsg{2, 3, 1, 3, 0, 0, 341, 55}
	sa := SadbSa{SadbSaSpi: 10}
	src := AddrPair{
		Addr:        SadbAddress{0, 32, 0},
		SockAddr:    &sockaddrInet4{syscall.SockaddrInet4{Port: 80, Addr: [4]byte{0xac, 0x10, 0x01, 0x0c}}},
		SadbAddrLen: 3,
	}
	dst := AddrPair{
		Addr:        SadbAddress{0, 32, 0},
		SockAddr:    &sockaddrInet4{syscall.SockaddrInet4{Port: 80, Addr: [4]byte{0xac, 0x10, 0x01, 0x0d}}},
		SadbAddrLen: 3,
	}
	smsg := SadbMsgTransport{
		SadbMsg: &sadbMsg,
		Serializer: []Serializer{
			&SadbExtTransport{
				&SadbExt{SadbExtType: SADB_EXT_SA},
				&sa,
			},
			&SadbExtTransport{
				&SadbExt{SadbExtType: SADB_EXT_ADDRESS_SRC},
				&src,
			},
			&SadbExtTransport{
				&SadbExt{SadbExtType: SADB_EXT_ADDRESS_DST},
				&dst,
			},
		},
	}
	err := smsg.Serialize(&w)
	s.Assert().NoError(err)

	b := []byte{
		0x02, 0x03, 0x01, 0x03, 0x0a, 0x00, 0x00, 0x00, 0x55, 0x01, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 0x00, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00, 0x02, 0x00, 0x00, 0x50, 0xac, 0x10, 0x01, 0x0c,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x06, 0x00, 0x00, 0x20, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x50, 0xac, 0x10, 0x01, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	s.Assert().Equal(b, w.Bytes())
}
func (s *PFKeyv2TestSuit) TestToIPNetTosockaddr() {
	addr := &sockaddrInet4{syscall.SockaddrInet4{Port: 00, Addr: [4]byte{0xac, 0x10, 0x01, 0x0c}}}
	ipnet := addr.ToIPNet(0)
	sa := ToSockaddr(ipnet)
	s.Assert().Equal(addr, sa)
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbXNatTType() {
	b := []byte{
		0x02, 0x00, 0x00, 0x00,
	}
	r := bytes.NewReader(b)
	smsg := SadbXNatTType{}
	err := smsg.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := SadbXNatTType{2, [3]uint8{0, 0, 0}}
	s.Assert().Equal(smsgOK, smsg)
}

func (s *PFKeyv2TestSuit) TestSerializeSadbXNatTType() {
	smsg := SadbXNatTType{2, [3]uint8{0, 0, 0}}
	buf := bytes.Buffer{}
	err := smsg.Serialize(&buf)
	s.Assert().NoError(err)

	b := []byte{
		0x02, 0x00, 0x00, 0x00,
	}
	s.Assert().Equal(b, buf.Bytes())
}

func (s *PFKeyv2TestSuit) TestDeserializeSadbXNatTPort() {
	b := []byte{
		0x11, 0x94, 0x00, 0x00,
	}
	r := bytes.NewReader(b)
	smsg := SadbXNatTPort{}
	err := smsg.Deserialize(r)
	s.Assert().NoError(err)

	smsgOK := SadbXNatTPort{4500, 0}
	s.Assert().Equal(smsgOK, smsg)
}

func (s *PFKeyv2TestSuit) TestSerializeSadbXNatTPort() {
	smsg := SadbXNatTPort{4500, 0}
	buf := bytes.Buffer{}
	err := smsg.Serialize(&buf)
	s.Assert().NoError(err)

	b := []byte{
		0x11, 0x94, 0x00, 0x00,
	}
	s.Assert().Equal(b, buf.Bytes())
}
