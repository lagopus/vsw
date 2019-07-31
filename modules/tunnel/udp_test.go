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

// +build test

package tunnel

import (
	"encoding/binary"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/suite"
)

type testUDPTestSuite struct {
	suite.Suite
}

var udpTestSuite *testUDPTestSuite

func (suite *testUDPTestSuite) TestEncapUDP() {
	mbuf := allocMbuf()
	suite.NotEmpty(mbuf)
	defer mbuf.Free()

	// payload.
	payload := []byte{0x01, 0x2, 0x03, 0x04}
	mbuf.SetData(payload)

	// data.
	expectedData := []byte{
		0x00, 0x64, // src_port
		0x00, 0xc8, // dst_port
		0x00, 0x0c, // dgram_len
		0x00, 0x00, // dgram_cksum
	}
	expectedData = append(expectedData, payload...)

	// encapUDP: OK.
	_, err := encapUDP(mbuf, 100, 200)
	suite.Empty(err)
	mdata := mbuf.Data()
	suite.Equal(expectedData, mdata)
}

func (suite *testUDPTestSuite) TestEncapUDPErr() {
	// encapUDP: NG, mbuf is nil
	_, err := encapUDP(nil, 100, 200)
	suite.NotEmpty(err)
}

func (suite *testUDPTestSuite) TestDecapUDP() {
	mbuf := allocMbuf()
	suite.NotEmpty(mbuf)
	defer mbuf.Free()

	// data.
	l3 := []byte{
		0x45, 0x00, 0x00, 0x20,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x7c, 0xca,
		0x7f, 0x00, 0x00, 0x01, // src IP
		0x7f, 0x00, 0x00, 0x01, // dst IP
	}

	expectedSrcPort := []byte{0x00, 0x64}
	expectedDstPort := []byte{0x00, 0xc8}
	expectedDgramLen := []byte{0x00, 0x0c}
	expectedDgramCksum := []byte{0xfc, 0xa1}
	udp := append(expectedSrcPort, expectedDstPort...)
	udp = append(udp, expectedDgramLen...)
	udp = append(udp, expectedDgramCksum...)

	payload := []byte{0x01, 0x2, 0x03, 0x04}

	data := append(l3, udp...)
	data = append(data, payload...)
	mbuf.SetData(data[len(l3):]) /* UDP/payload */

	etherType := uint16(syscall.ETH_P_IP)
	etherType = binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&etherType)))[:])

	// decapUDP: OK.
	outUDP, err := decapUDP(mbuf, &data[0], etherType, true)
	suite.Empty(err)
	suite.Equal(binary.LittleEndian.Uint16(expectedSrcPort), outUDP.srcPort())
	suite.Equal(binary.LittleEndian.Uint16(expectedDstPort), outUDP.dstPort())
	suite.Equal(binary.LittleEndian.Uint16(expectedDgramLen), outUDP.dgramLen())
	suite.Equal(binary.LittleEndian.Uint16(expectedDgramCksum), outUDP.dgramCksum())
}

func (suite *testUDPTestSuite) TestDecapUDPErr() {
	mbuf := allocMbuf()
	suite.NotEmpty(mbuf)
	defer mbuf.Free()

	// data.
	data := []byte{0x00}

	etherType := uint16(syscall.ETH_P_IP)
	etherType = binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&etherType)))[:])

	// decapUDP: NG, Bad checksum.
	_, err := decapUDP(mbuf, &data[0], etherType, true)
	suite.NotEmpty(err)

	// decapUDP: NG, mbuf is nil.
	_, err = decapUDP(nil, &data[0], etherType, true)
	suite.NotEmpty(err)

	// decapUDP: NG, l3 is nil.
	_, err = decapUDP(mbuf, nil, etherType, true)
	suite.NotEmpty(err)
}

func (suite *testUDPTestSuite) TestEncapUDPInsertChecksum() {
	mbuf := allocMbuf()
	suite.NotEmpty(mbuf)
	defer mbuf.Free()

	// data.
	l3 := []byte{
		0x45, 0x00, 0x00, 0x20,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0x7f, 0x00, 0x00, 0x01, // src IP
		0x7f, 0x00, 0x00, 0x01, // dst IP
	}

	udp := []byte{
		0x00, 0x64, // src_port
		0x00, 0xc8, // dst_port
		0x00, 0x0c, // dgram_len
	}
	udpChecksum := []byte{
		0x00, 0x00, // dgram_cksum
	}
	expectedChecksum := []byte{
		0xfc, 0xa1, // dgram_cksum
	}

	payload := []byte{0x01, 0x2, 0x03, 0x04}

	data := append(l3, udp...)
	data = append(data, udpChecksum...)
	data = append(data, payload...)
	mbuf.SetData(data)

	expectedData := append(l3, udp...)
	expectedData = append(expectedData, expectedChecksum...)
	expectedData = append(expectedData, payload...)

	etherType := uint16(syscall.ETH_P_IP)
	etherType = binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&etherType)))[:])

	// insertChecksum OK.
	err := insertChecksum(&data[len(l3)], &data[0], etherType)
	suite.Empty(err)
	suite.Equal(expectedData, data)
}

func (suite *testUDPTestSuite) TestEncapUDPInsertChecksumErr() {
	// data.
	data := []byte{0x00}

	etherType := uint16(syscall.ETH_P_IP)
	etherType = binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&etherType)))[:])

	// insertChecksum NG, udp is nil.
	err := insertChecksum(nil, &data[0], etherType)
	suite.NotEmpty(err)

	// insertChecksum NG, l3 is nil.
	err = insertChecksum(&data[0], nil, etherType)
	suite.NotEmpty(err)
}

func (suite *testUDPTestSuite) TestGenSRCPort() {
	// data.
	ether1 := []byte{
		0x52, 0x54, 0x00, 0x00, 0x00, 0x01, // dst mac.
		0x52, 0x54, 0x00, 0x00, 0x00, 0x02, // src mac.
		0x08, 0x00, // proto (IPv4)
	}
	ether2 := []byte{
		0x52, 0x54, 0x00, 0x00, 0x00, 0xff, // dst mac.
		0x52, 0x54, 0x00, 0x00, 0x00, 0xff, // src mac.
		0x08, 0x00, // proto (IPv4)
	}
	l31 := []byte{
		0x45, 0x00, 0x00, 0x20,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x7c, 0xca,
		0x7f, 0x00, 0x00, 0x01, // src IP
		0x7f, 0x00, 0x00, 0x01, // dst IP
	}
	l32 := []byte{
		0x45, 0x00, 0x00, 0x20,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x7c, 0xca,
		0x7f, 0x00, 0x00, 0x02, // src IP
		0x7f, 0x00, 0x00, 0x02, // dst IP
	}
	data := append(ether1, l31...)
	dataSameEther := append(ether1, l32...)
	dataNotSameEther := append(ether2, l31...)

	datas := map[string][]byte{
		"nomal":          data,
		"same_ether":     dataSameEther,
		"not_same_ether": dataNotSameEther,
	}
	ports := map[string]uint16{}
	min := uint16(1000)
	max := uint16(5000)

	for k, data := range datas {
		port := genSRCPort(&data[0], min, max)
		// min <= port <= max.
		suite.True(min <= port)
		suite.True(port <= max)
		ports[k] = port
	}
	// nomal, same ether.
	suite.Equal(ports["nomal"], ports["same_ether"])
	// nomal, not same ether.
	suite.NotEqual(ports["nomal"], ports["not_same_ether"])
}

func TestUDPTestSuites(t *testing.T) {
	udpTestSuite = new(testUDPTestSuite)
	suite.Run(t, udpTestSuite)
}
