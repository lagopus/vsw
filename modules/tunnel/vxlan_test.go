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
	"testing"

	"github.com/stretchr/testify/suite"
)

type testVXLANTestSuite struct {
	suite.Suite
}

var vxlanTestSuite *testVXLANTestSuite

func (suite *testVXLANTestSuite) TestEncapVXLAN() {
	mbuf := allocMbuf()
	suite.NotEmpty(mbuf)
	defer mbuf.Free()

	// payload.
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	mbuf.SetData(payload)

	// data.
	expectedVXLAN := []byte{
		0x08, 0x00, 0x00, 0x00, // flags(I = 1)
		0x00, 0x00, 0x01, 0x00, // VNI = 1
	}
	expectedData := append(expectedVXLAN, payload...)

	// encapVXLAN: OK.
	_, err := encapVXLAN(mbuf, 1)
	suite.Empty(err)
	mdata := mbuf.Data()
	suite.Equal(expectedData, mdata)
}

func (suite *testVXLANTestSuite) TestEncapVXLANErr() {
	// encapVXLAN: NG, mbuf is nil.
	_, err := encapVXLAN(nil, 1)
	suite.NotEmpty(err)
}

func (suite *testVXLANTestSuite) TestDecapVXLAN() {
	mbuf := allocMbuf()
	suite.NotEmpty(mbuf)
	defer mbuf.Free()

	// payload.
	payload := []byte{0x01, 0x02, 0x03, 0x04}

	// data.
	expectedFlags := []byte{
		0x08, 0x00, 0x00, 0x02, // flags(I = 1), Ignore R(0x2)
	}
	expectedVNI := []byte{
		0x00, 0x00, 0x01, 0x02, // VNI = 1, Ignore R(0x2)
	}
	data := append(expectedFlags, expectedVNI...) //VXLAN
	data = append(data, payload...)
	mbuf.SetData(data)

	expectedData := payload

	// decapVXLAN: OK.
	outVXLAN, err := decapVXLAN(mbuf, 1)
	suite.Empty(err)
	mdata := mbuf.Data()
	suite.Equal(expectedData, mdata)
	suite.Equal(binary.LittleEndian.Uint32(expectedFlags), outVXLAN.flags())
	suite.Equal(binary.LittleEndian.Uint32(expectedVNI), outVXLAN.vni())
}

func (suite *testVXLANTestSuite) TestDecapVXLANErr() {
	mbuf := allocMbuf()
	suite.NotEmpty(mbuf)
	defer mbuf.Free()

	// decapVXLAN: NG, mbuf is nil..
	_, err := decapVXLAN(nil, 1)
	suite.NotEmpty(err)

	// decapVXLAN: NG, Bad I flag.
	data := []byte{
		0x00, 0x00, 0x00, 0x00, // flags(Bad I != 0)
		0x00, 0x00, 0x01, 0x00, // VNI = 1
		0x01, 0x02, 0x03, 0x04, // payload
	}
	mbuf.SetData(data)

	_, err = decapVXLAN(mbuf, 1)
	suite.NotEmpty(err)

	// decapVXLAN: NG, Bad VNI.
	data = []byte{
		0x08, 0x00, 0x00, 0x00, // flags(I = 1)
		0x00, 0x00, 0xff, 0x00, // VNI(Bad VNI != 1)
		0x01, 0x02, 0x03, 0x04, // payload
	}
	mbuf.SetData(data)

	_, err = decapVXLAN(nil, 1)
	suite.NotEmpty(err)
}

func TestVXLANTestSuites(t *testing.T) {
	vxlanTestSuite = new(testVXLANTestSuite)
	suite.Run(t, vxlanTestSuite)
}
