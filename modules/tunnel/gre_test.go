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

type testGRETestSuite struct {
	suite.Suite
}

var greTestSuite *testGRETestSuite

func (suite *testGRETestSuite) TestEncapGRE() {
	mbuf := allocMbuf()
	suite.NotEmpty(mbuf)
	defer mbuf.Free()

	// payload.
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	mbuf.SetData(payload)

	// data.
	expectedGRE := []byte{
		0x00, 0x00, // Reserved0, Ver
		0x08, 0x00, // Protocol Type
	}
	expectedData := append(expectedGRE, payload...)

	// encapGRE: OK.
	_, err := encapGRE(mbuf, 0x0800)
	suite.Empty(err)
	mdata := mbuf.Data()
	suite.Equal(expectedData, mdata)
}

func (suite *testGRETestSuite) TestEncapGREErr() {
	// encapGRE: NG, mbuf is nil.
	_, err := encapGRE(nil, 0x0800)
	suite.NotEmpty(err)
}

func (suite *testGRETestSuite) TestDecapGRE() {
	mbuf := allocMbuf()
	suite.NotEmpty(mbuf)
	defer mbuf.Free()

	// payload.
	payload := []byte{0x01, 0x02, 0x03, 0x04}

	// data.
	expectedVer := []byte{
		0x00, 0x00, // Reserved0, Ver
	}
	expectedProto := []byte{
		0x08, 0x00, // Protocol Type
	}
	data := append(expectedVer, expectedProto...)
	data = append(data, payload...)
	mbuf.SetData(data)

	expectedData := payload

	// decapGRE: OK.
	outGRE, err := decapGRE(mbuf)
	suite.Empty(err)
	mdata := mbuf.Data()
	suite.Equal(expectedData, mdata)
	suite.Equal(binary.LittleEndian.Uint16(expectedVer), outGRE.version())
	suite.Equal(binary.LittleEndian.Uint16(expectedProto), outGRE.protocol())
}

func (suite *testGRETestSuite) TestDecapGREErr() {
	mbuf := allocMbuf()
	suite.NotEmpty(mbuf)
	defer mbuf.Free()

	// decapGRE: NG, mbuf is nil..
	_, err := decapGRE(nil)
	suite.NotEmpty(err)
}

func TestGRETestSuites(t *testing.T) {
	greTestSuite = new(testGRETestSuite)
	suite.Run(t, greTestSuite)
}
