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

package vxlan

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type testCFDBTestSuite struct {
	suite.Suite
	cfdb *CFDB
}

func (suite *testCFDBTestSuite) SetupTest() {
	var err error

	// alloc FDB.
	suite.cfdb, err = allocFDB()
	suite.Empty(err)
}

func (suite *testCFDBTestSuite) TearDownTest() {
	var err error

	// free FDB.
	err = suite.cfdb.free()
	suite.Empty(err)
}

func (suite *testCFDBTestSuite) TestLearnFindDelClear() {
	cfdb := suite.cfdb

	// data.
	mac1 := MacAddress{0x0, 0x0, 0x0, 0x0, 0x0, 0x1}
	cmac1 := newCEtherAddr(&mac1)
	mac2 := MacAddress{0x0, 0x0, 0x0, 0x0, 0x0, 0x2}
	cmac2 := newCEtherAddr(&mac2)
	mac3 := MacAddress{0x0, 0x0, 0x0, 0x0, 0x0, 0x3}
	cmac3 := newCEtherAddr(&mac3)

	ip1 := []byte{ // ip header.
		0x45, 0x00, 0x00, 0x20,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x7c, 0xca,
		0x7f, 0x00, 0x00, 0x01, // src IP
		0x7f, 0x00, 0x00, 0x02, // dst IP
	}
	cip1 := newCIP(ip1)

	ip2 := []byte{ // ip header.
		0x45, 0x00, 0x00, 0x20,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x7c, 0xca,
		0x7f, 0x00, 0x00, 0x03, // src IP
		0x7f, 0x00, 0x00, 0x04, // dst IP
	}
	cip2 := newCIP(ip2)

	ip3 := []byte{ // ip header.
		0x45, 0x00, 0x00, 0x20,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x7c, 0xca,
		0x7f, 0x00, 0x00, 0x05, // src IP
		0x7f, 0x00, 0x00, 0x06, // dst IP
	}
	cip3 := newCIP(ip3)

	data := map[*CEtherAddr]*CIP{
		cmac1: cip1,
		cmac2: cip2,
	}
	expectedIP1 := map[*CIP]uint32{
		cip1: bytes2Uint([]byte{0x7f, 0x00, 0x00, 0x01}),
		cip2: bytes2Uint([]byte{0x7f, 0x00, 0x00, 0x03}),
	}
	expectedMac1 := map[*CEtherAddr]*MacAddress{
		cmac1: &mac1,
		cmac2: &mac2,
	}
	expectedIP2 := map[*CIP]uint32{
		cip1: bytes2Uint([]byte{0x7f, 0x00, 0x00, 0x05}),
		cip2: bytes2Uint([]byte{0x7f, 0x00, 0x00, 0x03}),
	}

	//// learn.
	var err error
	for mac, ip := range data {
		err = cfdb.learn(mac, ip)
		suite.Empty(err)
	}

	//// find.
	// found.
	var centry *CFDBEntry
	for mac, ip := range data {
		centry, err = cfdb.find(mac)
		suite.Empty(err)
		suite.NotEmpty(centry)
		suite.Equal(expectedIP1[ip], centry.remoteIP2Uint())
		suite.Equal(uint2IP(expectedIP1[ip]), centry.RemoteIP())
		suite.Equal(expectedMac1[mac], centry.MacAddr())
		suite.False(centry.refed())
	}

	//// find.
	// not found.
	centry, err = cfdb.find(cmac3)
	suite.Empty(err)
	suite.Empty(centry)

	/// learn (same).
	err = cfdb.learn(cmac1, cip1)
	suite.Empty(err)

	// find.
	// found.
	for mac, ip := range data {
		var centry *CFDBEntry
		centry, err = cfdb.find(mac)
		suite.Empty(err)
		suite.NotEmpty(centry)
		suite.Equal(expectedIP1[ip], centry.remoteIP2Uint())
		if mac == cmac1 {
			suite.True(centry.refed())
		} else {
			suite.False(centry.refed())
		}
	}

	//// update.
	err = cfdb.learn(cmac1, cip3)
	suite.Empty(err)

	// find.
	// found.
	for mac, ip := range data {
		var centry *CFDBEntry
		centry, err = cfdb.find(mac)
		suite.Empty(err)
		suite.NotEmpty(centry)
		suite.Equal(expectedIP2[ip], centry.remoteIP2Uint())
		suite.False(centry.refed())
	}

	//// delete.
	err = cfdb.del(cmac1)
	suite.Empty(err)

	// find.
	// not found.
	centry, err = cfdb.find(cmac1)
	suite.Empty(err)
	suite.Empty(centry)

	// find.
	// found.
	centry, err = cfdb.find(cmac2)
	suite.Empty(err)
	suite.NotEmpty(centry)
	suite.Equal(expectedIP1[cip2], centry.remoteIP2Uint())

	//// clear.
	err = cfdb.clear()
	suite.Empty(err)

	// find.
	// not found.
	for mac := range data {
		centry, err = cfdb.find(mac)
		suite.Empty(err)
		suite.Empty(centry)
	}
}

func (suite *testCFDBTestSuite) TestGC() {
	cfdb := suite.cfdb

	// data.
	mac1 := MacAddress{0x0, 0x0, 0x0, 0x0, 0x0, 0x1}
	cmac1 := newCEtherAddr(&mac1)
	mac2 := MacAddress{0x0, 0x0, 0x0, 0x0, 0x0, 0x2}
	cmac2 := newCEtherAddr(&mac2)

	ip1 := []byte{ // ip header.
		0x45, 0x00, 0x00, 0x20,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x7c, 0xca,
		0x7f, 0x00, 0x00, 0x01, // src IP
		0x7f, 0x00, 0x00, 0x02, // dst IP
	}
	cip1 := newCIP(ip1)

	ip2 := []byte{ // ip header.
		0x45, 0x00, 0x00, 0x20,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x7c, 0xca,
		0x7f, 0x00, 0x00, 0x03, // src IP
		0x7f, 0x00, 0x00, 0x04, // dst IP
	}
	cip2 := newCIP(ip2)

	data := map[*CEtherAddr]*CIP{
		cmac1: cip1,
		cmac2: cip2,
	}

	//// learn.
	var err error
	for mac, ip := range data {
		err = cfdb.learn(mac, ip)
		suite.Empty(err)
	}

	/// learn (same).
	err = cfdb.learn(cmac1, cip1)
	suite.Empty(err)

	/// GC.
	var centry *CFDBEntry
	for mac := range data {
		centry, err = cfdb.gc(mac)
		suite.Empty(err)
		if mac == cmac1 {
			suite.NotEmpty(centry)
		} else {
			suite.Empty(centry)
		}
	}

	// not found.
	centry, err = cfdb.find(cmac2)
	suite.Empty(err)
	suite.Empty(centry)

	// find.
	for mac := range data {
		centry, err = cfdb.find(mac)
		suite.Empty(err)
		if mac == cmac1 {
			// found.
			suite.NotEmpty(centry)
		} else {
			// not found.
			suite.Empty(centry)
		}
	}
}

var testCFDBSuite *testCFDBTestSuite

func TestCFDBTestSuites(t *testing.T) {
	testCFDBSuite = new(testCFDBTestSuite)
	suite.Run(t, testCFDBSuite)
}
