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

package vxlan

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type testFDBTestSuite struct {
	suite.Suite
}

func (suite *testFDBTestSuite) SetupTest() {
}

func (suite *testFDBTestSuite) TearDownTest() {
}

func (suite *testFDBTestSuite) TestNewLearnDelClear() {
	fdb := NewFDB(1, 5*time.Minute, nil)
	suite.NotEmpty(fdb)

	mac1 := MacAddress{0x0, 0x0, 0x0, 0x0, 0x0, 0x1}
	mac2 := MacAddress{0x0, 0x0, 0x0, 0x0, 0x0, 0x2}
	mac3 := MacAddress{0x0, 0x0, 0x0, 0x0, 0x0, 0x3}
	expectedFDB1 := map[MacAddress]net.IP{
		mac1: net.ParseIP("192.168.0.1").To4(),
		mac2: net.ParseIP("192.168.0.2").To4(),
		mac3: net.ParseIP("192.168.0.3").To4(),
	}
	expectedFDB2 := map[MacAddress]net.IP{
		mac1: net.ParseIP("192.168.10.1").To4(),
		mac2: net.ParseIP("192.168.0.2").To4(),
		mac3: net.ParseIP("192.168.0.3").To4(),
	}
	expectedFDB3 := map[MacAddress]net.IP{
		mac2: net.ParseIP("192.168.0.2").To4(),
		mac3: net.ParseIP("192.168.0.3").To4(),
	}

	// Learn - OK.
	for mac, ip := range expectedFDB1 {
		fdb.Learn(&mac, &ip)
	}
	for mac, ip := range expectedFDB1 {
		e := fdb.db[mac]
		entry := e.Value.(*Entry)
		suite.Equal(mac, entry.MacAddr)
		suite.Equal(ip, entry.RemoteIP)
	}
	suite.Equal(3, fdb.limitedEntries.Len())

	// Update.
	ip := expectedFDB2[mac1]
	fdb.Learn(&mac1, &ip)
	for mac, ip := range expectedFDB2 {
		e := fdb.db[mac]
		entry := e.Value.(*Entry)
		suite.Equal(mac, entry.MacAddr)
		suite.Equal(ip, entry.RemoteIP)
	}
	suite.Equal(3, fdb.limitedEntries.Len())

	// Delete - OK.
	fdb.Delete(&mac1)
	e := fdb.db[mac1]
	suite.Empty(e)
	for mac, ip := range expectedFDB3 {
		e := fdb.db[mac]
		entry := e.Value.(*Entry)
		suite.Equal(mac, entry.MacAddr)
		suite.Equal(ip, entry.RemoteIP)
	}
	suite.Equal(2, fdb.limitedEntries.Len())

	// Clear - OK.
	fdb.Clear()
	suite.Equal(0, len(fdb.db))
	suite.Equal(0, fdb.limitedEntries.Len())
}

func (suite *testFDBTestSuite) TestAgingOut() {
	ctrlFunc := func(*ControlParam) error {
		return nil
	}
	fdb := NewFDB(1, 0, ctrlFunc)
	suite.NotEmpty(fdb)

	mac1 := MacAddress{0x0, 0x0, 0x0, 0x0, 0x0, 0x1}
	mac2 := MacAddress{0x0, 0x0, 0x0, 0x0, 0x0, 0x2}
	mac3 := MacAddress{0x0, 0x0, 0x0, 0x0, 0x0, 0x3}
	expectedFDB1 := map[MacAddress]net.IP{
		mac1: net.ParseIP("192.168.0.1").To4(),
		mac2: net.ParseIP("192.168.0.2").To4(),
		mac3: net.ParseIP("192.168.0.3").To4(),
	}

	// agingTime = 0 sec (Not deletion target.)
	fdb.setAgingTime(0)
	ip := expectedFDB1[mac1]
	fdb.Learn(&mac1, &ip)

	// agingTime = 1 Hour (Not deletion target.)
	fdb.setAgingTime(1 * time.Hour)
	ip = expectedFDB1[mac2]
	fdb.Learn(&mac2, &ip)

	// agingTime = 1 nsec (Deletion target.)
	fdb.setAgingTime(1 * time.Nanosecond)
	ip = expectedFDB1[mac3]
	fdb.Learn(&mac3, &ip)

	//// mac1/mac2/mac3 in db.
	suite.Equal(3, len(fdb.db))
	//// mac2/mac3 in limitedEntries.
	suite.Equal(2, fdb.limitedEntries.Len())

	// sleep (2 nsec).
	time.Sleep(2 * time.Nanosecond)

	// Aging - OK.
	err := fdb.Aging()
	suite.Empty(err)

	//// mac1/mac2/mac3 is found in db.
	suite.Equal(3, len(fdb.db))
	for mac, ip := range expectedFDB1 {
		e := fdb.db[mac]
		entry := e.Value.(*Entry)
		suite.Equal(mac, entry.MacAddr)
		suite.Equal(ip, entry.RemoteIP)
	}

	//// mac2 is found in limitedEntries.
	suite.Equal(1, fdb.limitedEntries.Len())
	e := fdb.limitedEntries.Front()
	entry := e.Value.(*Entry)
	suite.Equal(mac2, entry.MacAddr)
}

var testFDBSuite *testFDBTestSuite

func TestFDBTestSuites(t *testing.T) {
	testFDBSuite = new(testFDBTestSuite)
	suite.Run(t, testFDBSuite)
}
