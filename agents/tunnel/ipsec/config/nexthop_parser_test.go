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

package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

type testNexthopParserTestSuite struct {
	suite.Suite
}

func (suite *testNexthopParserTestSuite) TestParse() {
	confStr := "port 1 src-mac 00:00:00:00:00:02 dst-mac 00:00:00:00:00:03"

	err := nexthopParser.Parse(strings.Fields(confStr))
	suite.Empty(err)
}

func (suite *testNexthopParserTestSuite) TestParseErrorBadParam() {
	// Bad param length.
	confStr := ""
	err := nexthopParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testNexthopParserTestSuite) TestParseErrorPort() {
	// Bad port.
	confStr := "port hoge"
	err := nexthopParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "strconv.ParseUint: parsing \"hoge\": invalid syntax")

	// Empty value.
	confStr = "port"
	err = nexthopParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testNexthopParserTestSuite) TestParseErrorSrcMac() {
	// Bad src mac addr.
	confStr := "src-mac hoge"
	err := nexthopParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "address hoge: invalid MAC address")

	// Empty value.
	confStr = "src-mac"
	err = nexthopParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func (suite *testNexthopParserTestSuite) TestParseErrorDstMac() {
	// Bad dst mac addr.
	confStr := "dst-mac hoge"
	err := nexthopParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "address hoge: invalid MAC address")

	// Empty value.
	confStr = "dst-mac"
	err = nexthopParser.Parse(strings.Fields(confStr))
	suite.EqualError(err, "Bad format")
}

func TestNexthopParserTestSuites(t *testing.T) {
	suite.Run(t, new(testNexthopParserTestSuite))
}
