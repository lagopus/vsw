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

package tick

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type testTaskTestSuite struct {
	suite.Suite
}

func (suite *testTaskTestSuite) TestNewTask() {
	name := "task1"
	callback := func(now time.Time, args []interface{}) error {
		return nil
	}
	args := []interface{}{
		"test",
	}

	task1, err := NewTask(
		"task1",
		callback,
		args)
	suite.Empty(err)
	suite.Equal(name, task1.name)
	suite.Equal(reflect.ValueOf(callback),
		reflect.ValueOf(task1.callback))
	suite.Equal(args, task1.args)
}

func (suite *testTaskTestSuite) TestNewTaskError() {
	// callback is nil
	_, err := NewTask("task1", nil, nil)
	suite.EqualError(err, "Invalid args")

	// name is empty
	_, err = NewTask("",
		func(now time.Time, args []interface{}) error {
			return nil
		},
		nil)
	suite.EqualError(err, "Invalid args")
}

func TestTaskTestSuites(t *testing.T) {
	suite.Run(t, new(testTaskTestSuite))
}
