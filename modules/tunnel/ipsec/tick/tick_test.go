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

package tick

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type testTickTestSuite struct {
	suite.Suite
}

var wg sync.WaitGroup

func (suite *testTickTestSuite) TearDownTest() {
	ticker := GetTicker()
	ticker.AllUnregisterTask()
}

func tickerStart(ticker *Ticker) {
	ticker.Start(&wg)
}

func tickerStop(ticker *Ticker) {
	ticker.Stop()
	wg.Wait()
}

func (suite *testTickTestSuite) TestRegisterUnregisterTask() {
	var task1, task2 *Task
	var err error
	task1, err = NewTask(
		"task1",
		func(now time.Time, args []interface{}) error {
			return nil
		},
		nil)
	suite.Empty(err)

	task2, err = NewTask(
		"task2",
		func(now time.Time, args []interface{}) error {
			return nil
		},
		nil)
	suite.Empty(err)

	ticker := GetTicker()

	// Register
	err = ticker.RegisterTask(task1)
	suite.Empty(err)
	if _, ok := ticker.tasks["task1"]; !ok {
		suite.Fail("Can't Register")
	}
	err = ticker.RegisterTask(task2)
	suite.Empty(err)
	if _, ok := ticker.tasks["task2"]; !ok {
		suite.Fail("Can't Register")
	}

	// Unregister
	ticker.UnregisterTask(task1)
	if _, ok := ticker.tasks["task1"]; ok {
		suite.Fail("Can't unregister")
	}
	ticker.UnregisterTaskByName("task2")
	if _, ok := ticker.tasks["task2"]; ok {
		suite.Fail("Can't unregister")
	}
}

func (suite *testTickTestSuite) TestRegisterTaskError() {
	task1, err := NewTask(
		"task1",
		func(now time.Time, args []interface{}) error {
			return nil
		},
		nil)
	suite.Empty(err)

	ticker := GetTicker()
	err = ticker.RegisterTask(task1)
	suite.Empty(err)
	if _, ok := ticker.tasks["task1"]; !ok {
		suite.Fail("Can't Register")
	}

	// Already exists
	err = ticker.RegisterTask(task1)
	suite.EqualError(err, "Already exists : task1")

	// Callback is nil
	err = ticker.RegisterTask(&Task{})
	suite.EqualError(err, "Callback func is nil")

	// Invalid args
	err = ticker.RegisterTask(nil)
	suite.EqualError(err, "Invalid args")
}

func (suite *testTickTestSuite) TestStartStop1() {
	var counter uint

	task1, err := NewTask(
		"task1",
		func(now time.Time, args []interface{}) error {
			counter++
			fmt.Printf("counter %d\n", counter)
			return nil
		},
		nil)
	suite.Empty(err)

	ticker := GetTicker()
	err = ticker.RegisterTask(task1)
	suite.Empty(err)

	// start
	tickerStart(ticker)
	time.Sleep(3 * time.Second)

	// stop
	tickerStop(ticker)
	var backupCounter = counter
	suite.NotEqual(0, counter)
	time.Sleep(2 * time.Second)
	suite.Equal(backupCounter, counter)
}

func testCallbackFunc(now time.Time,
	args []interface{}) error {
	if counter, ok := args[0].(*uint); ok {
		*counter++
		fmt.Printf("counter %d\n", *counter)
	}
	return nil
}

func (suite *testTickTestSuite) TestStartStop2() {
	var counter uint
	var args []interface{}
	args = append(args, &counter)

	task1, err := NewTask(
		"task1",
		testCallbackFunc,
		args)
	suite.Empty(err)

	ticker := GetTicker()
	err = ticker.RegisterTask(task1)
	suite.Empty(err)

	// start
	tickerStart(ticker)
	time.Sleep(3 * time.Second)

	// stop
	tickerStop(ticker)
	var backupCounter = counter
	suite.NotEqual(0, counter)
	time.Sleep(2 * time.Second)
	suite.Equal(backupCounter, counter)
}

func TestTickTestSuites(t *testing.T) {
	suite.Run(t, new(testTickTestSuite))
}
