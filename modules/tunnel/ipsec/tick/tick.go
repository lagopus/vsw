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
	"log"
	"sync"
	"time"
)

const (
	// IntervalMillisecond Interval for Ticker.
	IntervalMillisecond uint64 = 1000
	// Interval Interval (type of Duration)
	Interval time.Duration = time.Duration(IntervalMillisecond) * time.Millisecond
)

// Ticker ticker
type Ticker struct {
	tasks       map[string]*Task
	stopChannel chan bool
	isRunning   bool
	lock        sync.Mutex
}

var ticker = newTicker()

func newTicker() *Ticker {
	t := &Ticker{
		tasks:       map[string]*Task{},
		stopChannel: make(chan bool),
	}
	return t
}

func (t *Ticker) timeOutEvent() error {
	t.lock.Lock()
	defer t.lock.Unlock()

	now := time.Now()
	for _, task := range t.tasks {
		if err := task.callback(now, task.args); err != nil {
			log.Println(err)
			return err
		}
	}
	return nil
}

func (t *Ticker) tickerLoop(wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(Interval)
	for {
		select {
		case <-ticker.C:
			if err := t.timeOutEvent(); err != nil {
				log.Println(err)
				return
			}
		case <-t.stopChannel:
			ticker.Stop()
			return
		}
	}
}

// Public.

// RegisterTask Register task.
func (t *Ticker) RegisterTask(task *Task) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	if task == nil {
		return fmt.Errorf("Invalid args")
	}

	if task.callback != nil {
		if _, ok := t.tasks[task.name]; !ok {
			t.tasks[task.name] = task
			return nil
		}
		return fmt.Errorf("Already exists : %v", task.name)
	}
	return fmt.Errorf("Callback func is nil")
}

// UnregisterTask Unregister task.
func (t *Ticker) UnregisterTask(task *Task) {
	t.lock.Lock()
	defer t.lock.Unlock()

	delete(t.tasks, task.name)
}

// UnregisterTaskByName Unregister task by name of task.
func (t *Ticker) UnregisterTaskByName(taskName string) {
	t.lock.Lock()
	defer t.lock.Unlock()

	delete(t.tasks, taskName)
}

// AllUnregisterTask All unregister task.
func (t *Ticker) AllUnregisterTask() {
	t.lock.Lock()
	defer t.lock.Unlock()

	for taskName := range t.tasks {
		delete(t.tasks, taskName)
	}
}

// Start Start ticker.
func (t *Ticker) Start(wg *sync.WaitGroup) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.isRunning == false {
		wg.Add(1)
		go t.tickerLoop(wg)
		t.isRunning = true
	}
}

// Stop Stop ticker.
func (t *Ticker) Stop() {
	t.stopChannel <- true

	t.lock.Lock()
	defer t.lock.Unlock()

	if t.isRunning == true {
		t.isRunning = false
	}
}

// GetTicker Get ticker instance.
func GetTicker() *Ticker {
	return ticker
}
