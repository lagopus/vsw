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
	"fmt"
	"time"
)

// Task Task for ticker. Don't unregister task in callback function.
type Task struct {
	name     string
	callback func(now time.Time, args []interface{}) error // Don't unregister task in this.
	args     []interface{}
}

// NewTask Create task.
func NewTask(name string,
	callback func(now time.Time, args []interface{}) error,
	args []interface{}) (*Task, error) {

	if len(name) != 0 && callback != nil {
		t := &Task{
			name:     name,
			callback: callback,
			args:     args,
		}
		return t, nil
	}
	return nil, fmt.Errorf("Invalid args")
}
