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

package notifier

import (
	"fmt"
	"sync"
)

type Notifier struct {
	listeners map[chan Notification]chan Notification
	buffers   int
	mutex     sync.Mutex
}

type Type int

const (
	Add Type = iota
	Delete
	Update
)

var typeStrings = [...]string{
	Add:    "ADD",
	Delete: "DELETE",
	Update: "UPDATE",
}

func (t Type) String() string { return typeStrings[t] }

type Notification struct {
	Type   Type        // Add, Delete, or Modify
	Target interface{} // Target Object which was added, deleted or modified
	Value  interface{} // Value added, or modified
}

func (noti Notification) String() string {
	return fmt.Sprintf("%s %v to %v", noti.Type, noti.Value, noti.Target)
}

func NewNotifier(buffers int) *Notifier {
	if buffers < 0 {
		buffers = 0
	}
	return &Notifier{
		listeners: make(map[chan Notification]chan Notification),
		buffers:   buffers,
	}
}

func (n *Notifier) Notify(t Type, tgt interface{}, v interface{}) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	for _, listener := range n.listeners {
		listener <- Notification{t, tgt, v}
	}
}

func (n *Notifier) Listen() chan Notification {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	ch := make(chan Notification, n.buffers)
	n.listeners[ch] = ch
	return ch
}

func (n *Notifier) Close(ch chan Notification) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	delete(n.listeners, ch)
	close(ch)
}
