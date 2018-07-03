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
	"testing"
)

const SubCount = 10

func TestNotify(t *testing.T) {
	// Create notifier
	noti := NewNotifier(0)

	var subs []chan Notification
	var acks []chan struct{}

	for i := 0; i < 10; i++ {
		ch := noti.Listen()
		ack := make(chan struct{})
		subs = append(subs, ch)
		acks = append(acks, ack)
		j := i
		go func() {
			for n := range ch {
				t.Logf("%d: got %v", j, n)
				ack <- struct{}{}
			}
		}()
	}

	noti.Notify(Add, "notify 1", nil)

	for _, ack := range acks {
		<-ack
	}

	noti.Notify(Delete, "notify 2", nil)

	for _, ack := range acks {
		<-ack
	}

	for _, sub := range subs {
		noti.Close(sub)
	}

	noti.Notify(Add, "notify 3", nil)
}
