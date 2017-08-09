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

package netlink

import (
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"syscall"
)

// Type is either syscall.RTM_NEWNEIGH or syscall.RTM_DELNEIGH
type NeighUpdate struct {
	Type uint16
	*netlink.Neigh
}

// NeighSubscribe subscribes to NUD changes.
// API is similar to netlink.RouteSubscribe.
func NeighSubscribe(ch chan<- NeighUpdate, done <-chan struct{}) error {
	s, err := nl.SubscribeAt(netns.None(), netns.None(), syscall.NETLINK_ROUTE, syscall.RTNLGRP_NEIGH)
	if err != nil {
		return err
	}

	if done != nil {
		go func() {
			<-done
			s.Close()
		}()
	}

	go func() {
		defer close(ch)
		for {
			msgs, err := s.Receive()
			if err != nil {
				return
			}
			for _, m := range msgs {
				neigh, err := netlink.NeighDeserialize(m.Data)
				if err != nil {
					return
				}
				ch <- NeighUpdate{Type: m.Header.Type, Neigh: neigh}
			}
		}
	}()

	return nil
}
