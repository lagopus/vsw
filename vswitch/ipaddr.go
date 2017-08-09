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

package vswitch

import (
	"bytes"
	"fmt"
	"github.com/lagopus/vsw/utils/notifier"
	"net"
	"sync"
)

// IPAddrs manages IP Addresses of the device.
type IPAddrs struct {
	container interface{}
	ipaddrs   []IPAddr
	mutex     sync.Mutex
}

// IPAddr represents IP Address
type IPAddr struct {
	IP   net.IP     // IP Address
	Mask net.IPMask // Network Mask
}

func (ip IPAddr) String() string {
	prefix, _ := ip.Mask.Size()
	return fmt.Sprintf("%v/%d", ip.IP, prefix)
}

func newIPAddrs(container interface{}) *IPAddrs {
	return &IPAddrs{container: container}
}

// ListIPAddrs returns a slice IPAddr currently set.
func (i *IPAddrs) ListIPAddrs() []IPAddr {
	return i.ipaddrs
}

// AddCIDR adds IP Address represented in CIDR format.
// See AddIPAddr for more detail.
func (i *IPAddrs) AddCIDR(cidr string) bool {
	if ip, mask, err := net.ParseCIDR(cidr); err == nil {
		return i.AddIPAddr(IPAddr{ip, mask.Mask})
	}
	return false
}

// AddIPAddr adds IP Address.
// If IP Address is added, it sends Add notification.
// If IP Address already existed, and prefix has changed,
// it sends out Update notification.
// Returns true for success, false otherwise.
func (i *IPAddrs) AddIPAddr(ip IPAddr) bool {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	nt := notifier.Add
	for n, ipaddr := range i.ipaddrs {
		if ipaddr.IP.Equal(ip.IP) {
			if bytes.Compare(ipaddr.Mask, ip.Mask) == 0 {
				// Nothing to update
				return true
			}
			i.ipaddrs[n].Mask = ip.Mask
			nt = notifier.Update
			goto Notify
		}
	}

	// append to the list
	i.ipaddrs = append(i.ipaddrs, ip)

Notify:
	noti.Notify(nt, i.container, ip)
	return true
}

// DeleteIPAddr deletes IP Address.
// If IP Address is deleted, it sends out Delete notification.
// Returns true for success, false otherwise.
func (i *IPAddrs) DeleteIPAddr(ip IPAddr) bool {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	for n, ipaddr := range i.ipaddrs {
		if ipaddr.IP.Equal(ip.IP) {
			i.ipaddrs[n] = i.ipaddrs[len(i.ipaddrs)-1]
			i.ipaddrs = i.ipaddrs[:len(i.ipaddrs)-1]
			noti.Notify(notifier.Delete, i.container, ip)
			return true
		}
	}
	return false
}
