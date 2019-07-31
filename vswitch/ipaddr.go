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

package vswitch

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/lagopus/vsw/utils/notifier"
)

// AddressFamily represents address family of network address
type AddressFamily int

const (
	AF_IPv4 AddressFamily = iota
	AF_IPv6
)

func (af AddressFamily) String() string {
	s := map[AddressFamily]string{
		AF_IPv4: "IPv4",
		AF_IPv6: "IPv6",
	}
	return s[af]
}

func (af AddressFamily) MarshalJSON() ([]byte, error) {
	if af == AF_IPv4 {
		return []byte(`"IPv4"`), nil
	}
	return []byte(`"IPv6"`), nil
}

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

// Represents any IP (0.0.0.0/0)
var AnyIPAddr = IPAddr{
	[]byte{0, 0, 0, 0},
	[]byte{0, 0, 0, 0},
}

// CreateIPAddr creates IPAddr from net.IP.
// Network mask is set to 32.
func CreateIPAddr(ip net.IP) IPAddr {
	return IPAddr{ip, []byte{0xff, 0xff, 0xff, 0xff}}
}

// ParseCIDR parases a CIDR notation IP address and prefix,
// and returns IPAddr.  Works as net.ParseCIDR.
func ParseCIDR(s string) (IPAddr, error) {
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return AnyIPAddr, err
	}
	return IPAddr{ip, ipnet.Mask}, nil
}

func (ip IPAddr) String() string {
	prefix, _ := ip.Mask.Size()
	return fmt.Sprintf("%v/%d", ip.IP, prefix)
}

func (ip IPAddr) MarshalJSON() ([]byte, error) {
	return []byte(`"` + ip.String() + `"`), nil
}

// Equal reports whether ip and x are the same IP address with
// the same network prefix length.
func (ip IPAddr) Equal(x IPAddr) bool {
	return ip.IP.Equal(x.IP) && bytes.Equal(ip.Mask, x.Mask)
}

func newIPAddrs(container interface{}) *IPAddrs {
	return &IPAddrs{container: container}
}

// ListIPAddrs returns a slice IPAddr currently set.
func (i *IPAddrs) ListIPAddrs() []IPAddr {
	addrs := make([]IPAddr, len(i.ipaddrs))
	copy(addrs, i.ipaddrs)
	return addrs
}

// AddCIDR adds IP Address represented in CIDR format.
// See AddIPAddr for more detail.
func (i *IPAddrs) AddCIDR(cidr string) error {
	if ip, mask, err := net.ParseCIDR(cidr); err == nil {
		return i.AddIPAddr(IPAddr{ip, mask.Mask})
	} else {
		return err
	}
}

// AddIPAddr adds IP Address.
// If IP Address is added, it sends Add notification.
// If IP Address already existed, and prefix has changed,
// it sends out Update notification.
// Returns error if failed.
func (i *IPAddrs) AddIPAddr(ip IPAddr) error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	nt := notifier.Add
	for n, ipaddr := range i.ipaddrs {
		if ipaddr.IP.Equal(ip.IP) {
			if bytes.Equal(ipaddr.Mask, ip.Mask) {
				// Nothing to update
				return errors.New("Duplicated IP Address found")
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
	return nil
}

// DeleteIPAddr deletes IP Address.
// If IP Address is deleted, it sends out Delete notification.
// Returns error if failed.
func (i *IPAddrs) DeleteIPAddr(ip IPAddr) error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	for n, ipaddr := range i.ipaddrs {
		if ipaddr.IP.Equal(ip.IP) {
			i.ipaddrs[n] = i.ipaddrs[len(i.ipaddrs)-1]
			i.ipaddrs = i.ipaddrs[:len(i.ipaddrs)-1]
			noti.Notify(notifier.Delete, i.container, ip)
			return nil
		}
	}
	return errors.New("No such IP Address")
}
