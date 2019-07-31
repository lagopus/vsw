//
// Copyright 2019 Nippon Telegraph and Telephone Corporation.
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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
)

type NAPT struct {
	vif            *VIF
	maximumEntries uint
	agingTime      uint
	portRange      PortRange
	address        net.IP
	enabled        bool
	mutex          sync.Mutex
}

var naptDefaultPortRange = PortRange{Start: 49152, End: 65535}

const (
	NAPTDefaultAgingTime      = 900
	NAPTDefaultMaximumEntries = 10000
)

func (n *NAPT) String() string {
	return fmt.Sprintf("maximum-entries: %d, aging-time: %d, port-range: %v, address: %v, enabled: %v",
		n.maximumEntries, n.agingTime, &n.portRange, n.address, n.enabled)
}

func (n *NAPT) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"maximum-entries": n.maximumEntries,
		"aging-time":      n.agingTime,
		"port-range":      &n.portRange,
		"address":         n.address,
		"enabled":         n.enabled,
	}
	return json.Marshal(m)
}

func (n *NAPT) MaximumEntries() uint {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	return n.maximumEntries
}

func (n *NAPT) SetMaximumEntries(max uint) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.enabled {
		return errors.New("Can't modify setting. NAPT is already enabled.")
	}

	n.maximumEntries = max
	return nil
}

func (n *NAPT) AgingTime() uint {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	return n.agingTime
}

func (n *NAPT) SetAgingTime(time uint) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.enabled {
		return errors.New("Can't modify setting. NAPT is already enabled.")
	}

	n.agingTime = time
	return nil
}

func (n *NAPT) Address() net.IP {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	return n.address
}

func (n *NAPT) SetAddress(ip net.IP) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.enabled {
		return errors.New("Can't modify setting. NAPT is already enabled.")
	}

	// duplicate net.IP
	dup := make(net.IP, len(ip))
	copy(dup, ip)

	n.address = ip
	return nil
}

func (n *NAPT) PortRange() *PortRange {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	return &n.portRange
}

func (n *NAPT) SetPortRange(pr *PortRange) error {
	if pr.Start < naptDefaultPortRange.Start {
		return errors.New("PortRange out of bounds")
	}
	n.portRange = *pr
	return nil
}

func (n *NAPT) IsEnabled() bool {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	return n.enabled
}

func (n *NAPT) Enable() error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.enabled {
		return nil
	}

	n.enabled = true

	if err := n.vif.enableNAPT(); err != nil {
		n.enabled = false
		return err
	}

	return nil
}

func (n *NAPT) Disable() error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if !n.enabled {
		return nil
	}

	n.enabled = false

	if err := n.vif.disableNAPT(); err != nil {
		n.enabled = true
		return err
	}

	return nil
}

func newNAPT(v *VIF) *NAPT {
	if v == nil {
		return nil
	}
	return &NAPT{
		vif:            v,
		maximumEntries: NAPTDefaultMaximumEntries,
		agingTime:      NAPTDefaultAgingTime,
		portRange:      naptDefaultPortRange,
	}
}
