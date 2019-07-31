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
	"errors"
	"fmt"
	"sync"

	"github.com/lagopus/vsw/dpdk"
)

// OutputDevice is implemented by an instance, such as VIF and VRF,
// that behaves as an output device.
// Oputput devices have VIFIndex assigned, and has an input ring.
type OutputDevice interface {
	VIFIndex() VIFIndex
	Input() *dpdk.Ring
	fmt.Stringer
}

type vifIndexManager struct {
	indices   []OutputDevice
	nextIndex int
	count     int
	mutex     sync.Mutex
}

var vifIdxMgr = &vifIndexManager{nextIndex: 1}

// For testing only. Don't use this for production.
func (m *vifIndexManager) reset() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.indices = nil
	m.nextIndex = 1
	m.count = 0

	logger.Warning("VIFIndex manager has been hard reset!")
}

func (m *vifIndexManager) allocVIFIndex(dev OutputDevice) (VIFIndex, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	index := InvalidVIFIndex

	if len(m.indices) < MaxVIFIndex {
		// If we still haven't reached the limit,
		// we just append to the end of the slice.
		m.indices = append(m.indices, dev)

		// VIFIndex is index in the slice plus 1.
		index = VIFIndex(len(m.indices))
	} else {
		// If the slice grown up to the limit, then
		// we search for the vacant slot.
		for i := 0; i < MaxVIFIndex; i++ {
			if m.indices[i] == nil {
				m.indices[i] = dev
				index = VIFIndex(i + 1)
			}
		}
	}

	if index == InvalidVIFIndex {
		return InvalidVIFIndex, errors.New("Number of VIF exceeded the limit.")
	}

	return index, nil
}

func (m *vifIndexManager) freeVIFIndex(index VIFIndex) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if index == InvalidVIFIndex {
		return errors.New("Invalid VIFIndex")
	}

	if int(index) > len(m.indices) {
		return errors.New("No such VIFIndex")
	}

	idx := index - 1
	if m.indices[idx] == nil {
		return errors.New("No such VIFIndex")
	}

	m.indices[idx] = nil

	return nil
}
