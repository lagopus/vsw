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

/*
#include "packet.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"github.com/lagopus/vsw/dpdk"
	"io/ioutil"
	"strconv"
	"strings"
	"sync"
)

// DpdkConfig defines a configuration for DPDK.
type DpdkConfig struct {
	CoreMask      int      // Value passed to -c option
	CoreList      string   // Value passed to -l option
	MemoryChannel int      // Value passed to -n option
	PmdPath       string   // Value passed to -d option
	Vdevs         []string // Value passed to --vdev options
	NumElements   uint     // A number of elements in mempool (Optimal: NumElements == 2^q - 1)
	CacheSize     uint     // Cache size (Optimal: NumElements % CacheSize == 0)
	DataRoomSize  uint     // Data Room Size for each mbuf, including dpdk.RTE_PKTMBUF_HEADROOM
}

const (
	MemPoolName         = "Lagopus2" // Memory pool name for Lagopus2
	DefaultNumElements  = 2 << 16    // Default number of elements
	DefaultCacheSize    = 256        // Default cache size
	DefaultPmdPath      = "/usr/local/lib"
	DefaultDataRoomSize = dpdk.RTE_PKTMBUF_HEADROOM + C.MAX_PACKET_SZ
)

// DpdkResource represents DPDK resources shared by Lagopus2.
type DpdkResource struct {
	Mempool *dpdk.MemPool // DPDK Memory pool.
	cores   map[uint]bool
	mutex   sync.Mutex
}

var dpdkResource *DpdkResource

func searchPmdLibrary(path string) []string {
	files, _ := ioutil.ReadDir(path)
	var pmds []string
	path += "/"
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "librte_pmd_") && strings.HasSuffix(f.Name(), ".so") {
			pmds = append(pmds, "-d", path+f.Name())
		}
	}
	return pmds
}

// InitDpdk initialize DPDK with the given DPDK configuration.
// Returns true for success, and false for failure.
func InitDpdk(dc *DpdkConfig) bool {
	if dc == nil || dpdkResource != nil {
		return true
	}

	argv := []string{"lagopus2"}
	cores := make(map[uint]bool)

	if dc.CoreMask > 0 {
		argv = append(argv, "-c", fmt.Sprintf("%x", dc.CoreMask))

		mask := dc.CoreMask
		n := uint(0)
		for mask > 0 {
			if mask&1 != 0 {
				cores[n] = false
			}
			mask >>= 1
			n++
		}
	} else if dc.CoreList != "" {
		argv = append(argv, "-l", dc.CoreList)

		coreList := strings.Split(dc.CoreList, ",")
		for _, c := range coreList {
			if n, err := strconv.Atoi(c); err == nil {
				cores[uint(n)] = false
			}
		}
	}

	if dc.MemoryChannel > 0 {
		argv = append(argv, "-n", fmt.Sprintf("%d", dc.MemoryChannel))
	}

	if dc.PmdPath == "" {
		dc.PmdPath = DefaultPmdPath
	}
	argv = append(argv, searchPmdLibrary(dc.PmdPath)...)

	for _, vdev := range dc.Vdevs {
		argv = append(argv, "--vdev", vdev)
	}

	if dpdk.EalInit(argv) < 0 {
		return false
	}

	if dc.NumElements == 0 {
		dc.NumElements = DefaultNumElements
	}

	if dc.CacheSize == 0 {
		dc.CacheSize = DefaultCacheSize
	}

	if dc.DataRoomSize == 0 {
		dc.DataRoomSize = DefaultDataRoomSize
	}

	pool := dpdk.PktMbufPoolCreate(MemPoolName, dc.NumElements, dc.CacheSize,
		C.sizeof_struct_lagopus_packet_metadata,
		dc.DataRoomSize, dpdk.SOCKET_ID_ANY)

	if pool == nil {
		return false
	}

	cores[dpdk.GetMasterLcore()] = true
	Logger.Printf("core list: %v", cores)

	dpdkResource = &DpdkResource{
		Mempool: pool,
		cores:   cores,
	}

	return true
}

// GetDpdkResource returnes the current DpdkResource.
// Call this to get an access to memory pool allocated by Lagopus2.
func GetDpdkResource() *DpdkResource {
	return dpdkResource
}

// AllocLcore returns vacant slave core. If there's no slave core left,
// returns an error.
// Make sure that any modules that requires slave core get allocation
// from this API. Otherwise, unexpected results are expected, e.g.
// deadlock.
func (d *DpdkResource) AllocLcore() (uint, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	for i, c := range d.cores {
		if !c {
			d.cores[i] = true
			return i, nil
		}
	}
	return 0, errors.New("No slave core available")

}

// FreeLcore frees given slave core for others to use.
func (d *DpdkResource) FreeLcore(coreid uint) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if coreid != dpdk.GetMasterLcore() && int(coreid) < len(d.cores) {
		d.cores[coreid] = false
	}
}
