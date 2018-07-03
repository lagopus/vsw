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
	"io/ioutil"
	"strings"
	"sync"

	"github.com/lagopus/vsw/dpdk"
)

// DpdkConfig defines a configuration for DPDK.
type dpdkConfig struct {
	Dpdk DpdkConfig
}

type DpdkConfig struct {
	CoreMask      int      `toml:"core_mask"`      // Value passed to -c option
	CoreList      string   `toml:"core_list"`      // Value passed to -l option
	MemoryChannel int      `toml:"memory_channel"` // Value passed to -n option
	PmdPath       string   `toml:"pmd_path"`       // Value passed to -d option
	Vdevs         []string `toml:"vdevs"`          // Value passed to --vdev options
	NumElements   uint     `toml:"num_elements"`   // A number of elements in mempool (Optimal: NumElements == 2^q - 1)
	CacheSize     uint     `toml:"cache_size"`     // Cache size (Optimal: NumElements % CacheSize == 0)
}

const (
	MemPoolName          = "Lagopus2" // Memory pool name for Lagopus2
	DefaultCoreMask      = 0xfe       // Default Core Mask
	DefaultMemoryChannel = 2          // Default Memory Channel
	DefaultNumElements   = 2 << 16    // Default number of elements
	DefaultCacheSize     = 256        // Default cache size
	DefaultPmdPath       = "/usr/local/lib"
	dataRoomSize         = dpdk.RTE_PKTMBUF_HEADROOM + C.MAX_PACKET_SZ
)

type lcore struct {
	used   bool
	usedby string
}

// DpdkResource represents DPDK resources shared by Lagopus2.
type DpdkResource struct {
	// DPDK default memory pool.
	Mempool *dpdk.MemPool

	// DPDK memory pool per socket. The key is the socket ID.
	// SOCKET_ID_ANY
	Mempools map[int]*dpdk.MemPool
	lcores   map[uint]lcore
	mutex    sync.Mutex
}

type dpdkManager struct {
	dr    *DpdkResource
	dc    DpdkConfig
	mutex sync.Mutex
}

var dpdkMgr *dpdkManager

func searchDrivers(path string) []string {
	prefixes := []string{
		"librte_pmd_",
		"librte_mempool_",
	}

	files, _ := ioutil.ReadDir(path)
	var drivers []string
	path += "/"
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".so") {
			continue
		}

		for _, prefix := range prefixes {
			if strings.HasPrefix(f.Name(), prefix) {
				drivers = append(drivers, "-d", path+f.Name())
				break
			}
		}
	}
	return drivers
}

// InitDpdk initialize DPDK with the given DPDK configuration.
// Returns error on failure.
func initDpdk() error {
	dpdkMgr.mutex.Lock()
	defer dpdkMgr.mutex.Unlock()

	if dpdkMgr.dr != nil {
		return errors.New("Already initialized")
	}

	// Parse configuration file's [dpdk] section
	config := dpdkConfig{
		DpdkConfig{
			MemoryChannel: DefaultMemoryChannel,
			PmdPath:       DefaultPmdPath,
			NumElements:   DefaultNumElements,
			CacheSize:     DefaultCacheSize,
		},
	}
	if _, err := GetConfig().Decode(&config); err != nil {
		return fmt.Errorf("Can't parse config file: %v", err)
	}

	// Create argv for DPDK initialization
	argv := []string{"vsw"}

	if config.Dpdk.CoreMask == 0 && config.Dpdk.CoreList == "" {
		config.Dpdk.CoreMask = DefaultCoreMask
	}
	if config.Dpdk.CoreMask > 0 {
		argv = append(argv, "-c", fmt.Sprintf("%x", config.Dpdk.CoreMask))
	} else if config.Dpdk.CoreList != "" {
		argv = append(argv, "-l", config.Dpdk.CoreList)
	}

	argv = append(argv, "-n", fmt.Sprintf("%d", config.Dpdk.MemoryChannel))
	argv = append(argv, searchDrivers(config.Dpdk.PmdPath)...)

	for _, vdev := range config.Dpdk.Vdevs {
		argv = append(argv, "--vdev", vdev)
	}

	if err := dpdk.EalInit(argv); err != nil {
		return fmt.Errorf("dpdk.EalInit failed: %v", err)
	}

	// List all available slave lcores and sockets
	lcores := make(map[uint]lcore)
	master := dpdk.GetMasterLcore()
	sockets := make(map[uint]struct{})
	n := uint(0)
	for n < dpdk.MaxLcore {
		if n != master && dpdk.LcoreIsEnabled(n) {
			lcores[n] = lcore{false, ""}
			sockets[dpdk.LcoreToSocketId(n)] = struct{}{}
		}
		n++
	}
	Logger.Printf("core list: %v", lcores)

	var defpool *dpdk.MemPool
	pools := make(map[int]*dpdk.MemPool)
	for sid := range sockets {
		pool, err := dpdk.PktMbufPoolCreate(MemPoolName, config.Dpdk.NumElements, config.Dpdk.CacheSize,
			C.sizeof_struct_lagopus_packet_metadata,
			dataRoomSize, int(sid))

		if err != nil {
			for _, p := range pools {
				p.Free()
			}
			return fmt.Errorf("dpdk.PktMbufPoolCreate failed: %v", err)
		}

		pools[int(sid)] = pool
		if defpool == nil {
			defpool = pool
			pools[dpdk.SOCKET_ID_ANY] = pool
		}
	}

	dpdkMgr.dr = &DpdkResource{
		Mempool:  defpool,
		Mempools: pools,
		lcores:   lcores,
	}
	dpdkMgr.dc = config.Dpdk

	return nil
}

// GetCurrentDPDKConfig returns the configuration used to initialize DPDK.
func GetCurrentDPDKConfig() DpdkConfig {
	dpdkMgr.mutex.Lock()
	defer dpdkMgr.mutex.Unlock()

	return dpdkMgr.dc
}

func (d DpdkConfig) String() string {
	return fmt.Sprintf("CoreMask: 0x%02x, CoreList: '%s', MemoryChannel: %d, PmdPath: %s, Vdevs: %s, #Elements: %d, CacheSize: %d",
		d.CoreMask, d.CoreList, d.MemoryChannel, d.PmdPath, d.Vdevs, d.NumElements, d.CacheSize)
}

// GetDpdkResource returns the current DpdkResource.
// Call this to get an access to memory pool allocated by Lagopus2.
func GetDpdkResource() *DpdkResource {
	dpdkMgr.mutex.Lock()
	defer dpdkMgr.mutex.Unlock()

	return dpdkMgr.dr
}

// AllocLcore returns vacant slave core. If there's no slave core left,
// returns an error.
// Make sure that any modules that requires slave core get allocation
// from this API. Otherwise, unexpected results are expected, e.g.
// deadlock.
func (d *DpdkResource) AllocLcore(name string) (uint, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	for i, c := range d.lcores {
		if !c.used {
			d.lcores[i] = lcore{true, name}
			return i, nil
		}
	}
	return 0, errors.New("No slave core available")

}

// ReserveLcore reserves given slave core, and returns true if succeed.
// Returns false otherwise.
// Make sure that any modules that requires slave core get allocation
// from this API. Otherwise, unexpected results are expected, e.g.
// deadlock.
func (d *DpdkResource) reserveLcore(name string, coreid uint) bool {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if c, ok := d.lcores[coreid]; ok && !c.used {
		d.lcores[coreid] = lcore{true, name}
		return true
	}

	return false
}

// FreeLcore frees given slave core for others to use.
func (d *DpdkResource) FreeLcore(coreid uint) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if c, ok := d.lcores[coreid]; ok && c.used {
		d.lcores[coreid] = lcore{false, ""}
	}
}

// ResearveAllSlaveLcores reserves all available slave lcores and returns
// a slice of core IDs reserved.
func (d *DpdkResource) reserveAllSlaveLcores(name string) []uint {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	var cores []uint

	for i, c := range d.lcores {
		if !c.used {
			d.lcores[i] = lcore{true, name}
			cores = append(cores, i)
		}
	}

	return cores
}

func (d *DpdkResource) String() string {
	str := ""
	for i, c := range d.lcores {
		str += fmt.Sprintf("%d: ", i)
		if c.used {
			str += c.usedby
		} else {
			str += "-"
		}
		str += ", "
	}
	return str
}

func init() {
	dpdkMgr = &dpdkManager{}
}
