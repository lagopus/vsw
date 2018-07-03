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
	"errors"
	"fmt"
	"regexp"
	"sync"

	"github.com/lagopus/vsw/utils/notifier"
)

const (
	tapModule    = "tap"
	hostifModule = "hostif"
)

// VRF represents Virtual Routing & Forwarding instance.
type VRF struct {
	name     string
	vifs     []*VIF
	router   *router
	tap      *BaseInstance
	hostif   *BaseInstance
	enabled  bool
	index    VRFIndex
	rd       uint64 // XXX: Do we need this?
	sadb     *SADatabases
	sadbOnce sync.Once
	*RoutingTable
}

type vrfManager struct {
	mutex     sync.Mutex
	byName    map[string]*VRF
	byIndex   [MaxVRF]*VRF
	nextIndex int
	rds       map[uint64]struct{}
	re        *regexp.Regexp
}

var vrfMgr *vrfManager

// should be called via assignIndex only
func (vm *vrfManager) findSlot(vrf *VRF, from, to int) bool {
	for i := from; i < to; i++ {
		if vm.byIndex[i] == nil {
			vrf.index = VRFIndex(i)
			vm.byIndex[i] = vrf
			vm.nextIndex = (i + 1) % len(vm.byIndex)
			return true
		}
	}
	return false
}

// should be called with lock held
func (vm *vrfManager) assignIndex(vrf *VRF) bool {
	// try from the nextIndex to the end
	if vm.findSlot(vrf, vm.nextIndex, len(vm.byIndex)) {
		return true
	}
	// try from the head to the nextIndex
	return vm.findSlot(vrf, 0, vm.nextIndex)
}

// should be called with lock held
func (vm *vrfManager) releaseIndex(vrf *VRF) {
	vm.byIndex[int(vrf.index)] = nil
}

// NewVRF creates a VRF instance.
func NewVRF(name string) (*VRF, error) {
	if !vrfMgr.re.MatchString(name) {
		return nil, fmt.Errorf("Invalid VRF name: '%v'", name)
	}

	vrfMgr.mutex.Lock()
	defer vrfMgr.mutex.Unlock()

	if _, exists := vrfMgr.byName[name]; exists {
		return nil, fmt.Errorf("VRF %s already exists", name)
	}

	vrf := &VRF{
		name:    name,
		enabled: false,
	}

	if !vrfMgr.assignIndex(vrf) {
		return nil, fmt.Errorf("No space left for new VRF")
	}

	// Create an ICMP processor
	var errMsg error
	tapName := name + "-tap"
	if tap, err := newInstance(tapModule, tapName, name); err != nil {
		errMsg = fmt.Errorf("ICMP handler instance creation failed: %v", err)
		goto error1
	} else {
		vrf.tap = tap
	}

	// Craete a router
	if router, err := newRouter(vrf, name); err != nil {
		errMsg = fmt.Errorf("Router instance creation failed: %v", err)
		goto error2
	} else {
		vrf.router = router
	}

	// Forward all IP packets to the ICMP processor
	if err := vrf.router.connect(vrf.tap.Input(), MATCH_IPV4_DST_SELF, nil); err != nil {
		errMsg = errors.New("Can't connect a router and an tap modules")
		goto error3
	}

	vrf.RoutingTable = newRoutingTable(vrf)
	vrfMgr.byName[name] = vrf

	noti.Notify(notifier.Add, vrf, nil)

	return vrf, nil

error3:
	vrf.router.free()
error2:
	vrf.tap.free()
error1:
	vrfMgr.releaseIndex(vrf)
	return nil, errMsg
}

func (v *VRF) Free() {
	vrfMgr.mutex.Lock()
	defer vrfMgr.mutex.Unlock()

	vifs := append([]*VIF(nil), v.vifs...)
	for _, vif := range vifs {
		v.DeleteVIF(vif)
	}

	v.router.disconnect(MATCH_IPV4_DST_SELF, nil)
	v.tap.free()
	v.router.free()
	delete(vrfMgr.byName, v.name)
	vrfMgr.releaseIndex(v)

	if v.rd != 0 {
		delete(vrfMgr.rds, v.rd)
	}

	noti.Notify(notifier.Delete, v, nil)
}

func (v *VRF) baseInstance() *BaseInstance {
	return v.router.base
}

func (v *VRF) IsEnabled() bool {
	return v.enabled
}

func (v *VRF) Enable() error {
	if !v.enabled {
		if err := v.tap.enable(); err != nil {
			return err
		}
		if err := v.router.enable(); err != nil {
			v.tap.disable()
			return err
		}
		v.enabled = true
	}
	return nil
}

func (v *VRF) Disable() {
	if v.enabled {
		v.router.disable()
		v.tap.disable()
		v.enabled = false
	}
}

// Name returns the name of the VRF.
func (v *VRF) Name() string {
	return v.name
}

func (v *VRF) String() string {
	return v.name
}

// Index returns a unique identifier of the VRF.
func (v *VRF) Index() VRFIndex {
	return v.index
}

// SetRD sets the route distinguisher of thr VRF.
func (v *VRF) SetRD(rd uint64) error {
	vrfMgr.mutex.Lock()
	defer vrfMgr.mutex.Unlock()

	oldrd := v.rd

	if _, exists := vrfMgr.rds[rd]; exists {
		return fmt.Errorf("VRF RD %d already exists", rd)
	}

	v.rd = rd
	vrfMgr.rds[rd] = struct{}{}

	if oldrd != 0 {
		delete(vrfMgr.rds, oldrd)
	}

	return nil
}

// RD returns the route distinguisher of the VRF.
func (v *VRF) RD() uint64 {
	return v.rd
}

func (v *VRF) AddVIF(vif *VIF) error {
	var err error

	if err = vif.setVRF(v); err != nil {
		return err
	}

	if err = v.router.addVIF(vif); err != nil {
		goto error1
	}

	// ICMP -> VIF (If not Tunnel)
	if vif.Tunnel() == nil {
		if err = v.tap.connect(vif.Outbound(), MATCH_OUT_VIF, vif); err != nil {
			goto error2
		}
	}

	// VIF -> router (DST_SELF)
	if err = vif.connect(v.router.input(), MATCH_ETH_DST_SELF, nil); err != nil {
		goto error3
	}

	// VIF -> router (broadcast)
	if err = vif.connect(v.router.input(), MATCH_ETH_DST_BC, nil); err != nil {
		goto error4
	}

	// VIF -> router (multicast)
	if err = vif.connect(v.router.input(), MATCH_ETH_DST_MC, nil); err != nil {
		goto error5
	}

	v.vifs = append(v.vifs, vif)

	// TUN/TAP for the VIF will be created
	noti.Notify(notifier.Add, v, vif)

	return nil

error5:
	vif.disconnect(MATCH_ETH_DST_BC, vif)
error4:
	vif.disconnect(MATCH_ETH_DST_SELF, vif)
error3:
	v.tap.disconnect(MATCH_OUT_VIF, vif)
error2:
	v.router.deleteVIF(vif)
error1:
	vif.setVRF(nil)
	return err
}

func (v *VRF) DeleteVIF(vif *VIF) error {
	for n, tv := range v.vifs {
		if tv == vif {
			v.tap.disconnect(MATCH_OUT_VIF, vif)
			vif.disconnect(MATCH_ETH_DST_SELF, nil)
			vif.disconnect(MATCH_ETH_DST_BC, nil)
			vif.disconnect(MATCH_ETH_DST_MC, nil)
			vif.setVRF(nil)
			v.router.deleteVIF(vif)

			l := len(v.vifs) - 1
			v.vifs[n] = v.vifs[l]
			v.vifs[l] = nil
			v.vifs = v.vifs[:l]

			//  TUN/TAP for the VIF will be deleted
			noti.Notify(notifier.Delete, v, vif)

			return nil
		}
	}
	return fmt.Errorf("Can't find %v in the VRF.", vif)
}

// VIF returns a slice of Vif Indices in the VRF.
func (v *VRF) VIF() []*VIF {
	vifs := make([]*VIF, len(v.vifs))
	copy(vifs, v.vifs)
	return vifs
}

// Dump returns descriptive information about the VRF
func (v *VRF) Dump() string {
	str := fmt.Sprintf("%s: RD=%d. %d VIF(s):", v.name, v.rd, len(v.vifs))
	for _, vif := range v.vifs {
		str += fmt.Sprintf(" %v", vif)
	}
	if v.sadb != nil {
		sad := v.sadb.SAD()
		str += fmt.Sprintf("\n%d SAD", len(sad))
		for _, sa := range sad {
			str += fmt.Sprintf("\n\t%v", sa)
		}

		spd := v.sadb.SPD()
		str += fmt.Sprintf("\n%d SPD", len(spd))
		for _, sp := range spd {
			str += fmt.Sprintf("\n\t%v", sp)
		}
	}
	return str
}

// SADatabases returns SADatabases associated with the VRF.
func (v *VRF) SADatabases() *SADatabases {
	v.sadbOnce.Do(func() {
		v.sadb = newSADatabases(v)
	})
	return v.sadb
}

// GetAllVRF returns a slice of available VRF.
func GetAllVRF() []*VRF {
	vrfMgr.mutex.Lock()
	defer vrfMgr.mutex.Unlock()

	v := make([]*VRF, len(vrfMgr.byName))
	n := 0
	for _, vrf := range vrfMgr.byName {
		v[n] = vrf
		n++
	}
	return v
}

// GetVRFByName returns a VRF with the given name.
func GetVRFByName(name string) *VRF {
	vrfMgr.mutex.Lock()
	defer vrfMgr.mutex.Unlock()

	return vrfMgr.byName[name]
}

// GetVRFByIndex returns a VRF with the given index.
func GetVRFByIndex(index VRFIndex) *VRF {
	vrfMgr.mutex.Lock()
	defer vrfMgr.mutex.Unlock()

	return vrfMgr.byIndex[int(index)]
}

func init() {
	vrfMgr = &vrfManager{
		byName: make(map[string]*VRF),
		rds:    make(map[uint64]struct{}),
		re:     regexp.MustCompile(`^vrf\d+$`),
	}
}
