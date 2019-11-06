package vswitch

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

type VRID uint8

var VRRPMcastAddr = IPAddr{
	[]byte{224, 0, 0, 18},
	[]byte{0xff, 0xff, 0xff, 0xff},
}

type vrrpObserver interface {
	vrrpEnabled(vif *VIF)
	vrrpDisabled(vif *VIF)
}

type VRRP struct {
	groups   map[string]*VRRPGroups // key is ip address
	observer vrrpObserver
	vif      *VIF
	mutex    sync.Mutex
}

type VRRPGroups struct {
	vgs   map[VRID]*VRRPGroup
	mutex sync.Mutex
}

// A VRRPGroup is used to hold a VRRPGroups router group configuration.
// If it is updated with the same VRID, all will be overwritten.
type VRRPGroup struct {
	VirtualRouterId       VRID // virtual router id
	Priority              uint8
	Preempt               bool
	PreemptDelay          uint16
	AcceptMode            bool
	AdvertisementInterval uint16
	TrackInterface        string // interface name(same as name of vswitch.Interface)
	PriorityDecrement     uint8
	virtualAddrs          []net.IP // one or more virtual address.
}

// AddVirtualAddr adds a virtual ip address to VRRPGroup.
// Set when creating VRRPGroup.
func (vg *VRRPGroup) AddVirtualAddr(ip net.IP) {
	for _, addr := range vg.virtualAddrs {
		if addr.Equal(ip) {
			// Do not register duplicates
			return
		}
	}
	vg.virtualAddrs = append(vg.virtualAddrs, ip)
}

// DeleteVirtualAdd deletes a virtual ip address from VRRPGroup.
func (vg *VRRPGroup) DeleteVirtualAddr(ip net.IP) {
	for n, addr := range vg.virtualAddrs {
		if addr.Equal(ip) {
			vg.virtualAddrs[n] = vg.virtualAddrs[len(vg.virtualAddrs)-1]
			vg.virtualAddrs[len(vg.virtualAddrs)-1] = nil
			vg.virtualAddrs = vg.virtualAddrs[:len(vg.virtualAddrs)-1]
			return
		}
	}
}

func (vg *VRRPGroup) String() string {
	return fmt.Sprintf("vrid: %v, priority: %v, vaddr: %v", vg.VirtualRouterId, vg.Priority, vg.virtualAddrs)
}

func NewVRRPGroup(vrid VRID) *VRRPGroup {
	return &VRRPGroup{
		VirtualRouterId: vrid,
	}
}

// add adds VRRPGroup to VRRPGroups.
func (v *VRRPGroups) add(vg *VRRPGroup) {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	// vgs is created when addVRRPGroup()
	// TODO: Notification of changes to modules that reference VRRPGroup data.
	v.vgs[vg.VirtualRouterId] = vg
}

// delete deletes VRRPGroup entry.
func (v *VRRPGroups) delete(vrid VRID) {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	delete(v.vgs, vrid)
}

// newVRRP create a VRRP at the same time as VIF creation
func newVRRP(vif *VIF) *VRRP {
	if vif == nil {
		return nil
	}
	return &VRRP{
		vif: vif,
		// groups is generated only after VRRPGroup is set.
		// observer is set when vrf is set
	}
}

func (v *VRRP) enable() {
	// Notify that VRRP is enabled.
	if v.observer != nil {
		v.observer.vrrpEnabled(v.vif)
	}

	v.vif.IPAddrs.AddIPAddr(VRRPMcastAddr)
}

func (v *VRRP) disable() {
	if v.observer != nil {
		// Notify that VRRP is disabled,
		// and set observer to nil.
		v.observer.vrrpDisabled(v.vif)
	}

	v.vif.IPAddrs.DeleteIPAddr(VRRPMcastAddr)
}

// Notify enable/disable depending on the observer setting.
func (v *VRRP) setVRRPObserver(observer vrrpObserver) {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if v.groups != nil {
		if observer != nil {
			// v.observer shall have a valid observer
			// before calling enable.
			v.observer = observer
			v.enable()
		} else {
			v.disable()
		}
	}
	v.observer = observer
}

func (v *VRRP) isVRRPEnabled() bool {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	return (v.groups != nil)
}

// getVRRPGroups returns *VRRPGroups.
// This function should be called after protecting the mutex lock(v.mutex.Lock()).
func (v *VRRP) getVRRPGroups(ip IPAddr) *VRRPGroups {
	if v.groups == nil {
		return nil
	}

	return v.groups[ip.IP.String()]
}

// AddVRRPGroup adds a VRRPGroup to VRRPGroups of specified ip
// VRRPGroup member changes are overwritten because the updated vg is passed
// In the future, only the changes will be updated
func (v *VRRP) AddVRRPGroup(ip IPAddr, vg *VRRPGroup) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if vg == nil {
		return errors.New("VRRPGroup data is nil.")
	}

	isFirst := false
	if v.groups == nil {
		v.groups = make(map[string]*VRRPGroups)
		isFirst = true
	}

	// If there is no VRRPGroups to add VRRPGroup,
	// create VRRPGroups and add to VRRP
	vgs := v.getVRRPGroups(ip)
	if vgs == nil {
		vgs = &VRRPGroups{vgs: make(map[VRID]*VRRPGroup)}
		v.groups[ip.IP.String()] = vgs
	}
	vgs.add(vg)

	// After VRRPGroup registration,
	// notify vrf only for the first time.
	if isFirst {
		v.enable()
	}
	return nil
}

// DeleteVRRPGroup deletes an VRRPGroup from VRRPGroups by the ip and the vrid
func (v *VRRP) DeleteVRRPGroup(ip IPAddr, vrid VRID) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	vgs := v.getVRRPGroups(ip)
	if vgs == nil {
		return fmt.Errorf("VRRPGroups does not exist: ip=%v", ip)
	}

	// Delete VRRPGroup from VRRPGroups
	vgs.delete(vrid)

	if len(vgs.vgs) == 0 {
		// If there is no VRRPGroup, VRRPGroups is not necessary
		delete(v.groups, ip.IP.String())

		if len(v.groups) == 0 {
			v.groups = nil
			v.disable()
		}
	}

	return nil
}

// listVRRPGroup returns a slice VRRPGroup currently set.
func (v *VRRP) listVRRPGroup(ip IPAddr) []*VRRPGroup {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	vgs := v.getVRRPGroups(ip)
	if vgs == nil {
		return nil
	}
	list := make([]*VRRPGroup, len(vgs.vgs))
	i := 0
	for _, vg := range vgs.vgs {
		list[i] = vg
		i++
	}
	return list
}

func (v *VRRP) VRRPGroup(ip IPAddr, vrid VRID) *VRRPGroup {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	vgs := v.getVRRPGroups(ip)
	if vgs == nil {
		return nil
	}

	return vgs.vgs[vrid]
}
