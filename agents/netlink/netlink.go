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

// netlink is a Netlink Agent for Lagopus2
package netlink

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/lagopus/vsw/utils/notifier"
	"github.com/lagopus/vsw/vswitch"
	vlog "github.com/lagopus/vsw/vswitch/log"
	"github.com/vishvananda/netlink"
)

const agentName = "netlink"

var log = vswitch.Logger
var netlinkInstance *NetlinkAgent

type NetlinkAgent struct {
	vswch  chan notifier.Notification
	ruch   chan netlink.RouteUpdate
	nldone chan struct{}
	vrfs   map[string]*netlink.Vrf
	taps   map[string]*netlink.Tuntap
	links  map[int]vswitch.OutputDevice
	tables map[int]*vswitch.VRF
}

const rulePref = 1000

func enableIpForwarding(link string) error {
	path := "/proc/sys/net/ipv4/conf/" + link + "/forwarding"
	err := ioutil.WriteFile(path, []byte("1\n"), 0644)
	if err != nil {
		log.Fatalf("Netlink Agent: Can't enable IP forwarding on %s: %v", link, err)
	}
	return err
}

func (n *NetlinkAgent) addVRF(vrf *vswitch.VRF) {
	log.Printf("Netlink Agent: Adding VRF for %v", vrf.Name())

	var tableID int
	fmt.Sscanf(vrf.Name(), "vrf%d", &tableID)

	// Create VRF
	nv := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{
			Name:   vrf.Name(),
			TxQLen: 1000,
		},
		Table: uint32(tableID),
	}
	if err := netlink.LinkAdd(nv); err != nil {
		log.Fatalf("Netlink Agent: Adding VRF %s failed: %v", vrf.Name(), err)
		return
	}

	log.Printf("Netlink Agent: %s has LinkIndex %d", vrf.Name(), nv.Index)

	// Create Rules
	rule := netlink.NewRule()
	rule.IifName = vrf.Name()
	rule.Priority = rulePref
	rule.Table = tableID

	if err := netlink.RuleAdd(rule); err != nil {
		netlink.LinkDel(nv)
		log.Fatalf("Netlink Agent: Adding iif Rule to VRF %s failed: %v", vrf.Name(), err)
		return
	}

	rule.OifName = rule.IifName
	rule.IifName = ""

	if err := netlink.RuleAdd(rule); err != nil {
		netlink.LinkDel(nv)
		log.Fatalf("Netlink Agent: Adding oif Rule to VRF %s failed: %v", vrf.Name(), err)
		return
	}

	// Bring the Link Up
	if err := netlink.LinkSetUp(nv); err != nil {
		netlink.LinkDel(nv)
		log.Fatalf("Netlink Agent: Bringing up VRF %s failed: %v", vrf.Name(), err)
		return
	}

	// Enable forwarding
	if err := enableIpForwarding(vrf.Name()); err != nil {
		netlink.LinkDel(nv)
		return
	}

	n.vrfs[nv.LinkAttrs.Name] = nv
	n.tables[tableID] = vrf
	n.links[nv.LinkAttrs.Index] = vrf
}

func (n *NetlinkAgent) deleteRule(vrfName string) {
	// delete related rule
	rule := netlink.NewRule()
	rule.IifName = vrfName
	if err := netlink.RuleDel(rule); err != nil {
		log.Fatalf("Netlink Agent: Deleting Rule iif= %s failed: %v", vrfName, err)
	}
	rule.OifName = rule.IifName
	rule.IifName = ""
	if err := netlink.RuleDel(rule); err != nil {
		log.Fatalf("Netlink Agent: Deleting Rule oif= %s failed: %v", vrfName, err)
	}
}

func (n *NetlinkAgent) deleteVRF(vrf *vswitch.VRF) {
	if nv, ok := n.vrfs[vrf.Name()]; ok {
		netlink.LinkDel(nv)
		n.deleteRule(nv.LinkAttrs.Name)
		delete(n.vrfs, nv.LinkAttrs.Name)
		delete(n.tables, int(nv.Table))
	}
}

func (n *NetlinkAgent) deleteAllVRF() {
	for _, vrf := range n.tables {
		n.deleteVRF(vrf)
	}
}

func (n *NetlinkAgent) handleVRFNoti(t notifier.Type, vrf *vswitch.VRF) {
	switch t {
	case notifier.Add:
		n.addVRF(vrf)
	case notifier.Delete:
		n.deleteVRF(vrf)
	default:
		// nop
	}
}

// For TunTap
const (
	sizeOfIfReq = 40
	IFNAMSIZ    = 16
)

type ifReq struct {
	Name  [IFNAMSIZ]byte
	Flags uint16
	pad   [sizeOfIfReq - IFNAMSIZ - 2]byte
}

func (n *NetlinkAgent) addTap(vrf *vswitch.VRF, vif *vswitch.VIF) {
	log.Printf("Netlink Agent: Adding Tap for %v", vif)

	// Create a Tap
	nt := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{
			Name:   vif.Name(),
			TxQLen: 1000,
		},
		Mode:  netlink.TUNTAP_MODE_TAP,
		Flags: netlink.TUNTAP_ONE_QUEUE | netlink.TUNTAP_NO_PI,
	}

	if err := netlink.LinkAdd(nt); err != nil {
		log.Fatalf("Netlink Agent: Adding TAP %v failed: %v", vif, err)
		return
	}

	// Config MAC Address
	if err := netlink.LinkSetHardwareAddr(nt, vif.MACAddress()); err != nil {
		log.Fatalf("Netlink Agent: Setting TAP %v's MAC to %s failed: %v", vif, vif.MACAddress(), err)
	}

	// Set Master
	master := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: vrf.Name()}}
	if err := netlink.LinkSetMaster(nt, master); err != nil {
		log.Fatalf("Netlink Agent: Setting TAP %v's master to %s failed: %v", vif, vrf.Name(), err)
		netlink.LinkDel(nt)
		return
	}

	// Enable ARP
	if err := netlink.LinkSetARPOn(nt); err != nil {
		log.Fatalf("Netlink Agent: Enable ARP on TAP %v failed: %v", vif, err)
		netlink.LinkDel(nt)
		return
	}

	// Enable forwarding
	if err := enableIpForwarding(vif.Name()); err != nil {
		netlink.LinkDel(nt)
		return
	}

	// Open created Tap
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		log.Printf("Netlink Agent: Can't open TAP for %v", vif)
		netlink.LinkDel(nt)
		return
	}

	var req ifReq
	req.Flags = uint16(nt.Flags) | uint16(nt.Mode)
	copy(req.Name[:15], nt.Name)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		log.Printf("Netlink Agent: Getting TAP %v failed: %v", vif.Name(), errno)
		file.Close()
		//	netlink.LinkDel(nt)
		return
	}

	n.links[nt.Index] = vif
	n.taps[nt.LinkAttrs.Name] = nt

	n.configTapMTU(vif, vif.MTU())
	n.configTapLinkStatus(vif, vif.IsEnabled())

	for _, ipaddr := range vif.ListIPAddrs() {
		n.handleIPAddr(notifier.Add, vif, ipaddr)
	}

	if err := vif.SetTAP(file); err != nil {
		log.Printf("Netlink Agent: Setting TAP to VIF failed: %v", err)
	}
}

func (n *NetlinkAgent) deleteTap(vif *vswitch.VIF) {
	log.Printf("Netlink Agent: Deleting %v", vif)

	if tap, ok := n.taps[vif.Name()]; ok {
		vif.TAP().Close()
		netlink.LinkDel(tap)
		delete(n.taps, vif.Name())
		delete(n.links, tap.Index)
	}

	vif.SetTAP(nil)
}

func (n *NetlinkAgent) deleteAllTap() {
	for _, dev := range n.links {
		if vif, ok := dev.(*vswitch.VIF); ok {
			n.deleteTap(vif)
		}
	}
}

func (n *NetlinkAgent) configTapMTU(vif *vswitch.VIF, mtu vswitch.MTU) {
	if tap, ok := n.taps[vif.Name()]; ok {
		// MTU in the VSW is L2 MTU. We must subtract ether header size.
		mtu -= 14
		log.Printf("Netlink Agent: Configure MTU for %v to %d", vif, mtu)
		if err := netlink.LinkSetMTU(tap, int(mtu)); err != nil {
			log.Fatalf("Netlink Agent: Setting TAP %v's MTU to %d failed: %v", vif, mtu, err)
		}
	}
}

func (n *NetlinkAgent) configTapLinkStatus(vif *vswitch.VIF, enabled bool) {
	if tap, ok := n.taps[vif.Name()]; ok {
		log.Printf("Netlink Agent: Change link state of %v to %v", vif, enabled)
		if enabled {
			if err := netlink.LinkSetUp(tap); err != nil {
				log.Fatalf("Netlink Agent: Bringing up Tap %s failed: %v", vif, err)
			}
		} else {
			if err := netlink.LinkSetDown(tap); err != nil {
				log.Fatalf("Netlink Agent: Bringing down Tap %s failed: %v", vif, err)
			}
		}
	}
}

func (n *NetlinkAgent) configTapMAC(vif *vswitch.VIF, mac net.HardwareAddr) {
	if tap, ok := n.taps[vif.Name()]; ok {
		if err := netlink.LinkSetHardwareAddr(tap, vif.MACAddress()); err != nil {
			log.Fatalf("Netlink Agent: Setting TAP %v's MAC to %s failed: %v", vif, vif.MACAddress(), err)
		}
	}
}

func (n *NetlinkAgent) handleVIFNoti(t notifier.Type, vrf *vswitch.VRF, vif *vswitch.VIF) {
	switch t {
	case notifier.Add:
		n.addTap(vrf, vif)
	case notifier.Delete:
		n.deleteTap(vif)
	default:
		// nop
	}
}

func (n *NetlinkAgent) handleIPAddr(t notifier.Type, vif *vswitch.VIF, ip vswitch.IPAddr) {
	if tap, ok := n.taps[vif.Name()]; ok {
		addr := &netlink.Addr{IPNet: &net.IPNet{ip.IP, ip.Mask}}

		log.Printf("Netlink Agent: %s IP Address %s to TAP %s", t, ip, vif)

		switch t {
		case notifier.Add, notifier.Update:
			if err := netlink.AddrReplace(tap, addr); err != nil {
				log.Fatalf("Netlink Agent: Adding/Replacing IP Address %s to TAP %s failed: %v", ip, vif, err)
			}
		case notifier.Delete:
			if err := netlink.AddrDel(tap, addr); err != nil {
				log.Fatalf("Netlink Agent: Deleting IP Address %s to TAP %s failed: %v", ip, vif, err)
			}
		}
	}
}

func (n *NetlinkAgent) handleRouteUpdate(ru netlink.RouteUpdate) {
	vi, ok := n.tables[ru.Table]
	if !ok {
		log.Warning("Can't find VRF associated with table %d", ru.Table)
		return
	}

	entry := vswitch.Route{
		Dst:     ru.Dst,
		Src:     ru.Src,
		Gw:      ru.Gw,
		Metrics: ru.Priority,
		Scope:   vswitch.RouteScope(ru.Scope),
		Type:    vswitch.RouteType(ru.Route.Type),
	}

	if len(ru.MultiPath) == 0 {
		if dev, ok := n.links[ru.LinkIndex]; ok {
			entry.Dev = dev
		} else {
			log.Warning("Can't find VIF associated with link index %d", ru.LinkIndex)
			return
		}
	} else {
		for _, nhi := range ru.MultiPath {
			if dev, ok := n.links[nhi.LinkIndex]; ok {
				nh := &vswitch.Nexthop{
					Dev:    dev,
					Weight: nhi.Hops + 1,
					Gw:     nhi.Gw,
				}
				entry.Nexthops = append(entry.Nexthops, nh)
			} else {
				log.Warning("Can't find VIF associated with link index %d", ru.LinkIndex)
			}
		}
	}

	switch ru.Type {
	case syscall.RTM_NEWROUTE:
		if err := vi.AddEntry(entry); err != nil {
			log.Printf("Netlink Agent: Can't add a route entry for %v: %v (%v)", vi, entry, err)
		}
	case syscall.RTM_DELROUTE:
		if err := vi.DeleteEntry(entry); err != nil {
			log.Printf("Netlink Agent: Can't delete a route entry for %v: %v (%v)", vi, entry, err)
		}
	default:
		log.Printf("Unknown RouteUpdate type: %v", ru.Type)
	}
}

func (n *NetlinkAgent) listen() {
	for {
		select {
		case noti, ok := <-n.vswch:
			if !ok {
				return
			}
			log.Printf("Netlink Agent: VSW: %v\n", noti)

			if vif, ok := noti.Target.(*vswitch.VIF); ok {
				switch value := noti.Value.(type) {
				case nil:
					n.handleVIFNoti(noti.Type, nil, vif)

				case vswitch.MTU:
					if noti.Type == notifier.Update {
						n.configTapMTU(vif, value)
					}

				case vswitch.IPAddr:
					n.handleIPAddr(noti.Type, vif, value)

				case bool:
					if noti.Type == notifier.Update {
						n.configTapLinkStatus(vif, value)
					}

				case net.HardwareAddr:
					if noti.Type == notifier.Update {
						n.configTapMAC(vif, value)
					}

				default:
					log.Printf("Netlink Agent: Unexpectd value: %v\n", vif)
				}

			} else if vrf, ok := noti.Target.(*vswitch.VRF); ok {
				switch vif := noti.Value.(type) {
				case nil:
					n.handleVRFNoti(noti.Type, vrf)

				case *vswitch.VIF:
					n.handleVIFNoti(noti.Type, vrf, vif)

				case vswitch.Route:
					// Don't care. This should have came out from me.

				case *vswitch.PBREntry:
					// Don't care. We don't support PBR in netlink agent.

				default:
					log.Printf("Netlink Agent: Unexpectd value: %v\n", vif)
				}
			} else {
				log.Printf("Netlink Agent: Unexpectd target: %v\n", noti.Target)
			}

		case ru, ok := <-n.ruch:
			if !ok {
				return
			}
			log.Printf("Netlink Agent: RU: %v", ru)
			n.handleRouteUpdate(ru)

		}
	}
}

func (n *NetlinkAgent) Enable() error {
	// Initialize Netlink Agent
	n.ruch = make(chan netlink.RouteUpdate)
	n.nldone = make(chan struct{})
	n.vrfs = make(map[string]*netlink.Vrf)
	n.taps = make(map[string]*netlink.Tuntap)
	n.links = make(map[int]vswitch.OutputDevice)
	n.tables = make(map[int]*vswitch.VRF)

	// Listen to changes on VIF/VRF
	n.vswch = vswitch.GetNotifier().Listen()

	if err := netlink.RouteSubscribe(n.ruch, n.nldone); err != nil {
		return fmt.Errorf("Netlink Agent: Can't receive route update: %v", err)
	}

	go func() {
		n.listen()
	}()

	return nil
}

func (n *NetlinkAgent) Disable() {
	n.deleteAllVRF()
	n.deleteAllTap()
	vswitch.GetNotifier().Close(n.vswch)

	// Clean ups
	close(n.nldone)
	close(n.ruch)
	n.vrfs = nil
	n.taps = nil
	n.links = nil
	n.tables = nil
}

func (n *NetlinkAgent) String() string {
	return agentName
}

func init() {
	if l, err := vlog.New(agentName); err == nil {
		log = l
	} else {
		log.Fatalf("Can't create logger: %s", agentName)
	}

	netlinkInstance = &NetlinkAgent{}
	vswitch.RegisterAgent(netlinkInstance)
}
