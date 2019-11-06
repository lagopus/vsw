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

package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"

	pb "github.com/coreswitch/openconfigd/proto"
	"github.com/lagopus/vsw/vswitch"
	vlog "github.com/lagopus/vsw/vswitch/log"
)

const (
	DriverDPDK             = "ethdev"
	DriverRIF              = "rif"
	DriverTunnel           = "tunnel"
	DefaultOpenconfigdHost = "localhost"
	DefaultOpenconfigdPort = uint16(2650)
	DefaultListenPort      = uint16(2653)
)

const configAgentStr = "config"

type ConfigAgent struct {
	subscribePaths [][]string
	ocdConn        *connect
	server         *Server

	setParser    *parser
	deleteParser *parser
	oc           *openconfig
	updatedNI    map[*ni]struct{}
	updatedIF    map[*iface]struct{}
	deletedNI    map[*deletedNI]struct{}
	deletedIF    map[*deletedIface]struct{}
	pendingTIF   map[string][]interface{}
	Setting      ocdSetting `toml:"openconfig"`

	iface map[string]*vswitch.Interface
	vif   map[string]*vswitch.VIF
	vrf   map[string]*vswitch.VRF
	vsi   map[string]*vswitch.VSI
}

type ocdSetting struct {
	Server string `toml:"server_host"` // OpenConfigd Server Host
	Port   uint16 `toml:"server_port"` // OpenConfigd Server Port #
	Listen uint16 `toml:"listen_port"` // Show server listen port number
	DryRun bool   `toml:"dry_run"`     // Dry Run
}

var log = vswitch.Logger

//
// configuration methods for instances
//
func (c *ConfigAgent) getInterfaceInstance(i *iface) (*vswitch.Interface, error) {
	if iface, ok := c.iface[i.name]; ok {
		return iface, nil
	}

	// Not enough info yet
	if i.driver == DRV_UNKNOWN {
		return nil, errors.New("Driver not set")
	}

	if i.iftype == IF_UNKNOWN {
		return nil, errors.New("Interface type not set")
	}

	var private interface{}
	driverName := DriverDPDK

	switch i.driver {
	case DRV_DPDK:
		// DPDK driver requires device info
		if i.device != "" {
			private = i.device
		} else {
			return nil, errors.New("Device info not set for DPDK driver type")
		}

	case DRV_LOCAL:
		switch i.iftype {
		case IF_ETHERNETCSMACD:
			driverName = DriverRIF

		case IF_TUNNEL:
			if i.tunnel != nil {
				// L2 Tunnel requires backend VRF
				vrf, ok := c.vrf[i.tunnel.vrf]
				if !ok {
					c.pendingTIF[i.tunnel.vrf] = append(c.pendingTIF[i.tunnel.vrf], i)
					return nil, fmt.Errorf("VRF %s, required for a tunnel, is not ready yet.",
						i.tunnel.vrf)
				}

				t, err := vswitch.NewL2Tunnel(i.tunnel.em)
				if err != nil {
					return nil, fmt.Errorf("L2 Tunnel config err: %v", err)
				}

				if err := t.SetTOS(uint8(i.tunnel.tos)); err != nil {
					return nil, fmt.Errorf("L2 Tunnel config err: %v", err)
				}

				if err := t.SetVNI(i.tunnel.vni); err != nil {
					return nil, fmt.Errorf("L2 Tunnel config err: %v", err)
				}

				t.SetAddressType(i.tunnel.af)
				t.SetHopLimit(i.tunnel.hl)
				t.SetVRF(vrf)
				t.SetLocalAddress(i.tunnel.local)
				t.SetRemoteAddresses(i.tunnel.remotes)

				private = t
			}
			driverName = DriverTunnel
		}
	}

	iface, err := vswitch.NewInterface(driverName, i.name, private)
	if err != nil {
		return nil, fmt.Errorf("Can't create New Interface: %v", err)
	}
	c.iface[i.name] = iface
	return iface, nil
}

func (c *ConfigAgent) getVIFInstance(i *vswitch.Interface, s *subiface) (*vswitch.VIF, error) {
	if vif, ok := c.vif[s.name]; ok {
		return vif, nil
	}

	var vif *vswitch.VIF
	var err error
	if s.tunnel == nil {
		vif, err = i.NewVIF(s.id)
	} else {
		var vrf *vswitch.VRF
		if s.tunnel.vrf != "" {
			v, ok := c.vrf[s.tunnel.vrf]
			if !ok {
				c.pendingTIF[s.tunnel.vrf] = append(c.pendingTIF[s.tunnel.vrf], s)
				return nil, fmt.Errorf("VRF %s, required for a tunnel, is not ready yet.", vrf)
			}
			vrf = v
		}

		t, err := vswitch.NewL3Tunnel(s.tunnel.em)
		if err != nil {
			return nil, fmt.Errorf("L3 Tunnel config err: %v", err)
		}

		if err := t.SetTOS(int8(s.tunnel.tos)); err != nil {
			return nil, fmt.Errorf("L3 Tunnel config err: %v", err)
		}

		t.SetAddressType(s.tunnel.af)
		t.SetHopLimit(s.tunnel.hl)
		t.SetVRF(vrf)
		t.SetLocalAddress(s.tunnel.local)
		t.SetRemoteAddresses(s.tunnel.remotes)
		t.SetSecurity(s.tunnel.sec)

		vif, err = i.NewTunnel(s.id, t)
	}
	if err != nil {
		return nil, fmt.Errorf("Can't create New VIF: %v", err)
	}

	c.vif[s.name] = vif
	return vif, nil
}

func (c *ConfigAgent) processSetSubinterfaceCmd(iface *vswitch.Interface, s *subiface, vids map[vswitch.VID]struct{}, i *iface) error {
	vif, err := c.getVIFInstance(iface, s)
	if err != nil {
		return err
	}

	// Set VID
	if s.vid != vif.VID() {
		if err := vif.SetVID(s.vid); err != nil {
			s.vid = vif.VID()
			log.Err("Can't set VID for %v (rolling back to %d): %v", s.name, s.vid, err)
		}
	}

	// Update IPAddress
	for _, ip := range s.ipaddr {
		vif.AddIPAddr(ip.ip)

		// There is no setting of VRRP
		if ip.vrrp == nil {
			continue
		}
		for _, vg := range ip.vrrp {
			if err := vif.AddVRRPGroup(ip.ip, vg); err != nil {
				log.Err("Can'n add VRRPGroup: %v, %v, %v", ip, vg, err)
			}
		}
	}

	// Configure NAPT
	if n := s.napt; n != nil {
		napt := vif.NAPT()

		if napt == nil {
			if n, err := vif.PrepareNAPT(); err == nil {
				napt = n
			} else {
				return err
			}
		}

		if !n.enabled {
			if err := napt.Disable(); err != nil {
				return err
			}
		}

		if napt.MaximumEntries() != n.maximumEntries {
			if err := napt.SetMaximumEntries(n.maximumEntries); err != nil {
				return err
			}
		}

		if napt.AgingTime() != n.agingTime {
			if err := napt.SetAgingTime(n.agingTime); err != nil {
				return err
			}
		}

		if !napt.PortRange().Equal(n.portRange) {
			if err := napt.SetPortRange(n.portRange); err != nil {
				return err
			}
		}

		if !napt.Address().Equal(n.address) {
			if err := napt.SetAddress(n.address); err != nil {
				return err
			}
		}

		if n.enabled {
			if err := napt.Enable(); err != nil {
				return err
			}
		}
	}

	// Enable
	if s.enabled {
		if err := vif.Enable(); err != nil {
			return fmt.Errorf("Can't enable VIF: %v", err)
		}
	} else {
		vif.Disable()
	}

	// Check if the VIF is associated with any NI
	for name := range s.ni {
		if vsi, ok := c.vsi[name]; ok {
			if err := vsi.AddVIF(vif); err != nil {
				log.Err("Can't add VIF %s to VSI %s: %v", vif.Name(), name, err)
			}
		}
	}
	for name := range s.ni {
		if vrf, ok := c.vrf[name]; ok {
			if err := vrf.AddVIF(vif); err != nil {
				log.Err("Can't add VIF %s to VRF %s: %v", vif.Name(), name, err)
			}
		}
	}

	return nil
}

func (c *ConfigAgent) processSetInterfaceCmd(i *iface) error {
	iface, err := c.getInterfaceInstance(i)
	if err != nil {
		return err
	}

	// Update interface

	// Update MAC
	if i.mac != nil && bytes.Compare(i.mac, iface.MACAddress()) != 0 {
		if err := iface.SetMACAddress(i.mac); err != nil {
			i.mac = iface.MACAddress()
			log.Err("Setting MAC for %s failed (rolling back to %v): %v", i.name, i.mac, err)
		}
	}

	// Update MTU
	if i.mtu != 0 && i.mtu != vswitch.InvalidMTU && i.mtu != iface.MTU() {
		if err := iface.SetMTU(i.mtu); err != nil {
			i.mtu = iface.MTU()
			log.Err("Setting MTU for %s failed (rolling back to %v): %v", i.name, i.mtu, err)
		}
	}

	// Update VLAN Mode
	if i.ifmode != iface.InterfaceMode() {
		if err := iface.SetInterfaceMode(i.ifmode); err != nil {
			i.ifmode = iface.InterfaceMode()
			log.Err("Setting InterfaceMode for %s failed (rolling back to %v): %v", i.name, i.ifmode, err)
		}
	}

	// Add missing VID
	// We delete unused VID after updating subinterfaces
	vids := make(map[vswitch.VID]struct{})
	for _, vid := range iface.VID() {
		vids[vid] = struct{}{}
	}
	for vid := range i.vids {
		if _, ok := vids[vid]; !ok {
			iface.AddVID(vid)
		}
	}

	// Update subinterfaces
	for _, s := range i.subs {
		if err := c.processSetSubinterfaceCmd(iface, s, vids, i); err != nil {
			return fmt.Errorf("VIF %s configuration failed: %v", s.name, err)
		}
	}

	// Delete unused VID
	for vid := range vids {
		if _, ok := i.vids[vid]; !ok {
			iface.DeleteVID(vid)
		}
	}

	// Change enable status
	if i.enabled {
		if err := iface.Enable(); err != nil {
			return fmt.Errorf("Can't enable interface: %v", err)
		}
	} else {
		iface.Disable()
	}
	return nil
}

type networkInstance interface {
	AddVIF(*vswitch.VIF) error
	DeleteVIF(*vswitch.VIF) error
	Disable()
	Free()
	VIF() []*vswitch.VIF
	String() string
}

func setVIFToNI(ni *ni, vsw networkInstance) {
	// Add VIF
	for name := range ni.vifs {
		if vif := vswitch.GetVIFByName(name); vif != nil {
			if err := vsw.AddVIF(vif); err != nil {
				log.Err("Can't add VIF %s to %s: %v", name, ni.name, err)
			}
		}
	}

	// Delete VIF
	for _, vif := range vsw.VIF() {
		if _, ok := ni.vifs[vif.Name()]; !ok {
			vsw.DeleteVIF(vif)
		}
	}
}

func (c *ConfigAgent) getVSI(ni *ni) (*vswitch.VSI, error) {
	if vsi, ok := c.vsi[ni.name]; ok {
		return vsi, nil
	}

	var vsi *vswitch.VSI
	var err error
	if ni.niType == NI_L2VSI {
		if vsi, err = vswitch.NewVSI(ni.name); err != nil {
			return nil, fmt.Errorf("Can't create New VSI: %v\n", err)
		}
	} else {
		if vsi, err = vswitch.NewMAT(ni.name); err != nil {
			return nil, fmt.Errorf("Can't create New MAT: %v", err)
		}
	}

	c.vsi[ni.name] = vsi
	return vsi, nil
}

func (c *ConfigAgent) processSetVSICmd(ni *ni) error {
	vsi, err := c.getVSI(ni)
	if err != nil {
		return err
	}

	// Add and Enable/Disable VID
	for vid, state := range ni.vlans {
		if err := vsi.AddVID(vid); err != nil {
			return fmt.Errorf("Can't add VID %d: %v", vid, err)
		}
		if state {
			if err := vsi.EnableVID(vid); err != nil {
				return fmt.Errorf("Can't enable VID %d: %v", vid, err)
			}
		} else {
			if err := vsi.DisableVID(vid); err != nil {
				return fmt.Errorf("Can't disable VID %d: %v", vid, err)
			}
		}
	}

	// Delete unused VID
	for vid := range vsi.VID() {
		if _, ok := ni.vlans[vid]; !ok {
			vsi.DeleteVID(vid)
		}
	}

	// Update VIF
	setVIFToNI(ni, vsi)

	// Set FDB Config
	if ni.macLearning != vsi.MACLearning() {
		if ni.macLearning {
			vsi.EnableMACLearning()
		} else {
			vsi.DisableMACLearning()
		}
	}

	if ni.macAgingTime != vsi.MACAgingTime() {
		if err := vsi.SetMACAgingTime(ni.macAgingTime); err != nil {
			ni.macAgingTime = vsi.MACAgingTime()
			return fmt.Errorf("Setting MAC aging time failed. Falling back to %d: %v", ni.macAgingTime, err)
		}
	}

	if ni.maximumEntries != vsi.MaximumEntries() {
		if err := vsi.SetMaximumEntries(ni.maximumEntries); err != nil {
			ni.maximumEntries = vsi.MaximumEntries()
			return fmt.Errorf("Setting max entries failed. Falling back to %d: %v", ni.maximumEntries, err)
		}
	}

	// Enable/Disable
	if ni.enabled {
		if err := vsi.Enable(); err != nil {
			return fmt.Errorf("Can't enable VSI %v: %v", ni.name, err)
		}
	} else {
		vsi.Disable()
	}

	return nil
}

func (c *ConfigAgent) getVRF(ni *ni) (*vswitch.VRF, error) {
	if vrf, ok := c.vrf[ni.name]; ok {
		return vrf, nil
	}

	vrf, err := vswitch.NewVRF(ni.name)
	if err != nil {
		return nil, fmt.Errorf("Can't create New VRF: %v", err)
	}

	c.vrf[ni.name] = vrf
	return vrf, nil
}

func (c *ConfigAgent) processSetVRFCmd(ni *ni) error {
	vrf, err := c.getVRF(ni)
	if err != nil {
		return err
	}

	// XXX: AF ignored for now

	// Check pending tunnel
	if tifs, ok := c.pendingTIF[ni.name]; ok {
		for _, t := range tifs {
			switch v := t.(type) {
			case *iface:
				if err := c.processSetInterfaceCmd(v); err != nil {
					log.Err("Interface %s configuration failed: %v", v.name, err)
					continue
				}
			case *subiface:
				iface, err := c.getInterfaceInstance(v.iface)
				if err != nil {
					log.Err("Interface %s configuration failed: %v", v.iface.name, err)
					continue
				}
				if err := c.processSetSubinterfaceCmd(iface, v, nil, v.iface); err != nil {
					log.Err("VIF %s configuration failed: %v", v.name, err)
					continue
				}
			}
		}
		delete(c.pendingTIF, ni.name)
	}

	// Update VIF
	setVIFToNI(ni, vrf)

	// Update SAD
	if ni.sad != nil {
		sadb := vrf.SADatabases()
		for _, sa := range ni.sad {
			sadb.AddSADEntry(*sa)
		}

		for _, sa := range sadb.SAD() {
			if _, ok := ni.sad[sa.SPI]; !ok {
				sadb.DeleteSADEntry(sa.SPI)
			}
		}
	}

	// Update SPD
	if ni.spd != nil {
		sadb := vrf.SADatabases()
		for _, sp := range ni.spd {
			sadb.AddSPDEntry(*sp)
		}

		for _, sp := range sadb.SPD() {
			if _, ok := ni.spd[sp.Name]; !ok {
				sadb.DeleteSPDEntry(sp.Name)
			}
		}
	}

	// Enable/Disable
	if ni.enabled {
		if err := vrf.Enable(); err != nil {
			return fmt.Errorf("Can't enable VRF: %v", err)
		}
	} else {
		vrf.Disable()
	}

	log.Debug(0, "> %v", vrf.Dump())

	return nil
}

func (c *ConfigAgent) configPBR(vrf *vswitch.VRF, name string, p *pe) error {
	if name == "" {
		return fmt.Errorf("Rule name is empty.")
	}

	var vif *vswitch.VIF
	if p.inInterface != "" {
		vif = vswitch.GetVIFByName(p.inInterface)
		if vif == nil {
			return fmt.Errorf("No such input VIF found for PBR entry: %s", p.inInterface)
		}
	}

	var sp vswitch.PortRange
	if p.srcPort != nil {
		sp = *p.srcPort
	}
	var dp vswitch.PortRange
	if p.dstPort != nil {
		dp = *p.dstPort
	}
	ft := vswitch.FiveTuple{
		SrcIP:   p.srcAddr,
		DstIP:   p.dstAddr,
		SrcPort: sp,
		DstPort: dp,
		Proto:   p.protocol,
	}
	pbr := &vswitch.PBREntry{
		FiveTuple: ft,
		Priority:  p.priority,
		InputVIF:  vif,
		NextHops:  make(map[string]vswitch.PBRNextHop),
	}

	// set nexthop
	for key, val := range p.nhs {
		nh := pbr.NextHops[key]

		// nexthop: output interface
		if val.outInterface != "" {
			out := vswitch.GetVIFByName(val.outInterface)
			if out == nil {
				return fmt.Errorf("output VRF not enabled.%s", val.outInterface)
			}
			nh.Dev = out
		}
		// nexthop: ni
		if val.nhNI != "" {
			vrf := vswitch.GetVRFByName(val.nhNI)
			if vrf == nil {
				return fmt.Errorf("VRF not enabled.%s", val.nhNI)
			}
			nh.Dev = vrf
		}
		nh.Gw = val.addr.IP
		nh.Weight = int(val.weight)
		nh.Action = val.action

		if v, exists := pbr.NextHops[key]; exists {
			if !v.Equal(nh) {
				// Overwrite if updated
				pbr.NextHops[name] = nh
			}
		} else {
			// New registration if not registered.
			pbr.NextHops[name] = nh
		}
	}

	vrf.AddPBREntry(name, pbr)

	return nil
}

//
// delete command related
//
func (c *ConfigAgent) deleteInterface(iface *vswitch.Interface) {
	// delete config information
	for _, vif := range iface.VIF() {
		delete(c.vif, vif.String())
	}
	delete(c.iface, iface.String())

	iface.Free()
}

func (c *ConfigAgent) deleteSubiface(vif *vswitch.VIF) {
	// delete config information
	delete(c.vif, vif.String())

	vif.Free()
}

func deleteIPAddress(ipaddr vswitch.IPAddr, vif *vswitch.VIF) {
	if err := vif.DeleteIPAddr(ipaddr); err != nil {
		log.Err("Can't delete an ip address(%v) from %v: %v\n", ipaddr, vif, err)
	}
}

func deleteVRRPGroup(vgs *deletedVRRPGroups, ip vswitch.IPAddr, vif *vswitch.VIF) {
	for vrid, dvg := range vgs.vgs {
		// If virtual address is not specified, delete VRRPGroup itself.
		if dvg.self {
			if err := vif.DeleteVRRPGroup(ip, vrid); err != nil {
				log.Err("Can't delete an VRRPGroup(%v:%v): %v", ip, vrid, err)
			}
			continue
		}
		// If virtual address is specified,
		// get target VRRPGroup and delete virtual addresses.
		vg := vif.VRRPGroup(ip, vrid)
		if vg == nil {
			log.Err("VRRPGroup does not exist(%v:%v)", ip, vrid)
			continue
		}
		for _, addr := range dvg.vaddrs {
			vg.DeleteVirtualAddr(addr)
		}
	}
}

func deleteVIDFromInterface(vids []vswitch.VID, iface *vswitch.Interface) {
	for _, vid := range vids {
		if err := iface.DeleteVID(vid); err != nil {
			log.Err("VID %v deletion failed: %v\n", vid, err)
		}
	}
}

func (c *ConfigAgent) processDeleteInterfaceCmd(di *deletedIface) error {
	iface, ok := c.iface[di.name]
	if !ok {
		return errors.New("No such Interface")
	}

	if di.self {
		c.deleteInterface(iface)
		return nil
	}

	for _, s := range di.subs {
		vif, ok := c.vif[s.name]
		if !ok {
			log.Err("VIF %s deletion failed: No such VIF", s.name)
			continue
		}

		if s.self {
			c.deleteSubiface(vif)
			continue
		}

		for _, ipaddr := range s.ipaddr {
			deleteIPAddress(ipaddr, c.vif[s.name])
			delete(s.groups, ipaddr.IP.String())
		}

		for ipstr, vgs := range s.groups {
			ip := createIPAddr(net.ParseIP(ipstr), 32)
			deleteVRRPGroup(vgs, ip, vif)
		}
	}

	deleteVIDFromInterface(di.vids, iface)
	return nil
}

func (c *ConfigAgent) deleteVIFFromNI(vifs []string, vsw networkInstance) {
	for _, name := range vifs {
		if vif, ok := c.vif[name]; ok {
			if err := vsw.DeleteVIF(vif); err != nil {
				log.Err("Can't delete a VIF %v from %v: %v", name, vsw, err)
			}
		}
	}
}

func (c *ConfigAgent) deleteVSI(vsi *vswitch.VSI) {
	// delete config information
	delete(c.vsi, vsi.String())

	vsi.Free()
}

func deleteVIDFromVSI(vlans []vswitch.VID, vsi *vswitch.VSI) {
	for _, vid := range vlans {
		vsi.DeleteVID(vid)
	}
}

func (c *ConfigAgent) processDeleteVSICmd(dni *deletedNI) error {
	vsi, ok := c.vsi[dni.name]
	if !ok {
		return errors.New("No such VSI")
	}

	if dni.self {
		c.deleteVSI(vsi)
		return nil
	}

	c.deleteVIFFromNI(dni.vifs, vsi)

	deleteVIDFromVSI(dni.vlans, vsi)
	return nil
}

// Delete Tunnel interfaces that specify the VRF to be deleted as the destination.
func (c *ConfigAgent) deleteTunnel(vrf *vswitch.VRF) {
	// L2 tunnel
	for _, iface := range c.iface {
		if tun := iface.Tunnel(); tun == nil || tun.VRF() != vrf {
			continue
		}

		c.deleteInterface(iface)
	}
	// L3 tunnel
	for _, vif := range c.vif {
		if tun := vif.Tunnel(); tun == nil || tun.VRF() != vrf {
			continue
		}
		c.deleteSubiface(vif)
	}
}

func (c *ConfigAgent) deleteVRF(vrf *vswitch.VRF) {
	// delete config information
	delete(c.vrf, vrf.String())

	c.deleteTunnel(vrf)
	vrf.Free()
}

func deleteSADEntry(sad []uint32, vrf *vswitch.VRF) {
	for _, spi := range sad {
		vrf.SADatabases().DeleteSADEntry(spi)
	}
}

func deleteSPDEntry(spd []string, vrf *vswitch.VRF) {
	for _, name := range spd {
		vrf.SADatabases().DeleteSPDEntry(name)
	}
}

func (c *ConfigAgent) processDeleteVRFCmd(dni *deletedNI) error {
	vrf, ok := c.vrf[dni.name]
	if !ok {
		return errors.New("No such VRF")
	}

	if dni.self {
		c.deleteVRF(vrf)
		return nil
	}

	c.deleteVIFFromNI(dni.vifs, vrf)

	deleteSADEntry(dni.sad, vrf)
	deleteSPDEntry(dni.spd, vrf)
	return nil
}

func (c *ConfigAgent) clearDeleteConfs() {
	c.deletedNI = make(map[*deletedNI]struct{})
	c.deletedIF = make(map[*deletedIface]struct{})
	c.oc.dnis = make(map[string]*deletedNI)
	c.oc.difs = make(map[string]*deletedIface)
}

//
// control related
//
func (c *ConfigAgent) validate(configs []*pb.ConfigReply) bool {
	// TBD
	return true
}

func (c *ConfigAgent) commit(configs []*pb.ConfigReply) {
	for _, config := range configs {
		switch config.Type {
		case pb.ConfigType_SET:
			if i, err := c.setParser.parse(config.Path); err != nil {
				if pe, ok := err.(parserError); !ok || pe != noMatchingSyntaxError {
					log.Err("Error while parsing set command '%v': %v",
						config.Path, err)
				}
			} else {
				log.Debug(0, "set command parsed: %v", config.Path)
				switch v := i.(type) {
				case *iface:
					c.updatedIF[v] = struct{}{}
				case *ni:
					c.updatedNI[v] = struct{}{}
				}
			}
		case pb.ConfigType_DELETE:
			if i, err := c.deleteParser.parse(config.Path); err != nil {
				if pe, ok := err.(parserError); !ok || pe != noMatchingSyntaxError {
					log.Err("Error while parsing delete command'%v': %v",
						config.Path, err)
				}
			} else {
				log.Debug(0, "delete command parsed: %v", config.Path)
				switch v := i.(type) {
				case *deletedIface:
					c.deletedIF[v] = struct{}{}
				case *deletedNI:
					c.deletedNI[v] = struct{}{}
				}
			}
		}
	}
}

func (c *ConfigAgent) config() {
	// delete command
	for dni := range c.deletedNI {
		switch dni.niType {
		case NI_L2VSI:
			if err := c.processDeleteVSICmd(dni); err != nil {
				log.Err("VSI %s deletion failed: %v", dni.name, err)
			}

		case NI_L3VRF:
			if err := c.processDeleteVRFCmd(dni); err != nil {
				log.Err("VRF %s deletion failed: %v", dni.name, err)
			}
		}
	}

	for di := range c.deletedIF {
		if err := c.processDeleteInterfaceCmd(di); err != nil {
			log.Err("Interface %s deletion failed: %v", di.name, err)
		}
	}
	c.clearDeleteConfs()

	// set command
	for iface := range c.updatedIF {
		if err := c.processSetInterfaceCmd(iface); err != nil {
			log.Err("Interface %s configuration failed: %v", iface.name, err)
		}
	}

	// NOTE: we MUST connect VIF to VSI first. Not otherway around.
	for ni := range c.updatedNI {
		if ni.niType == NI_L3VRF {
			continue
		}
		if err := c.processSetVSICmd(ni); err != nil {
			log.Err("VSI %s configuration failed: %v", ni.name, err)
		}
	}

	for ni := range c.updatedNI {
		if ni.niType != NI_L3VRF {
			continue
		}
		if err := c.processSetVRFCmd(ni); err != nil {
			log.Err("VRF %s configuration failed: %v", ni.name, err)
		}
	}

	for ni := range c.updatedNI {
		for pname, pe := range ni.pbr {
			vrf, err := c.getVRF(ni)
			if err != nil {
				continue
			}
			if err := c.configPBR(vrf, pname, pe); err != nil {
				log.Err("configPBR(%s) failed: %v", pname, err)
				continue
			}
			delete(ni.pbr, pname)
		}
	}
}

// control controls received configuration message.
func (c *ConfigAgent) control() {
	var configs []*pb.ConfigReply // configurations that is received in a transaction

	for {
		recvConf, err := c.ocdConn.stream.Recv()
		if err != nil {
			log.Debug(0, "Receive error message: %v", err)
			return
		}

		switch recvConf.Type {
		case pb.ConfigType_VALIDATE_START, pb.ConfigType_COMMIT_START:
			configs = nil

		case pb.ConfigType_SET, pb.ConfigType_DELETE:
			configs = append(configs, recvConf)

		case pb.ConfigType_VALIDATE_END:
			log.Debug(0, "Validation Start")

			ct := pb.ConfigType_VALIDATE_SUCCESS
			if !c.validate(configs) {
				ct = pb.ConfigType_VALIDATE_FAILED
			}
			c.ocdConn.send(ct, nil)

			log.Debug(0, " Validation Done (%v)", ct)

		case pb.ConfigType_COMMIT_END:
			log.Debug(0, "Commit Start")

			c.commit(configs)
			c.updates()
			if !c.Setting.DryRun {
				c.config()
				log.Debug(0, "Commit Done")
			} else {
				log.Debug(0, "Commit Done (Dry Run)")
			}
			c.DumpConfig()

		default:
			log.Debug(0, "Unexecuted message received")
			continue
		}
	}
}

func (c *ConfigAgent) Enable() error {
	// Fetch openconfig related configuration
	vswitch.GetConfig().Decode(c)

	var err error
	c.ocdConn, err = getConnection(fmt.Sprintf("%s:%d", c.Setting.Server, c.Setting.Port))
	if err != nil {
		return log.Err("%v", err)
	}
	go c.control()

	// subscribe paths to OpenConfigd
	for _, p := range c.subscribePaths {
		c.ocdConn.send(pb.ConfigType_SUBSCRIBE, p)
	}
	// register show server
	if c.server, err = registerServer(c.Setting.Listen, c.ocdConn); err != nil {
		return log.Err("%v", err)
	}

	return nil
}

func (c *ConfigAgent) Disable() {
	if c.server != nil {
		c.server.unregisterServer()
	}
	if c.ocdConn != nil {
		c.ocdConn.free()
	}

	// TODO: We must free all created instances

	// clean infos
	c.oc.free()
}

func (c *ConfigAgent) String() string {
	return configAgentStr
}

func (c *ConfigAgent) updates() {
	log.Debug(0, "--- update ---\n")
	for id := range c.updatedNI {
		log.Debug(0, "Network Instance: %v\n", id)
		log.Debug(0, "-------------------\n")
	}

	for id := range c.updatedIF {
		log.Debug(0, "Interface: %v\n", id)
		log.Debug(0, "-------------------\n")
	}
	log.Debug(0, "--- delete ---\n")
	for v := range c.deletedNI {
		log.Debug(0, "Network Instance: %v\n", v)
		log.Debug(0, "--------------------\n")
	}
	for v := range c.deletedIF {
		log.Debug(0, "Interface: %v\n", v)
		log.Debug(0, "--------------------\n")
	}
	log.Debug(0, "--------------------\n")
}

func (c *ConfigAgent) DumpConfig() {
	for id, v := range c.oc.nis {
		log.Debug(0, "Network Instance: %v\n", id)
		log.Debug(0, "%v\n", v)
		log.Debug(0, "-------------------\n")
	}

	for id, v := range c.oc.ifs {
		log.Debug(0, "Interface: %v\n", id)
		log.Debug(0, "%v", v)
		log.Debug(0, "-------------------\n")
	}
}

func init() {
	if l, err := vlog.New(configAgentStr); err == nil {
		log = l
	} else {
		log.Fatalf("Can't create logger: %s", configAgentStr)
	}

	agent := &ConfigAgent{
		subscribePaths: [][]string{
			{"interfaces", "interface"},
			{"network-instances", "network-instance"},
		},

		iface: make(map[string]*vswitch.Interface),
		vif:   make(map[string]*vswitch.VIF),
		vsi:   make(map[string]*vswitch.VSI),
		vrf:   make(map[string]*vswitch.VRF),

		updatedNI:  make(map[*ni]struct{}),
		updatedIF:  make(map[*iface]struct{}),
		deletedNI:  make(map[*deletedNI]struct{}),
		deletedIF:  make(map[*deletedIface]struct{}),
		pendingTIF: make(map[string][]interface{}),

		Setting: ocdSetting{
			Server: DefaultOpenconfigdHost,
			Port:   DefaultOpenconfigdPort,
			Listen: DefaultListenPort,
		},
	}
	agent.oc = newOpenConfig(agent)

	agent.setParser = newOpenConfigParser(agent.oc, ocdcSetSyntax)
	agent.deleteParser = newOpenConfigParser(agent.oc, ocdcDeleteSyntax)
	vswitch.RegisterAgent(agent)
}
