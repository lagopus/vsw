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

package config

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/lagopus/vsw/ocdc"
	"github.com/lagopus/vsw/vswitch"
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
	subscriber *ocdc.Subscriber
	p          *parser
	oc         *openconfig
	updatedNI  map[*ni]struct{}
	updatedIF  map[*iface]struct{}
	Setting    ocdSetting `toml:"openconfig"`

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

func (c *ConfigAgent) commit(configs []*ocdc.Config) {
	for _, config := range configs {
		if config.Type == ocdc.CT_Delete {
			log.Printf("%s: Delete Not Supported yet; Requested to delete %v",
				configAgentStr, config.Path)
			continue
		}

		if i, err := c.p.parse(config.Path); err != nil {
			if pe, ok := err.(parserError); !ok || pe != noMatchingSyntaxError {
				log.Printf("%s: Error while parsing '%v': %v", configAgentStr, config.Path, err)
			}
		} else {
			log.Printf("%s: parsed: %v", configAgentStr, config.Path)
			switch v := i.(type) {
			case *iface:
				c.updatedIF[v] = struct{}{}
			case *ni:
				c.updatedNI[v] = struct{}{}
			}
		}
	}
}

func (c *ConfigAgent) validate(configs []*ocdc.Config) bool {
	// TBD
	return true
}

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

	// DPDK driver requires device info
	if i.driver == DRV_DPDK && i.device == "" {
		return nil, errors.New("Device info not set for DPDK driver type")
	}

	// Get appropriate module for each interface type
	driverName := DriverDPDK
	if i.driver == DRV_LOCAL {
		if i.iftype == IF_ETHERNETCSMACD {
			driverName = DriverRIF
		} else {
			driverName = DriverTunnel
		}
	}

	iface, err := vswitch.NewInterface(driverName, i.name, i.device)
	if err != nil {
		return nil, fmt.Errorf("Can't instantiate interface %v: %v", i.name, err)
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
		vif, err = i.NewTunnel(s.id, s.tunnel)
	}
	if err != nil {
		return nil, fmt.Errorf("Creating New VIF %v failed: %v", s.name, err)
	}

	c.vif[s.name] = vif
	return vif, err
}

func (c *ConfigAgent) configSubinterface(iface *vswitch.Interface, s *subiface, vids map[vswitch.VID]struct{}, i *iface) error {
	vif, err := c.getVIFInstance(iface, s)
	if err != nil {
		return err
	}

	// Set VID
	if s.vid != vif.VID() {
		if err := vif.SetVID(s.vid); err != nil {
			s.vid = vif.VID()
			log.Printf("%s: Can't set VID for %v (rolling back to %d): %v", configAgentStr, s.name, s.vid, err)
		}
	}

	// Update IPAddress
	for _, ip := range s.ipaddr {
		vif.AddIPAddr(ip)
	}
	for _, ip := range vif.ListIPAddrs() {
		if _, ok := s.ipaddr[ip.String()]; !ok {
			vif.DeleteIPAddr(ip)
		}
	}

	// Enable
	if s.enabled {
		if err := vif.Enable(); err != nil {
			return fmt.Errorf("Can't enable VIF %v: %v", s.name, err)
		}
	} else {
		vif.Disable()
	}

	// Check if the VIF is associated with any NI
	// NOTE: we MUST connect VIF to VSI first. Not otherway around.
	for name := range s.ni {
		if vsi, ok := c.vsi[name]; ok {
			vsi.AddVIF(vif)
		}
	}
	for name := range s.ni {
		if vrf, ok := c.vrf[name]; ok {
			vrf.AddVIF(vif)
		}
	}

	return nil
}

func (c *ConfigAgent) configInterface(i *iface) error {
	iface, err := c.getInterfaceInstance(i)
	if err != nil {
		return err
	}

	// Update interface

	// Update MAC
	if i.mac != nil && bytes.Compare(i.mac, iface.MACAddress()) != 0 {
		if err := iface.SetMACAddress(i.mac); err != nil {
			i.mac = iface.MACAddress()
			log.Printf("%s: Setting MAC for %s failed (rolling back to %v): %v", configAgentStr, i.name, i.mac, err)
		}
	}

	// Update MTU
	if i.mtu != 0 && i.mtu != vswitch.InvalidMTU && i.mtu != iface.MTU() {
		if err := iface.SetMTU(i.mtu); err != nil {
			i.mtu = iface.MTU()
			log.Printf("%s: Setting MTU for %s failed (rolling back to %v): %v", configAgentStr, i.name, i.mtu, err)
		}
	}

	// Update VLAN Mode
	if i.ifmode != iface.InterfaceMode() {
		if err := iface.SetInterfaceMode(i.ifmode); err != nil {
			i.ifmode = iface.InterfaceMode()
			log.Printf("%s: Setting InterfaceMode for %s failed (rolling back to %v): %v", configAgentStr, i.name, i.ifmode, err)
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
		if err := c.configSubinterface(iface, s, vids, i); err != nil {
			return err
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
			return fmt.Errorf("Can't enable interface %v: %v", i.name, err)
		}
	} else {
		iface.Disable()
	}
	return nil
}

type networkInstance interface {
	AddVIF(*vswitch.VIF) error
	DeleteVIF(*vswitch.VIF) error
	VIF() []*vswitch.VIF
}

func configVswitchNI(ni *ni, vsw networkInstance) error {
	// Add VIF
	for name := range ni.vifs {
		if vif := vswitch.GetVIFByName(name); vif != nil {
			if err := vsw.AddVIF(vif); err != nil {
				return fmt.Errorf("Adding VIF %s to %s failed: %v", name, ni.name, err)
			}
		}
	}

	// Delete VIF
	for _, vif := range vsw.VIF() {
		if _, ok := ni.vifs[vif.Name()]; !ok {
			vsw.DeleteVIF(vif)
		}
	}

	return nil
}

func (c *ConfigAgent) getVSI(ni *ni) (*vswitch.VSI, error) {
	if vsi, ok := c.vsi[ni.name]; ok {
		return vsi, nil
	}

	var vsi *vswitch.VSI
	var err error
	if ni.niType == NI_L2VSI {
		vsi, err = vswitch.NewVSI(ni.name)
	} else {
		vsi, err = vswitch.NewMAT(ni.name)
	}
	if err != nil {
		return nil, err
	}

	c.vsi[ni.name] = vsi
	return vsi, nil
}

func (c *ConfigAgent) configVSI(ni *ni) error {
	vsi, err := c.getVSI(ni)
	if err != nil {
		return err
	}

	// Add and Enable/Disable VID
	for vid, state := range ni.vlans {
		if err := vsi.AddVID(vid); err != nil {
			return fmt.Errorf("Adding VID %d to %s failed: %v", vid, ni.name, err)
		}
		if state {
			if err := vsi.EnableVID(vid); err != nil {
				return fmt.Errorf("Enabling VID %d on %s failed: %v", vid, ni.name, err)
			}
		} else {
			if err := vsi.DisableVID(vid); err != nil {
				return fmt.Errorf("Disabling VID %d on %s failed: %v", vid, ni.name, err)
			}
		}
	}

	// Delete unused VID
	for _, vid := range vsi.VID() {
		if _, ok := ni.vlans[vid]; !ok {
			vsi.DeleteVID(vid)
		}
	}

	// Update VIF
	configVswitchNI(ni, vsi)

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
		return nil, err
	}

	c.vrf[ni.name] = vrf
	return vrf, nil
}

func (c *ConfigAgent) configVRF(ni *ni) error {
	vrf, err := c.getVRF(ni)
	if err != nil {
		return err
	}

	// XXX: AF ignored for now

	// Update VIF
	configVswitchNI(ni, vrf)

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
			return fmt.Errorf("Can't enable VRF %s: %v", ni.name, err)
		}
	} else {
		vrf.Disable()
	}

	fmt.Printf("> %v", vrf.Dump())

	return nil
}

func (c *ConfigAgent) config() {
	for iface := range c.updatedIF {
		if err := c.configInterface(iface); err != nil {
			log.Printf("%s: %v", configAgentStr, err)
		}
	}

	// NOTE: we MUST connect VIF to VSI first. Not otherway around.
	for ni := range c.updatedNI {
		if ni.niType == NI_L3VRF {
			continue
		}
		if err := c.configVSI(ni); err != nil {
			log.Printf("%s: %v", configAgentStr, err)
		}
	}

	for ni := range c.updatedNI {
		if ni.niType != NI_L3VRF {
			continue
		}
		if err := c.configVRF(ni); err != nil {
			log.Printf("%s: %v", configAgentStr, err)
		}
	}
}

func (c *ConfigAgent) Enable() error {
	paths := [][]string{
		{"interfaces", "interface"},
		{"network-instances", "network-instance"},
	}

	// Fetch openconfig related configuration
	vswitch.GetConfig().Decode(c)
	ocdc.SetOcdServer(c.Setting.Server, c.Setting.Port)

	var err error
	if c.subscriber, err = ocdc.Subscribe(paths); err != nil {
		return fmt.Errorf("%s: %v", configAgentStr, err)
	}

	go func() {
		for recvConf := range c.subscriber.C {
			r := true
			switch recvConf.Mode {
			case ocdc.CM_Validate:
				log.Printf("%s: Validation Start", configAgentStr)
				r = c.validate(recvConf.Configs)
				log.Printf("%s: Validation Done (%v)", configAgentStr, r)
			case ocdc.CM_Commit:
				log.Printf("%s: Commit Start", configAgentStr)
				c.commit(recvConf.Configs)
				c.updates()
				if !c.Setting.DryRun {
					c.config()
					log.Printf("%s: Commit Done", configAgentStr)
				} else {
					log.Printf("%s: Commit Done (Dry Run)", configAgentStr)
				}
				c.DumpConfig()
			}
			c.subscriber.RC <- r
		}
	}()

	return nil
}

func (c *ConfigAgent) Disable() {
	if c.subscriber != nil {
		c.subscriber.Unsubscribe()
		close(c.subscriber.C)
	}
	// TODO: We must free all created instances

	// clean infos
	c.oc.free()
}

func (c *ConfigAgent) String() string {
	return configAgentStr
}

func (c *ConfigAgent) updates() {
	for id, v := range c.updatedNI {
		log.Printf("Network Instance: %v\n", id)
		log.Printf("%v\n", v)
		log.Printf("-------------------\n")
	}

	for id, v := range c.updatedIF {
		log.Printf("Interface: %v\n", id)
		log.Printf("%v", v)
		log.Printf("-------------------\n")
	}
}

func (c *ConfigAgent) DumpConfig() {
	for id, v := range c.oc.nis {
		log.Printf("Network Instance: %v\n", id)
		log.Printf("%v\n", v)
		log.Printf("-------------------\n")
	}

	for id, v := range c.oc.ifs {
		log.Printf("Interface: %v\n", id)
		log.Printf("%v", v)
		log.Printf("-------------------\n")
	}
}

func init() {
	agent := &ConfigAgent{
		oc: newOpenConfig(),

		iface: make(map[string]*vswitch.Interface),
		vif:   make(map[string]*vswitch.VIF),
		vsi:   make(map[string]*vswitch.VSI),
		vrf:   make(map[string]*vswitch.VRF),

		updatedNI: make(map[*ni]struct{}),
		updatedIF: make(map[*iface]struct{}),

		Setting: ocdSetting{
			Server: DefaultOpenconfigdHost,
			Port:   DefaultOpenconfigdPort,
			Listen: DefaultListenPort,
		},
	}

	agent.p = initParser(agent.oc)
	vswitch.RegisterAgent(agent)
}
