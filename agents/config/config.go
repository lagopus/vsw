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
	"fmt"
	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/modules/bridge"
	"github.com/lagopus/vsw/modules/l3"
	"github.com/lagopus/vsw/modules/vif"
	"github.com/lagopus/vsw/ocdc"
	"github.com/lagopus/vsw/vswitch"
	"net"
	"strconv"
	"strings"
)

type VRF struct {
	Name         string
	Interfaces   map[string]*VIF
	Enabled      bool
	RD           uint64
	MTU          int
	BridgeConfig bridge.Config
	vrf          *vswitch.Vrf
	tap          vswitch.Module
	layer3       vswitch.Module
	hostif       vswitch.Module
	updated      bool
	ready        bool
	ca           *ConfigAgent
}

func (v VRF) String() string {
	updated := ""
	if v.updated {
		updated = "*"
	}
	vrf := ""
	if v.vrf != nil {
		vrf = "Created"
	}
	return fmt.Sprintf("%v%s: RD=%016x Interfaces=[%v] Enabled=%v MTU=%d FDBConfig=[%v] %s",
		v.Name, updated, v.RD, v.Interfaces, v.Enabled, v.MTU, v.BridgeConfig, vrf)
}

type Interface struct {
	Name    string
	Device  string
	Driver  string
	Enabled bool
	MTU     int
	VIFs    map[int]*VIF
	updated bool
	ca      *ConfigAgent
}

func (i Interface) String() string {
	updated := ""
	if i.updated {
		updated = "*"
	}
	return fmt.Sprintf("%v%s: Device=%v Driver=%v Enabled=%v MTU=%d VIFs=%v",
		i.Name, updated, i.Device, i.Driver, i.Enabled, i.MTU, i.VIFs)
}

type VIF struct {
	Name        string
	IfName      string
	Index       int
	VRF         *VRF
	Interface   *Interface
	Enabled     bool
	VRRP        bool
	IPAddresses map[string]*vswitch.IPAddr
	updated     bool
	ready       bool
	bridge      vswitch.Module
	vif         vswitch.Module
}

func (v VIF) String() string {
	updated := ""
	if v.updated {
		updated = "*"
	}
	module := ""
	if v.vif != nil {
		module = "Created"
	}
	return fmt.Sprintf("%v-%d%s: Enabled=%v IPAddr(s)=%v %s",
		v.IfName, v.Index, updated, v.Enabled, v.IPAddresses, module)
}

type ConfigAgent struct {
	handle *ocdc.Handle
	vrfs   map[string]*VRF
	ifs    map[string]*Interface
	vifs   map[string]*VIF
	ready  chan struct{}
}

type ConfigAgentAPI interface {
	DumpConfig()
	Wait()
}

var log = vswitch.Logger

const configAgentStr = "Config Agent"

const (
	instanceType   = 1
	instanceID     = 2
	instanceConfig = 3

	configKey = 0

	niFdbConfigKey   = 2
	niFdbConfigValue = 3

	niIfaceID          = 2
	niIfaceConfigKey   = 4
	niIfaceConfigValue = 5
	niIfaceConfigLen   = 6

	niConfigKey   = 1
	niConfigValue = 2

	ifConfigKey   = 1
	ifConfigValue = 2

	ifSubifIndex          = 2
	ifSubifIPv4ID         = 3
	ifSubifIPv4ConfigType = 4
	ifSubifIPv4Key        = 5
	ifSubifIPv4Value      = 6
	ifSubifIPv4ConfigLen  = 7
)

func (v *VRF) configFdb(key, value string) bool {
	switch key {
	case "mac-aging-time":
		v.BridgeConfig.MacAgingTime, _ = strconv.Atoi(value)
	case "mac-learning":
		v.BridgeConfig.MacLearning, _ = strconv.ParseBool(value)
	case "maximum-entries":
		v.BridgeConfig.MaxEntries, _ = strconv.Atoi(value)
	default:
		log.Printf("%s: Unknown fdb config: %v=%v", configAgentStr, key, value)
		return false
	}
	return true
}

func (v *VRF) configVRF(key, value string) {
	switch key {
	case "route-distinguisher":
		f := strings.Split(value, ":")

		// Assigned Number
		n, _ := strconv.Atoi(f[1])
		num := uint16(n)

		// Administrator Field
		n, err := strconv.Atoi(f[0])

		var asn uint32
		var t uint64
		if err == nil {
			asn = uint32(n)
			t = 0x02 << 48
		} else {
			ip := strings.Split(f[0], ".")
			if len(ip) != 4 {
				log.Printf("%s: Unknown route-distinguisher: %v", configAgentStr, value)
				return
			}
			for _, s := range ip {
				d, _ := strconv.Atoi(s)
				asn = (asn << 8) | uint32(d)
			}
			t = uint64(0x01 << 48)
		}

		v.RD = t | uint64(asn)<<16 | uint64(num)

	case "enabled":
		v.Enabled, _ = strconv.ParseBool(value)
	case "mtu":
		v.MTU, _ = strconv.Atoi(value)
	case "name":
		if v.Name != value {
			log.Printf("%s: network-instance name doesn't match: %v != %v",
				configAgentStr, v.Name, value)
		}
	default:
		log.Printf("%s: Unknown network-instance config: %v=%v", configAgentStr, key, value)
		return
	}
	v.updated = true
}

func (v *VRF) configNetworkInstance(config []string) {
	if len(config) < 1 {
		return
	}

	switch config[configKey] {
	case "config":
		v.configVRF(config[niConfigKey], config[niConfigValue])
	case "fdb":
		if v.configFdb(config[niFdbConfigKey], config[niFdbConfigValue]) {
			v.updated = true
		}
	case "interfaces":
		// As we can extract interface and subinterface from the name
		// we don't bother extracting from config sent to us.
		if len(config) == niIfaceConfigLen {
			ifname := config[niIfaceID]
			vif := v.ca.VIF(ifname)
			vif.VRF = v
			v.Interfaces[ifname] = vif
			v.updated = true
		}
	default:
		log.Printf("%s: Unknown network-instance config: %v", configAgentStr, config)
		return
	}
}

func (v *VRF) VRFInstance() *vswitch.Vrf {
	if v.vrf == nil {
		v.vrf = vswitch.NewVRF(v.Name, v.RD)
	}
	return v.vrf
}

func (v *VRF) TAPInstance() vswitch.Module {
	if v.tap == nil {
		v.tap = v.VRFInstance().NewModule("tap", v.Name+"-tap")
	}
	return v.tap
}

func (v *VRF) Layer3Instance() vswitch.Module {
	if v.layer3 == nil {
		v.layer3 = v.VRFInstance().NewModule("l3", v.Name+"-l3")
		v.layer3.Connect(v.TAPInstance(), vswitch.MATCH_IPV4_DST_SELF)
	}
	return v.layer3
}

func (v *VRF) HostIFInstance() vswitch.Module {
	if v.hostif == nil {
		v.hostif = v.VRFInstance().NewModule("hostif", v.Name+"-hostif")

		l3m := v.Layer3Instance()
		l3m.Connect(v.hostif, vswitch.MATCH_IPV4_DST)

		entry := l3.InterfaceIpEntry{
			VrfRd: v.RD,
			IpAddress: vswitch.IPAddr{
				IP:   net.IPv4(224, 0, 0, 18),
				Mask: net.IPv4Mask(255, 255, 255, 255),
			},
		}
		l3m.Control("INTERFACE_HOSTIF_IP_ADD", entry)
	}
	return v.hostif
}

func (v *VRF) instantiateVRF() {
	for _, vif := range v.Interfaces {
		log.Printf("%s: Setting VIF: %v", configAgentStr, vif)
		if !vif.Enabled || vif.ready {
			continue
		}

		tap := v.TAPInstance()
		l3m := v.Layer3Instance()

		bi := vif.BridgeInstance()
		vi := vif.VIFInstance()

		bi.Control("SET_CONFIG", v.BridgeConfig)
		bid := bi.Control("GET_BRIDGE_ID", nil).(uint32)

		vi.Connect(bi, vswitch.MATCH_ANY)
		bi.Connect(vi, vswitch.MATCH_OUT_VIF)
		bi.Connect(tap, vswitch.MATCH_ETH_TYPE_ARP)
		bi.Connect(l3m, vswitch.MATCH_ETH_DST_SELF)
		l3m.Connect(bi, vswitch.MATCH_BRIDGE_ID, uint64(bid))
		tap.Connect(vi, vswitch.MATCH_OUT_VIF)

		// VRRP
		if vif.VRRP {
			log.Printf("%s: Connecting hostif to %v for VRRP", configAgentStr, vif.Name)
			v.HostIFInstance().Connect(vi, vswitch.MATCH_OUT_VIF)
		}

		// ready to bring up VIF
		vi.Vif().VifInfo().SetLink(vswitch.LinkUp)

		vif.updated = false
	}

	v.ready = true
	for _, vif := range v.Interfaces {
		if !vif.ready {
			v.ready = false
			break
		}
	}
}

func (v *VIF) configVIF(key, value string) {
	switch key {
	case "enabled":
		v.Enabled, _ = strconv.ParseBool(value)
	case "index":
		if idx, err := strconv.Atoi(value); err == nil {
			if idx != v.Index {
				log.Printf("%s: Subinterface index doesn'match: %d != %d",
					configAgentStr, v.Index, idx)
				return
			}
		}
	default:
		log.Printf("%s: Unknown interface config: %v=%v", configAgentStr, key, value)
		return
	}
	v.updated = true
}

func (v *VIF) IPAddress(id string) *vswitch.IPAddr {
	ip := v.IPAddresses[id]

	if ip == nil {
		ip = &vswitch.IPAddr{}
		v.IPAddresses[id] = ip
	}

	return ip
}

func (v *VIF) configIPv4Address(id, key, value string) {
	ip := v.IPAddress(id)

	switch key {
	case "ip":
		ip.IP = net.ParseIP(value)
	case "prefix-length":
		plen, err := strconv.Atoi(value)
		if err != nil {
			log.Printf("%s: Bad prefix-length: %v", configAgentStr, value)
			return
		}
		ip.Mask = net.CIDRMask(plen, 32)
	default:
		log.Printf("%s: Unknown IPv4 address config: %v=%v", configAgentStr, key, value)
		return
	}
	v.updated = true
}

func (v *VIF) configSubinterface(config []string) {
	if len(config) < 1 {
		return
	}

	switch config[configKey] {
	case "config":
		v.configVIF(config[ifConfigKey], config[ifConfigValue])
	case "ipv4":
		configLen := len(config)
		if configLen > ifSubifIPv4ConfigType {
			switch config[ifSubifIPv4ConfigType] {
			case "config":
				if len(config) == ifSubifIPv4ConfigLen {
					id := config[ifSubifIPv4ID]
					key := config[ifSubifIPv4Key]
					value := config[ifSubifIPv4Value]
					v.configIPv4Address(id, key, value)
				} else {
					log.Printf("%s: Unknown subinterface config: %v", configAgentStr, config)
				}
			case "vrrp":
				v.VRRP = true
			}
		}
	default:
		log.Printf("%s: Unknown subinterface config: %v", configAgentStr, config)
		return
	}
}

func (v *VIF) BridgeInstance() vswitch.Module {
	if v.bridge == nil {
		if v.VRF == nil {
			return nil
		}
		v.bridge = v.VRF.VRFInstance().NewModule("bridge", v.IfName+"-bridge")
		log.Printf("%s: Creating bridge instance - %s-bridge", configAgentStr, v.IfName)
	}
	return v.bridge
}

func (v *VIF) VIFInstance() vswitch.Module {
	if v.vif == nil {
		if v.VRF == nil {
			return nil
		}

		if v.Interface.Device == "" || !v.Enabled {
			return nil
		}

		log.Printf("%s: Creating VIF instance - %s", configAgentStr, v.Name)

		port, err := dpdk.EthDevGetPortByName(v.Interface.Device)
		if err != nil {
			log.Printf("%s: Can't find device %v: %v", configAgentStr, v.Interface.Device, err)
			return nil
		}

		v.vif = v.VRF.VRFInstance().NewModule("vif", v.Name)

		v.vif.Control("CONFIG",
			vif.VifConfig{
				SocketId: 0,
				PortId:   port,
				RxQueue:  vif.VifQueue{QueueId: 0, QueueLen: 4096},
				TxQueue:  vif.VifQueue{QueueId: 0, QueueLen: 2048},
			})

		vi := v.vif.Vif().VifInfo()
		for _, ipaddr := range v.IPAddresses {
			vi.AddIPAddr(*ipaddr)
		}
		v.ready = true
	}
	return v.vif
}

func (i *Interface) configInterface(key, value string) {
	switch key {
	case "name":
		i.Name = value
	case "device":
		i.Device = value
	case "driver":
		i.Driver = value
	case "enabled":
		i.Enabled, _ = strconv.ParseBool(value)
	case "mtu":
		i.MTU, _ = strconv.Atoi(value)
	default:
		log.Printf("%s: Unknown interface config: %v=%v)", configAgentStr, key, value)
		return
	}
	i.updated = true
}

func (i *Interface) configInterfaceInstance(config []string) {
	if len(config) < 1 {
		return
	}

	switch config[configKey] {
	case "config":
		i.configInterface(config[ifConfigKey], config[ifConfigValue])
	case "subinterfaces":
		if idx, err := strconv.Atoi(config[ifSubifIndex]); err == nil {
			vif := i.ca.VIF(i.Name + "-" + strconv.Itoa(idx))
			vif.configSubinterface(config[ifSubifIndex+1:])
		}
	default:
		log.Printf("%s: Unknown interface config: %v", configAgentStr, config)
	}
}

func (c *ConfigAgent) VRF(name string) *VRF {
	vrf := c.vrfs[name]

	if vrf == nil {
		vrf = &VRF{
			Name:       name,
			Interfaces: make(map[string]*VIF),
			ca:         c,
		}
		c.vrfs[name] = vrf
	}

	return vrf
}

func (c *ConfigAgent) Interface(name string) *Interface {
	iface := c.ifs[name]

	if iface == nil {
		iface = &Interface{
			Name: name,
			VIFs: make(map[int]*VIF),
			ca:   c,
		}
		c.ifs[name] = iface
	}

	return iface
}

func (c *ConfigAgent) VIF(name string) *VIF {
	vif := c.vifs[name]

	if vif == nil {
		f := strings.Split(name, "-")
		index, _ := strconv.Atoi(f[1])

		iface := c.Interface(f[0])
		vif = &VIF{
			Name:        name,
			IfName:      f[0],
			Index:       index,
			Interface:   iface,
			IPAddresses: make(map[string]*vswitch.IPAddr),
		}
		iface.VIFs[index] = vif
		c.vifs[name] = vif
	}

	return vif
}

func (c *ConfigAgent) commit(configs []*ocdc.Config) {
	for _, config := range configs {
		if config.Type == ocdc.TypeDelete {
			log.Printf("%s: Delete Not Supported yet; Requested to delete %v",
				configAgentStr, config.Path)
			continue
		}

		instance := config.Path[instanceID]
		configPath := config.Path[instanceConfig:]

		switch config.Path[instanceType] {
		case "network-instance":
			vrf := c.VRF(instance)
			vrf.configNetworkInstance(configPath)

		case "interface":
			iface := c.Interface(instance)
			iface.configInterfaceInstance(configPath)

		default:
			log.Printf("%s: Unknown config: %v", configAgentStr, config.Path)
		}
	}
}

func (c *ConfigAgent) validate(configs []*ocdc.Config) bool {
	// TBD
	return true
}

func (c *ConfigAgent) config() {
	for id, vrf := range c.vrfs {
		if vrf.updated {
			log.Printf("VRF %v ready: %v", id, vrf)
			vrf.instantiateVRF()
			vrf.updated = false
		}
	}

	needVRFSetting := false
	for id, iface := range c.ifs {
		if iface.updated {
			log.Printf("Interface %v ready: %v", id, iface)
			needVRFSetting = true
			iface.updated = false
		}

		for id, vif := range iface.VIFs {
			if vif.updated {
				log.Printf("Subinterface %v ready: %v", id, vif)
				if vif.Enabled {
					needVRFSetting = true
				}
				vif.updated = false
			}
		}
	}

	if needVRFSetting {
		for _, vrf := range c.vrfs {
			log.Printf("%s: Updating %v", configAgentStr, vrf.Name)
			vrf.instantiateVRF()
		}
	}

	if len(c.vrfs) > 0 {
		ready := true
		for _, vrf := range c.vrfs {
			if !vrf.ready {
				ready = false
				break
			}
		}
		if ready {
			c.ready <- struct{}{}
		}
	}
}

func (c *ConfigAgent) Start() bool {
	paths := [][]string{
		{"interfaces", "interface"},
		{"network-instances", "network-instance"},
	}

	c.handle = ocdc.Subscribe("config-agent", paths)
	if c.handle == nil {
		log.Printf("%s: Can't subscribe to OpenConfigd", configAgentStr)
		return false
	}

	go func() {
		for cm := range c.handle.ConfigMessage {
			rc := true
			if cm.Validate {
				log.Printf("%s: Validation Start", configAgentStr)
				rc = c.validate(cm.Configs)
				log.Printf("%s: Validation Done (%v)", configAgentStr, rc)
			} else {
				log.Printf("%s: Commit Start", configAgentStr)
				c.commit(cm.Configs)
				c.config()
				log.Printf("%s: Commit Done", configAgentStr)
			}
			c.handle.Rc <- rc
		}
	}()

	return true
}

func (c *ConfigAgent) Stop() {
	if c.handle != nil {
		c.handle.Unsubscribe()
	}
}

func (c *ConfigAgent) String() string {
	return configAgentStr
}

func (c *ConfigAgent) DumpConfig() {
	for id, vc := range c.vrfs {
		log.Printf("VRF ID: %v\n", id)
		log.Printf("%v", vc)
		log.Printf("-------------------\n")
	}

	for id, iface := range c.ifs {
		log.Printf("Interface ID: %v\n", id)
		log.Printf("%v", iface)
		log.Printf("-------------------\n")
	}

	for id, vif := range c.vifs {
		log.Printf("VIF ID: %v\n", id)
		log.Printf("%v", vif)
		log.Printf("-------------------\n")
	}
}

func (c *ConfigAgent) Wait() {
	<-c.ready
}

func init() {
	agent := &ConfigAgent{
		vrfs:  make(map[string]*VRF),
		ifs:   make(map[string]*Interface),
		vifs:  make(map[string]*VIF),
		ready: make(chan struct{}),
	}
	vswitch.RegisterAgent(agent)
}
