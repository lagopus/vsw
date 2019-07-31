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
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/lagopus/vsw/vswitch"
)

/*
* Parser related
 */
var ocdcShowSyntax = []*parserSyntax{
	{
		"show network-instances",
		[]*parserSyntaxEntry{
			{"", showNIs, niInstances},
		},
	},
	{
		"show network-instances network-instance STRING",
		[]*parserSyntaxEntry{
			{"", showNIStats, niStatus},
			{"state", showNIStats, niStatusState},
			{"interfaces", showNIIF, niIFs},
			{"interfaces interface STRING", showNIIF, niIF},
			{"vlans", showVSIVLANs, niVLANs},
		},
	},
	{
		"show network-instances network-instance STRING fdb",
		[]*parserSyntaxEntry{
			{"", showVSIFDB, niFdb},
			{"state", showVSIFDB, niFdbState},
			{"mac-table entries", showVSIFDB, niFdbMacTable},
			{"mac-table entries entry MACADDR", showVSIFDB, niFdbMacEntry},
		},
	},
	{
		"show network-instances network-instance STRING security ipsec",
		[]*parserSyntaxEntry{
			{"", showVRFSecurity, niSecurity},
			{"sad", showVRFSecurity, niSAD},
			{"sad sad-entries INTEGER", showVRFSecurity, niSADEntry},
			{"spd", showVRFSecurity, niSPD},
			{"spd spd-entries STRING", showVRFSecurity, niSPDEntry},
		},
	},
	{
		"show interfaces",
		[]*parserSyntaxEntry{
			{"", showIFs, ifInstances},
		},
	},
	{
		"show interfaces interface STRING",
		[]*parserSyntaxEntry{
			{"", showIF, ifStatus},
			{"state", showIF, ifStatusState},
			{"state counters", showIF, ifCounters},
			{"ethernet", showIF, ifEthernet},
			{"tunnel state", showIF, ifTunnel},
		},
	},
	{
		"show interfaces interface STRING subinterfaces",
		[]*parserSyntaxEntry{
			{"", showIFSubs, ifSubs},
		},
	},
	{
		"show interfaces interface STRING subinterfaces subinterface INTEGER",
		[]*parserSyntaxEntry{
			{"", showIFSub, ifSub},
			{"state", showIFSub, ifSubState},
			{"state counters", showIFSub, ifSubCounters},
			{"ipv4 addresses", showIFSub, ifSubAddresses},
			{"ipv4 addresses address A.B.C.D", showIFSub, ifSubAddress},
			{"vlan state vlan-id", showIFSub, ifSubVLANId},
			{"tunnel state", showIFSub, ifSubTunnel},
		},
	},
}

/*
 * Callbacks called from parser
 */
func getNIIFs(vifs []*vswitch.VIF) niIfaces {
	niIfs := niIfaces{make(map[string]niIface)}
	for _, vif := range vifs {
		ifName := vif.Interface().String()
		index, _ := strconv.Atoi(strings.Split(vif.Name(), "-")[1])

		niIf, ok := niIfs.Iface[ifName]
		if !ok {
			niIf = niIface{}
		}

		niIf.Subiface = append(niIf.Subiface, uint32(index))
		niIfs.Iface[ifName] = niIf
	}
	return niIfs
}

func getSADEntry(s vswitch.SA) *saEntry {
	sa := &saEntry{
		State: saState{
			Mode: s.Mode,
			LifeTime: lifeTime{
				LifeTimeInSeconds: s.LifeTimeInSeconds,
				LifeTimeInByte:    s.LifeTimeInByte,
			},
			LocalPeer:     localPeer{nil},
			RemotePeer:    remotePeer{nil},
			EncapProtocol: s.EncapProtocol,
			EncapSrcPort:  s.EncapSrcPort,
			EncapDstPort:  s.EncapDstPort,
		},
	}

	if s.LocalPeer != nil {
		sa.State.LocalPeer.IPAddress = &ipAddress{s.LocalPeer}
	}

	if s.RemotePeer != nil {
		sa.State.RemotePeer.IPAddress = &ipAddress{s.RemotePeer}
	}

	if s.Auth == vswitch.AuthSHA1 {
		sa.State.ESP.Authentication.Algorithm = &authAlgorithm{hmacSha196{s.AuthKey}}
	}

	switch s.Encrypt {
	case vswitch.EncryptAES:
		sa.State.ESP.Encryption.Algorithm = &encAlgorithm{Aes128Cbc: &aesKey{s.EncKey}}
	case vswitch.EncryptGCM:
		sa.State.ESP.Encryption.Algorithm = &encAlgorithm{Aes128Gcm: &aesKey{s.EncKey}}
	}

	return sa
}

func getSPDEntry(s vswitch.SP) *spEntry {
	sp := &spEntry{
		State: spState{
			SrcAddress: spAddress{
				PortNumber: s.SrcPort,
			},
			DstAddress: spAddress{
				PortNumber: s.SrcPort,
			},
			UpperProtocol:    s.UpperProtocol,
			Direction:        s.Direction,
			SecurityProtocol: s.SecurityProtocol,
			Priority:         s.Priority,
			Policy:           s.Policy,
		},
	}

	if s.SrcAddress.IP != nil {
		prefixLen, _ := s.SrcAddress.Mask.Size()
		sp.State.SrcAddress.IPAddress = ipAddress{s.SrcAddress.IP}
		sp.State.SrcAddress.PrefixLen = uint8(prefixLen)
	}

	if s.DstAddress.IP != nil {
		prefixLen, _ := s.DstAddress.Mask.Size()
		sp.State.DstAddress.IPAddress = ipAddress{s.DstAddress.IP}
		sp.State.DstAddress.PrefixLen = uint8(prefixLen)
	}

	return sp
}

func getSADEntrySpecifySPI(sad []vswitch.SA, spi uint32) *saEntry {
	for _, sa := range sad {
		if sa.SPI == spi {
			return getSADEntry(sa)
		}
	}
	return nil
}

func getSPDEntrySpecifyName(spd []vswitch.SP, name string) *spEntry {
	for _, sp := range spd {
		if sp.Name == name {
			return getSPDEntry(sp)
		}
	}
	return nil
}

func getSAD(sad []vswitch.SA) sadb {
	e := make(map[uint32]*saEntry)
	for _, sa := range sad {
		e[sa.SPI] = getSADEntry(sa)
	}
	return sadb{e}
}

func getSPD(spd []vswitch.SP) spdb {
	e := make(map[string]*spEntry)
	for _, sp := range spd {
		e[sp.Name] = getSPDEntry(sp)
	}
	return spdb{e}
}

func getSecurity(sads *vswitch.SADatabases) security {
	s := security{}

	if len(sads.SAD()) > 0 {
		s.IPSec = &ipsec{SAD: getSAD(sads.SAD())}
	}
	if len(sads.SPD()) > 0 {
		if s.IPSec == nil {
			s.IPSec = &ipsec{}
		}
		s.IPSec.SPD = getSPD(sads.SPD())
	}

	return s
}

func getVRFState(vrf *vswitch.VRF) niState {
	return niState{
		NiType:    NI_L3VRF,
		Enabled:   vrf.IsEnabled(),
		EnabledAF: []vswitch.AddressFamily{vswitch.AF_IPv4},
		RD:        vrf.RD(),
	}
}

func getVRFStats(vrf *vswitch.VRF) vrfStats {
	return vrfStats{
		State:      getVRFState(vrf),
		Interfaces: getNIIFs(vrf.VIF()),
		Security:   getSecurity(vrf.SADatabases()),
	}
}

func getFDBState(vsi *vswitch.VSI) fdbState {
	return fdbState{
		MACLearning:  vsi.MACLearning(),
		MACAgingTime: vsi.MACAgingTime(),
		MaxEntries:   vsi.MaximumEntries(),
	}
}

func getMACEntry(e vswitch.MACEntry) *macEntry {
	index, _ := strconv.Atoi(strings.Split(e.VIF.Name(), "-")[1])
	return &macEntry{
		State: macEntryState{
			VID:       e.VID,
			Age:       e.Age,
			EntryType: e.EntryType,
		},
		Iface: macEntryIF{
			InterfaceRef: interfaceReference{
				Iface:    e.VIF.Interface().String(),
				Subiface: uint32(index),
			},
		},
	}
}

func getMACEntrySpecifyMACAddress(mt []vswitch.MACEntry, macAddr string) *macEntry {
	for _, entry := range mt {
		if entry.MACAddress.String() == macAddr {
			return getMACEntry(entry)
		}
	}
	return nil
}

func getMACTable(mt []vswitch.MACEntry) macTable {
	if len(mt) == 0 {
		return macTable{}
	}

	macTable := macTable{
		Entries: &macEntries{
			Entry: make(map[string]*macEntry),
		},
	}
	for _, entry := range mt {
		macTable.Entries.Entry[entry.MACAddress.String()] = getMACEntry(entry)
	}
	return macTable
}

func getFDBStats(vsi *vswitch.VSI) fdb {
	return fdb{
		State:    getFDBState(vsi),
		MACTable: getMACTable(vsi.MACTable()),
	}
}

func getVSIVLANs(vids map[vswitch.VID]bool) niVlans {
	vlans := make(map[vswitch.VID]niVlan)
	for vid, active := range vids {
		vlans[vid] = niVlan{niVlanState{niVlanActive}}
		if !active {
			vlans[vid] = niVlan{niVlanState{niVlanSuspended}}
		}
	}
	return niVlans{vlans}
}

func getVSIState(vsi *vswitch.VSI) niState {
	return niState{
		NiType:    NI_L2VSI,
		Enabled:   vsi.IsEnabled(),
		EnabledAF: []vswitch.AddressFamily{},
	}
}

func getVSIStats(vsi *vswitch.VSI) vsiStats {
	return vsiStats{
		FDB:        getFDBStats(vsi),
		State:      getVSIState(vsi),
		Interfaces: getNIIFs(vsi.VIF()),
		VLANs:      getVSIVLANs(vsi.VID()),
	}
}

func showNIs(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	if key != niInstances {
		log.Err("Unexpected key: %v", key)
		return string(internalErrMsg), nil
	}

	stats := make(map[string]interface{})
	for _, vrf := range vswitch.GetAllVRF() {
		stats[vrf.Name()] = getVRFStats(vrf)
	}
	for _, vsi := range vswitch.VSIs() {
		stats[vsi.String()] = getVSIStats(vsi)
	}
	return outputResult(stats), nil
}

func showNIStats(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	var vsw interface{}
	name := args[0].(string)
	if vsw = vswitch.GetVRFByName(name); vsw == (*vswitch.VRF)(nil) {
		vsw = vswitch.GetVSI(name)
	}

	if vsw == (*vswitch.VSI)(nil) {
		return outputErr("No such network-instance: %v", name), nil
	}

	switch v := vsw.(type) {
	case *vswitch.VRF:
		return showVRFStats(v, key, args)

	case *vswitch.VSI:
		return showVSIStats(v, key, args)

	default:
		log.Err("Unexpected network-instance type: %T", v)
		return string(internalErrMsg), nil
	}
}

func showVRFStats(vrf *vswitch.VRF, key ocdcType, args []interface{}) (interface{}, error) {
	result := ""
	switch key {
	case niStatus:
		result = outputResult(getVRFStats(vrf))

	case niStatusState:
		result = outputResult(getVRFState(vrf))

	default:
		log.Err("Unexpected key: %v", key)
		result = string(internalErrMsg)
	}

	return result, nil
}

func showVSIStats(vsi *vswitch.VSI, key ocdcType, args []interface{}) (interface{}, error) {
	result := ""
	switch key {
	case niStatus:
		result = outputResult(getVSIStats(vsi))

	case niStatusState:
		result = outputResult(getVSIState(vsi))

	default:
		log.Err("Unexpected key: %v", key)
		result = string(internalErrMsg)
	}

	return result, nil
}

func showNIIF(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	var vsw networkInstance
	name := args[0].(string)
	if vsw = vswitch.GetVRFByName(name); vsw == (*vswitch.VRF)(nil) {
		vsw = vswitch.GetVSI(name)
	}

	if vsw == (*vswitch.VSI)(nil) {
		return outputErr("No such network-instance: %v", name), nil
	}

	ifs := getNIIFs(vsw.VIF())
	result := ""
	switch key {
	case niIFs:
		result = outputResult(ifs)

	case niIF:
		iface, ok := ifs.Iface[args[1].(string)]
		if !ok {
			return outputErr("No such interface in %v: %v", vsw.String(), args[1].(string)), nil
		}
		result = outputResult(iface)

	default:
		log.Err("Unexpected key: %v", key)
		result = string(internalErrMsg)
	}

	return result, nil
}

func showVRFSecurity(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	vrf := vswitch.GetVRFByName(args[0].(string))
	if vrf == nil {
		return outputErr("No such VRF: %v", args[0].(string)), nil
	}

	result := ""
	switch key {
	case niStatus:
	case niSecurity:
		result = outputResult(getSecurity(vrf.SADatabases()))

	case niSAD:
		result = outputResult(getSAD(vrf.SADatabases().SAD()))

	case niSADEntry:
		spi := uint32(args[1].(int))
		e := getSADEntrySpecifySPI(vrf.SADatabases().SAD(), spi)
		if e == nil {
			return outputErr("No such SAD entry in %v: %v", vrf.Name(), spi), nil
		}
		result = outputResult(e)

	case niSPD:
		result = outputResult(getSPD(vrf.SADatabases().SPD()))

	case niSPDEntry:
		spName := args[1].(string)
		e := getSPDEntrySpecifyName(vrf.SADatabases().SPD(), spName)
		if e == nil {
			return outputErr("No such SPD entry in %v: %v", vrf.Name(), spName), nil
		}
		result = outputResult(e)

	default:
		log.Err("Unexpected key: %v", key)
		result = string(internalErrMsg)
	}

	return result, nil
}

func showVSIFDB(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	vsi := vswitch.GetVSI(args[0].(string))
	if vsi == nil {
		return outputErr("No such VSI: %v", args[0].(string)), nil
	}

	result := ""
	switch key {
	case niFdb:
		result = outputResult(getFDBStats(vsi))

	case niFdbState:
		result = outputResult(getFDBState(vsi))

	case niFdbMacTable:
		result = outputResult(getMACTable(vsi.MACTable()))

	case niFdbMacEntry:
		macAddr := args[1].(net.HardwareAddr).String()
		me := getMACEntrySpecifyMACAddress(vsi.MACTable(), macAddr)
		if me == nil {
			return outputErr("No such MAC Entry: %v", macAddr), nil
		}
		result = outputResult(me)

	default:
		log.Err("Unexpected key: %v", key)
		result = string(internalErrMsg)
	}

	return result, nil
}

func showVSIVLANs(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	vsi := vswitch.GetVSI(args[0].(string))
	if vsi == nil {
		return outputErr("No such VSI: %v", args[0].(string)), nil
	}

	result := ""
	switch key {
	case niVLANs:
		result = outputResult(getVSIVLANs(vsi.VID()))
	default:
		log.Err("Unexpected key: %v", key)
		result = string(internalErrMsg)
	}

	return result, nil
}

//
// show for Interface
//
func getCounters(c *vswitch.Counter) counters {
	return counters{
		InOctets:         c.InOctets(),
		InUnicastPkts:    c.InUnicastPkts(),
		InBroadcastPkts:  c.InBroadcastPkts(),
		InMulticastPkts:  c.InMulticastPkts(),
		InDiscards:       c.InDiscards(),
		InErrors:         c.InErrors(),
		InUnknownProtos:  c.InUnknownProtos(),
		OutOctets:        c.OutOctets(),
		OutUnicastPkts:   c.OutUnicastPkts(),
		OutBroadcastPkts: c.OutBroadcastPkts(),
		OutMulticastPkts: c.OutMulticastPkts(),
		OutDiscards:      c.OutDiscards(),
		OutErrors:        c.OutErrors(),
		LastClear:        c.LastClear(),
	}
}

func getSubAddresses(ipaddrs []vswitch.IPAddr) map[string]subAddress {
	ips := make(map[string]subAddress)
	for _, ip := range ipaddrs {
		prefixLen, _ := ip.Mask.Size()
		ips[ip.IP.String()] = subAddress{
			State: addressState{uint8(prefixLen)},
		}
	}
	return ips
}

func getSubIFState(vif *vswitch.VIF) subIFState {
	return subIFState{
		Enabled:    vif.IsEnabled(),
		OperStatus: decodeLinkStatus(vif),
		LastChange: vif.LastChange(),
		Counters:   getCounters(vif.Counter()),
	}
}

func getSubIFStats(vif *vswitch.VIF) subIFStats {
	return subIFStats{
		State: getSubIFState(vif),
		IPv4: ipv4{
			Addresses: getSubAddresses(vif.ListIPAddrs()),
			State:     ipv4State{true},
		},
		VLAN:     subifVlan{subifVlanState{vif.VID()}},
		L3Tunnel: getL3Tunnel(vif.Tunnel()),
	}
}

func getL3Tunnel(t *vswitch.L3Tunnel) l3Tunnel {
	if t == nil {
		return l3Tunnel{}
	}

	l3tun := l3Tunnel{
		&l3TunnelState{
			tunnelState: tunnelState{
				AddressType:     t.AddressType(),
				LocalAddress:    t.LocalAddress(),
				RemoteAddresses: []net.IP{},
				HopLimit:        t.HopLimit(),
				NetworkInstance: "",
				EncapsMethod:    t.EncapsMethod(),
			},
			TOS:      t.TOS(),
			Security: t.Security(),
		},
	}

	if remotes := t.RemoteAddresses(); remotes != nil {
		l3tun.State.RemoteAddresses = remotes
	}
	if vrf := t.VRF(); vrf != nil {
		l3tun.State.NetworkInstance = vrf.Name()
	}

	return l3tun
}

func getL2Tunnel(t *vswitch.L2Tunnel) l2Tunnel {
	if t == nil {
		return l2Tunnel{}
	}

	l2tun := l2Tunnel{
		&l2TunnelState{
			tunnelState: tunnelState{
				AddressType:     t.AddressType(),
				LocalAddress:    t.LocalAddress(),
				RemoteAddresses: []net.IP{},
				HopLimit:        t.HopLimit(),
				NetworkInstance: t.VRF().Name(),
				EncapsMethod:    t.EncapsMethod(),
			},
			TOS:   t.TOS(),
			VXLAN: vxlan{t.VNI()},
		},
	}

	if remotes := t.RemoteAddresses(); remotes != nil {
		l2tun.State.RemoteAddresses = remotes
	}

	return l2tun
}

func getSwitchedVLAN(i *vswitch.Interface) switchedVlan {
	s := switchedVlan{
		switchedVlanState{
			InterfaceMode: i.InterfaceMode(),
			TrunkVlans:    []vswitch.VID{},
		},
	}
	if len(i.VID()) > 0 {
		switch s.State.InterfaceMode {
		case vswitch.AccessMode:
			s.State.AccessVlan = i.VID()[0]
		case vswitch.TrunkMode:
			s.State.TrunkVlans = i.VID()
		}
	}
	return s
}

func getEthernet(i *vswitch.Interface) ethernet {
	return ethernet{
		State: ethState{
			MACAddress: i.MACAddress().String(),
		},
		SwitchedVlan: getSwitchedVLAN(i),
	}
}

type linkStatuser interface {
	LinkStatus() (bool, error)
}

func decodeLinkStatus(s linkStatuser) operStatus {
	ls, err := s.LinkStatus()

	if err != nil {
		return operStatusUnknown
	}

	if ls {
		return operStatusUP
	}
	return operStatusDown
}

func getIFState(i *vswitch.Interface) ifState {
	s := ifState{
		MTU:        i.MTU(),
		Enabled:    i.IsEnabled(),
		OperStatus: decodeLinkStatus(i),
		LastChange: i.LastChange(),
		Counters:   getCounters(i.Counter()),
		Driver:     i.Driver(),
		Device:     "",
	}

	if device, ok := i.Private().(string); ok {
		s.Device = device
	}

	switch s.Driver {
	case DriverDPDK, DriverRIF:
		s.IFType = IF_ETHERNETCSMACD
	case DriverTunnel:
		s.IFType = IF_TUNNEL
	default:
		s.IFType = IF_UNKNOWN
	}

	return s
}

func getIFStats(i *vswitch.Interface) ifStats {
	s := ifStats{
		State:         getIFState(i),
		Subinterfaces: make(map[int]subIFStats),
		Ethernet:      getEthernet(i),
		L2Tunnel:      getL2Tunnel(i.Tunnel()),
	}

	for _, vif := range i.VIF() {
		index, _ := strconv.Atoi(strings.Split(vif.Name(), "-")[1])
		s.Subinterfaces[index] = getSubIFStats(vif)
	}

	return s
}

func showIFs(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	if key != ifInstances {
		log.Err("Unexpected key: %v", key)
		return string(internalErrMsg), nil
	}

	stats := make(map[string]ifStats)
	for _, i := range vswitch.Interfaces() {
		stats[i.String()] = getIFStats(i)
	}
	return outputResult(stats), nil
}

func showIF(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	i := vswitch.GetInterface(args[0].(string))
	if i == nil {
		return outputErr("No such Interface: %v", args[0].(string)), nil
	}

	result := ""
	switch key {
	case ifStatus:
		result = outputResult(getIFStats(i))

	case ifStatusState:
		result = outputResult(getIFState(i))

	case ifCounters:
		result = outputResult(getCounters(i.Counter()))

	case ifEthernet:
		result = outputResult(getEthernet(i))

	case ifTunnel:
		result = outputResult(getL2Tunnel(i.Tunnel()))

	default:
		log.Err("Unexpected key: %v", key)
		result = string(internalErrMsg)
	}

	return result, nil
}

func showIFSubs(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	if key != ifSubs {
		log.Err("Unexpected key: %v", key)
		return string(internalErrMsg), nil
	}

	ifName := args[0].(string)
	i := vswitch.GetInterface(ifName)
	if i == nil {
		return outputErr("No such Interface: %v", ifName), nil
	}
	stats := make(map[string]subIFStats)
	for _, vif := range i.VIF() {
		stats[vif.Name()] = getSubIFStats(vif)
	}

	return outputResult(stats), nil
}

func showIFSub(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	vifName := fmt.Sprintf("%s-%d", args[0].(string), args[1].(int))
	vif := vswitch.GetVIFByName(vifName)
	if vif == nil {
		return outputErr("No such VIF: %v", vifName), nil
	}

	result := ""
	switch key {
	case ifSub:
		result = outputResult(getSubIFStats(vif))

	case ifSubState:
		result = outputResult(getSubIFState(vif))

	case ifSubCounters:
		result = outputResult(getCounters(vif.Counter()))

	case ifSubAddresses:
		result = outputResult(getSubAddresses(vif.ListIPAddrs()))

	case ifSubAddress:
		ip := args[2].(net.IP)
		subAddr, ok := getSubAddresses(vif.ListIPAddrs())[ip.String()]
		if !ok {
			return outputErr("No such IPv4 address in VIF(%v): %v", vifName, ip), nil
		}
		result = outputResult(subAddr)

	case ifSubVLANId:
		result = outputResult(vif.VID())

	case ifSubTunnel:
		result = outputResult(getL3Tunnel(vif.Tunnel()))

	default:
		log.Err("Unexpected key: %v", key)
		result = string(internalErrMsg)
	}

	return result, nil
}

/*
 * JSON related
 */

// for network instance
type fdbState struct {
	MACLearning  bool `json:"mac-learning"`
	MACAgingTime int  `json:"mac-aging-time"`
	MaxEntries   int  `json:"max-entries"`
}

type macEntryState struct {
	VID       vswitch.VID       `json:"vlan"`
	Age       uint64            `json:"age"`
	EntryType vswitch.EntryType `json:"entry-type"`
}

type macEntryIF struct {
	InterfaceRef interfaceReference `json:"interface-ref"`
}

type interfaceReference struct {
	Iface    string `json:"interface"`
	Subiface uint32 `json:"subinterface"`
}

type macTable struct {
	Entries *macEntries `json:"entries,omitempty"`
}

type macEntries struct {
	Entry map[string]*macEntry `json:"entry"`
}

type macEntry struct {
	State macEntryState `json:"state"`
	Iface macEntryIF    `json:"interface"`
}

type fdb struct {
	State    fdbState `json:"state"`
	MACTable macTable `json:"mac-table"`
}

type niVlanStatus int

const (
	niVlanActive niVlanStatus = iota
	niVlanSuspended
)

func (s niVlanStatus) MarshalJSON() ([]byte, error) {
	if s == niVlanActive {
		return []byte(`"ACTIVE"`), nil
	}
	return []byte(`"SUSPENDED"`), nil
}

type niVlanState struct {
	Status niVlanStatus `json:"status"`
}

type niVlan struct {
	State niVlanState `json:"state"`
}

type niVlans struct {
	VLAN map[vswitch.VID]niVlan `json:"vlan"`
}

type lifeTime struct {
	LifeTimeInSeconds uint32 `json:"life-time-in-seconds"`
	LifeTimeInByte    uint32 `json:"life-time-in-byte"`
}

type ipAddress struct {
	IPv4Address net.IP `json:"ipv4-address,omitempty"`
}

type localPeer struct {
	IPAddress *ipAddress `json:"ip-address,omitempty"`
}

type remotePeer struct {
	IPAddress *ipAddress `json:"ip-address,omitempty"`
}

type hmacSha196 struct {
	Key string `json:"key-str"`
}

type authAlgorithm struct {
	HmacSha196 hmacSha196 `json:"hmac-sha1-96"`
}

type authentication struct {
	Algorithm *authAlgorithm `json:"authentication-algorithm,omitempty"`
}

type aesKey struct {
	Key string `json:"key-str"`
}

type encAlgorithm struct {
	Aes128Cbc *aesKey `json:"aes-128-cbc,omitempty"`
	Aes128Gcm *aesKey `json:"aes-128-gcm,omitempty"`
}

type encryption struct {
	Algorithm *encAlgorithm `json:"encryption-algorithm,omitempty"`
}

type esp struct {
	Authentication authentication `json:"authentication"`
	Encryption     encryption     `json:"encryption"`
}

type saState struct {
	Mode          vswitch.SAMode  `json:"sa-mode"`
	LifeTime      lifeTime        `json:"life-time"`
	LocalPeer     localPeer       `json:"local-peer"`
	RemotePeer    remotePeer      `json:"remote-peer"`
	EncapProtocol vswitch.IPProto `json:"encap-protocol"`
	EncapSrcPort  uint16          `json:"encap-src-port"`
	EncapDstPort  uint16          `json:"encap-dst-port"`
	ESP           esp             `json:"esp"`
}

type saEntry struct {
	State saState `json:"state"`
}

type sadb struct {
	SAD map[uint32]*saEntry `json:"sad-entries"`
}

type spAddress struct {
	IPAddress  ipAddress `json:"ip-address"`
	PrefixLen  uint8     `json:"prefix-length"`
	PortNumber uint16    `json:port-number"`
}

type spState struct {
	SrcAddress       spAddress         `json:"source-address"`
	DstAddress       spAddress         `json:"destination-address"`
	UpperProtocol    vswitch.IPProto   `json:"upper-protocol"`
	Direction        vswitch.Direction `json:"direction"`
	SecurityProtocol vswitch.IPProto   `json:"security-protocol"`
	Priority         int32             `json:"priority"`
	Policy           vswitch.Policy    `json:"policy"`
}

type spEntry struct {
	State spState `json:"state"`
}

type spdb struct {
	SPDEntries map[string]*spEntry `json:"spd-entries"`
}

type ipsec struct {
	SAD sadb `json:"sad"`
	SPD spdb `json:"spd"`
}

type security struct {
	IPSec *ipsec `json:"ipsec,omitempty"`
}

type niIface struct {
	Subiface []uint32 `json:"subinterface"`
}

type niIfaces struct {
	Iface map[string]niIface `json:"interface"`
}

type niState struct {
	NiType    niType                  `json:"type"`
	Enabled   bool                    `json:"enabled"`
	RD        uint64                  `json:"route-distinguisher"`
	EnabledAF []vswitch.AddressFamily `json:"enabled-address-families"`
}

type vrfStats struct {
	State      niState  `json:"state"`
	Interfaces niIfaces `json:"interfaces"`
	Security   security `json:"security"`
}

type vsiStats struct {
	FDB        fdb      `json:"fdb"`
	State      niState  `json:"state"`
	Interfaces niIfaces `json:"interfaces"`
	VLANs      niVlans  `json:"vlans"`
}

// for Interface
type switchedVlanState struct {
	InterfaceMode vswitch.VLANMode `json:"interface-mode"`
	AccessVlan    vswitch.VID      `json:"access-vlan"`
	TrunkVlans    []vswitch.VID    `json:"trunk-vlans"`
}

type switchedVlan struct {
	State switchedVlanState `json:"state"`
}

type duplexMode int

const (
	duplexModeFull duplexMode = iota
	duplexModeHalf
)

func (d duplexMode) String() string {
	if d == duplexModeFull {
		return "FULL"
	}
	return "HALF"
}

func (d duplexMode) MarshalJSON() ([]byte, error) {
	if d == duplexModeFull {
		return []byte(`"` + "FULL" + `"`), nil
	}
	return []byte(`"` + "HALF" + `"`), nil
}

type ethState struct {
	MACAddress string `json:"mac-address"`
}

type ethernet struct {
	State        ethState     `json:"state"`
	SwitchedVlan switchedVlan `json:"switched-vlan"`
}

type tunnelState struct {
	AddressType     vswitch.AddressFamily `json:"address-type"`
	LocalAddress    net.IP                `json:"local-inet-address"`
	RemoteAddresses []net.IP              `json:"remote-inet-address"`
	HopLimit        uint8                 `json:"hop-limit"`
	NetworkInstance string                `json:"network-instance"`
	EncapsMethod    vswitch.EncapsMethod  `json:"encaps-method"`
}

type vxlan struct {
	VNI uint32 `json:"vni"`
}

type l2TunnelState struct {
	tunnelState
	TOS   uint8 `json:"tos"`
	VXLAN vxlan `json:"vxlan"`
}

type l2Tunnel struct {
	State *l2TunnelState `json:"state,omitempty"`
}

type l3TunnelState struct {
	tunnelState
	Security vswitch.Security `json:"security"`
	TOS      int8             `json:"tos"`
}

type l3Tunnel struct {
	State *l3TunnelState `json:"state,omitempty"`
}

type counters struct {
	InOctets         uint64    `json:"in-octets"`
	InUnicastPkts    uint64    `json:"in-unicast-pkts"`
	InBroadcastPkts  uint64    `json:"in-broadcast-pkts"`
	InMulticastPkts  uint64    `json:"in-multicast-pkts"`
	InDiscards       uint64    `json:"in-discards"`
	InErrors         uint64    `json:"in-errors"`
	InUnknownProtos  uint32    `json:"in-unknown-protos"`
	OutOctets        uint64    `json:"out-octets"`
	OutUnicastPkts   uint64    `json:"out-unicast-pkts"`
	OutBroadcastPkts uint64    `json:"out-broadcast-pkts"`
	OutMulticastPkts uint64    `json:"out-multicast-pkts"`
	OutDiscards      uint64    `json:"out-discards"`
	OutErrors        uint64    `json:"out-errors"`
	LastClear        time.Time `json:"last-clear"`
}

type addressState struct {
	PrefixLen uint8 `json:"prefix-length"`
}

type subAddress struct {
	State addressState `json:"state"`
}

type ipv4State struct {
	Enabled bool `json:"enabled"`
}

type ipv4 struct {
	Addresses map[string]subAddress `json:"address"`
	State     ipv4State             `json:"state"`
}

type subifVlanState struct {
	VLANID vswitch.VID `json:"vlan-id"`
}

type subifVlan struct {
	State subifVlanState `json:"state"`
}

type operStatus int

const (
	operStatusUP operStatus = iota + 1
	operStatusDown
	operStatusTesting
	operStatusUnknown
	operStatusDormant
	operStatusNotPresent
	operStatusLowerLayerDown
)

func (o operStatus) String() string {
	str := map[operStatus]string{
		operStatusUP:             "UP",
		operStatusDown:           "DOWN",
		operStatusTesting:        "TESTING",
		operStatusUnknown:        "UNKNOWN",
		operStatusDormant:        "DORMANT",
		operStatusNotPresent:     "NOT_PRESENT",
		operStatusLowerLayerDown: "LOWER_LAYER_DOWN",
	}
	return str[o]
}

func (o operStatus) MarshalJSON() ([]byte, error) {
	return []byte(`"` + o.String() + `"`), nil
}

type subIFState struct {
	Enabled    bool       `json:"enabled"`
	OperStatus operStatus `json:"oper-status"`
	LastChange time.Time  `json:"last-change"`
	Counters   counters   `json:"counters"`
}

type subIFStats struct {
	State    subIFState `json:"state"`
	IPv4     ipv4       `json:"ipv4"`
	VLAN     subifVlan  `json:"vlan"`
	L3Tunnel l3Tunnel   `json:"tunnel"`
}

type ifState struct {
	IFType     ifType      `json:"type"`
	MTU        vswitch.MTU `json:"mtu"`
	Enabled    bool        `json:"enabled"`
	OperStatus operStatus  `json:"oper-status"`
	LastChange time.Time   `json:"last-change"`
	Counters   counters    `json:"counters"`
	Driver     string      `json:"driver"`
	Device     string      `json:"device"`
}

type ifStats struct {
	State         ifState            `json:"state"`
	Subinterfaces map[int]subIFStats `json:"subinterfaces"`
	Ethernet      ethernet           `json:"ethernet"`
	L2Tunnel      l2Tunnel           `json:"tunnel"`
}
