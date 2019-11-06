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
	"net"

	"github.com/lagopus/vsw/vswitch"
)

/*
 * Parser related
 */
var ocdcDeleteSyntax = []*parserSyntax{
	{
		"network-instances network-instance STRING",
		[]*parserSyntaxEntry{
			{"", deleteNI, niSelf},
			{"interfaces interface STRING subinterface INTEGER", deleteNI, niInterface},
			{"vlans vlan INTEGER", deleteNI, niVLAN},
			{"security ipsec sad sad-entries INTEGER", deleteNI, sadSPI},
			{"security ipsec spd spd-entries STRING", deleteNI, spdName},
		},
	},
	{
		"interfaces interface STRING",
		[]*parserSyntaxEntry{
			{"", deleteIF, ifSelf},
			{"ethernet switched-vlan config trunk-vlans INTEGER", deleteIF, ifVLANTrunk},
			{"ethernet switched-vlan config access-vlan INTEGER", deleteIF, ifVLANAccess},
		},
	},
	{
		"interfaces interface STRING subinterfaces subinterface INTEGER",
		[]*parserSyntaxEntry{
			{"", deleteIF, ifSubSelf},
			{"ipv4 addresses address A.B.C.D config prefix-length INTEGER", deleteIF, ifSubAddress},
		},
	},
	{
		"interfaces interface STRING subinterfaces subinterface INTEGER ipv4 addresses address A.B.C.D vrrp vrrp-group INTEGER",
		[]*parserSyntaxEntry{
			{"", deleteIF, ifSubVRRPGroup},
			{"config virtual-address A.B.C.D...", deleteIF, ifSubVRRPVirtualAddress},
		},
	},
}

/*
 * Callbacks called from parser
 */
func deleteNI(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	oc := (v).(*openconfig)
	name := args[0].(string)
	ni := oc.nis[name]
	if ni == nil {
		return nil, fmt.Errorf("%v is already deleted.\n", name)
	}

	dni := oc.getDeletedNetworkInstance(name, ni.niType)
	switch key {
	case niSelf:
		dni.setSelf()
		delete(oc.nis, name)
		delete(oc.ca.updatedNI, ni)

	case niInterface:
		id := args[2].(int)
		dni.addVIF(args[1].(string), id)
		ni.deleteInterface(args[1].(string), uint32(id))

	case niVLAN:
		vid := args[1].(int)
		dni.addVID(vid)
		ni.deleteVID(vid)

	case sadSPI:
		spi := uint32(args[1].(int))
		dni.addSA(spi)
		ni.deleteSA(spi)

	case spdName:
		dni.addSP(args[1].(string))
		ni.deleteSP(args[1].(string))

	default:
		return nil, ocdcTypeUnexpectedError(key)
	}
	return dni, nil
}

func deleteIF(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	oc := (v).(*openconfig)
	name := args[0].(string)
	i := oc.ifs[name]
	if i == nil {
		return nil, fmt.Errorf("%v is already deleted.\n", name)
	}

	di := oc.getDeletedInterface(name)
	switch key {
	case ifSelf:
		di.setSelf()
		delete(oc.ifs, name)
		delete(oc.ca.updatedIF, i)

	case ifVLANTrunk, ifVLANAccess:
		di.addVID(args[1].(int))
		i.deleteVID(args[1].(int))

	case ifSubSelf:
		di.getDeletedSubiface(args[1].(int)).setSelf()
		i.deleteSubiface(args[1].(int))

	case ifSubAddress:
		dsi := di.getDeletedSubiface(args[1].(int))
		dsi.addAddress(args[2].(net.IP), args[3].(int))
		if sub, ok := i.subs[args[1].(int)]; ok {
			sub.deleteAddress(args[2].(net.IP), args[3].(int))
			// Delete VRRPGroup from set data list
			sub.deleteVrrp(args[2].(net.IP))
		}

	case ifSubVRRPGroup:
		dsi := di.getDeletedSubiface(args[1].(int))
		dsi.getDeletedVRRPGroup(args[2].(net.IP), args[3].(int)).setSelf()
		if sub, ok := i.subs[args[1].(int)]; ok {
			// Delete VRRPGroup from set data list
			sub.deleteVrrpGroup(args[2].(net.IP), args[3].(int))
		}

	case ifSubVRRPVirtualAddress:
		dsi := di.getDeletedSubiface(args[1].(int))
		dvg := dsi.getDeletedVRRPGroup(args[2].(net.IP), args[3].(int))
		for cnt := 4; cnt < len(args); cnt++ {
			dvg.addDeletedVRRPVirtualAddress(args[cnt].(net.IP))
			if sub, ok := i.subs[args[1].(int)]; ok {
				// Delete virtual address from set data list
				sub.deleteVrrpVirtualAddress(args[2].(net.IP), args[3].(int), args[cnt].(net.IP))
			}
		}

	default:
		return nil, ocdcTypeUnexpectedError(key)
	}
	return di, nil
}

/*
 * Configuration related
 */
type deletedNI struct {
	// L2VSI/L3VRF Common
	self   bool // set true if delete a network-instance self
	name   string
	niType niType
	vifs   []string

	// L2VSI
	vlans []vswitch.VID

	// L3VRF
	sad []uint32
	spd []string
}

type deletedIface struct {
	self bool // set true if delete an interface self
	name string
	vids []vswitch.VID
	subs map[int]*deletedSubiface
}
type deletedSubiface struct {
	self   bool // set true if delete a vif self
	name   string
	ipaddr []vswitch.IPAddr
	groups map[string]*deletedVRRPGroups
}

type deletedVRRPGroups struct {
	vgs map[vswitch.VRID]*deletedVRRPGroup
}
type deletedVRRPGroup struct {
	self   bool
	vaddrs deletedVRRPVAddrList
}
type deletedVRRPVAddrList []net.IP

func (dni *deletedNI) setSelf() {
	dni.self = true
}

func (dni *deletedNI) addVIF(iface string, id int) {
	dni.vifs = append(dni.vifs, fmt.Sprintf("%s-%d", iface, id))
}

func (dni *deletedNI) addVID(vid int) {
	dni.vlans = append(dni.vlans, vswitch.VID(vid))
}

func (dni *deletedNI) addSA(spi uint32) {
	dni.sad = append(dni.sad, spi)
}

func (dni *deletedNI) addSP(name string) {
	dni.spd = append(dni.spd, name)
}

func (di *deletedIface) setSelf() {
	di.self = true
}

func (di *deletedIface) addVID(vid int) {
	di.vids = append(di.vids, vswitch.VID(vid))
}

func (di *deletedIface) getDeletedSubiface(id int) *deletedSubiface {
	if di.subs == nil {
		di.subs = make(map[int]*deletedSubiface)
	}
	ds, ok := di.subs[id]
	if !ok {
		ds = &deletedSubiface{
			name:   fmt.Sprintf("%s-%d", di.name, id),
			groups: make(map[string]*deletedVRRPGroups),
		}
		di.subs[id] = ds
	}
	return ds
}

func (dsi *deletedSubiface) addAddress(ip net.IP, mask int) {
	ipaddr := createIPAddr(ip, mask)
	dsi.ipaddr = append(dsi.ipaddr, ipaddr)
}

func (dsi *deletedSubiface) setSelf() {
	dsi.self = true
}

func (dsi *deletedSubiface) getDeletedVRRPGroup(ip net.IP, vrid int) *deletedVRRPGroup {
	id := vswitch.VRID(vrid)
	ipkey := ip.String()
	vgs, ok := dsi.groups[ipkey]
	if ok {
		if vg, ok := vgs.vgs[id]; ok {
			return vg
		}
	} else {
		vgs = &deletedVRRPGroups{
			vgs: make(map[vswitch.VRID]*deletedVRRPGroup),
		}
		dsi.groups[ipkey] = vgs
	}

	vg := &deletedVRRPGroup{}
	vgs.vgs[id] = vg

	return vg
}

func (dvg *deletedVRRPGroup) setSelf() {
	dvg.self = true
}

func (dvg *deletedVRRPGroup) addDeletedVRRPVirtualAddress(ip net.IP) {
	dvg.vaddrs = append(dvg.vaddrs, ip)
}

func (dni *deletedNI) String() string {
	str := fmt.Sprintf("%s: %v: self=%v ", dni.name, dni.niType, dni.self)

	str += "interfaces="
	for _, vif := range dni.vifs {
		str += vif + ","
	}

	switch dni.niType {
	case NI_L2VSI, NI_MAT:
		str += " vlans="
		for _, vid := range dni.vlans {
			str += fmt.Sprintf("%d,", vid)
		}
	case NI_L3VRF:
		str += " SAD="
		for _, spi := range dni.sad {
			str += fmt.Sprintf("%d", spi)
		}
		str += " SPD="
		for _, name := range dni.spd {
			str += name + ","
		}
	}
	return str
}

func (di *deletedIface) String() string {
	str := fmt.Sprintf("%s: self=%v ", di.name, di.self)

	str += "VID="
	for _, vid := range di.vids {
		str += fmt.Sprintf("%d,", vid)
	}

	for id, dsi := range di.subs {
		str += fmt.Sprintf("\n\tSUB(%d): self=%v ip=", id, dsi.self)
		for _, ip := range dsi.ipaddr {
			str += ip.String() + ","
		}
	}
	return str
}

func (o *openconfig) getDeletedNetworkInstance(name string, niType niType) *deletedNI {
	dn, ok := o.dnis[name]
	if !ok {
		dn = &deletedNI{
			name:   name,
			niType: niType,
		}
		o.dnis[name] = dn
	}
	return dn
}

func (o *openconfig) getDeletedInterface(name string) *deletedIface {
	di, ok := o.difs[name]
	if !ok {
		di = &deletedIface{
			name: name,
		}
		o.difs[name] = di
	}
	return di
}
