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

	"github.com/lagopus/vsw/vswitch"
)

/*
* Parser related
 */
var ocdcSetSyntax = []*parserSyntax{
	{
		"network-instances network-instance STRING",
		[]*parserSyntaxEntry{
			{"config enabled BOOL", setNI, niEnabled},
			{"config enabled-address-families STRING", setNI, niAddressFamily},
			{"config type STRING", setNI, niTypes},
			{"interfaces interface STRING subinterface INTEGER", setNI, niInterface},
			{"vlans vlan INTEGER config status STRING", setNI, niVLAN},
			{"fdb config mac-aging-time INTEGER", setNI, niFdbMacAgingTime},
			{"fdb config mac-learning BOOL", setNI, niFdbMacLearning},
			{"fdb config maximum-entries INTEGER", setNI, niFdbMaxEntries},
		},
	},
	{
		"network-instances network-instance STRING security ipsec sad sad-entries INTEGER config",
		[]*parserSyntaxEntry{
			{"sa-mode STRING", setIPSecSAD, sadSAMode},
			{"life-time life-time-in-seconds INTEGER", setIPSecSAD, sadLifeTimeInSec},
			{"life-time life-time-in-byte INTEGER", setIPSecSAD, sadLifeTimeInByte},
			{"local-peer ipv4-address A.B.C.D", setIPSecSAD, sadLocalPeer},
			{"remote-peer ipv4-address A.B.C.D", setIPSecSAD, sadRemotePeer},
			{"esp authentication STRING", setIPSecSAD, sadESPAuth},
			{"esp authentication STRING key-str STRING", setIPSecSAD, sadESPAuthKey},
			{"esp encryption STRING", setIPSecSAD, sadESPEncrypt},
			{"esp encryption STRING key-str STRING", setIPSecSAD, sadESPEncryptKey},
			{"encap-protocol STRING", setIPSecSAD, sadEncapProtocol},
			{"encap-src-port INTEGER", setIPSecSAD, sadEncapSrcPort},
			{"encap-dst-port INTEGER", setIPSecSAD, sadEncapDstPort},
		},
	},
	{
		"network-instances network-instance STRING security ipsec spd spd-entries STRING config",
		[]*parserSyntaxEntry{
			{"spi INTEGER", setIPSecSPD, spdSPI},
			{"destination-address ipv4-address A.B.C.D", setIPSecSPD, spdDestinationAddress},
			{"destination-address port-number INTEGER", setIPSecSPD, spdDestinationPort},
			{"destination-address prefix-length INTEGER", setIPSecSPD, spdDestinationPrefix},
			{"source-address ipv4-address A.B.C.D", setIPSecSPD, spdSourceAddress},
			{"source-address port-number INTEGER", setIPSecSPD, spdSourcePort},
			{"source-address prefix-length INTEGER", setIPSecSPD, spdSourcePrefix},
			{"upper-protocol STRING", setIPSecSPD, spdUpperProtocol},
			{"direction STRING", setIPSecSPD, spdDirection},
			{"security-protocol STRING", setIPSecSPD, spdSecurityProtocol},
			{"priority INTEGER", setIPSecSPD, spdPriority},
			{"policy STRING", setIPSecSPD, spdPolicy},
		},
	},
	{
		"network-instances network-instance STRING pbr-entries STRING",
		[]*parserSyntaxEntry{
			{"priority INTEGER", procPBR, pbrPriority},
			{"ipv4 config source-address A.B.C.D/E", procPBR, pbrSrcIP},
			{"ipv4 config destination-address A.B.C.D/E", procPBR, pbrDstIP},
			{"ipv4 config protocol PROTOCOL", procPBR, pbrProto},
			{"transport config destination-port PORTRANGE", procPBR, pbrDstPort},
			{"transport config source-port PORTRANGE", procPBR, pbrSrcPort},
			{"input-interface interface STRING subinterface INTEGER", procPBR, pbrInInterface},
		},
	},
	{
		"network-instances network-instance STRING pbr-entries STRING action next-hops next-hop STRING",
		[]*parserSyntaxEntry{
			{"network-instance STRING", procPBRNextHop, pbrNexthopNI},
			{"config next-hop A.B.C.D", procPBRNextHop, pbrNexthopAddress},
			{"config weight INTEGER", procPBRNextHop, pbrNexthopWeight},
			{"interface STRING subinterface INTEGER", procPBRNextHop, pbrNexthopIF},
			{"pass", procPBRNextHop, pbrPass},
		},
	},
	{
		"interfaces interface STRING config",
		[]*parserSyntaxEntry{
			{"device STRING", setIF, ifDevice},
			{"driver STRING", setIF, ifDriver},
			{"enabled BOOL", setIF, ifEnabled},
			{"mtu INTEGER", setIF, ifMTU},
			{"type STRING", setIF, ifTypes},
		},
	},
	{
		"interfaces interface STRING tunnel config",
		[]*parserSyntaxEntry{
			{"address-type STRING", setIFTunnel, ifTunnelAddressType},
			{"local-inet-address A.B.C.D", setIFTunnel, ifTunnelLocalAddress},
			{"hop-limit INTEGER", setIFTunnel, ifTunnelHopLimit},
			{"network-instance STRING", setIFTunnel, ifTunnelVRF},
			{"encaps-method STRING", setIFTunnel, ifTunnelEncapsMethod},
			{"remote-inet-address A.B.C.D", setIFTunnel, ifTunnelRemoteAddress},
			{"tos INTEGER", setIFTunnel, ifTunnelTOS},
			{"vxlan vni INTEGER", setIFTunnel, ifTunnelVNI},
		},
	},
	{
		"interfaces interface STRING ethernet",
		[]*parserSyntaxEntry{
			{"config mac-address MACADDR", setIF, ifMACAddr},
			{"switched-vlan config interface-mode STRING", setIF, ifVLANMode},
			{"switched-vlan config access-vlan INTEGER", setIF, ifVLANAccess},
			{"switched-vlan config trunk-vlans INTEGER", setIF, ifVLANTrunk},
		},
	},
	{
		"interfaces interface STRING subinterfaces subinterface INTEGER",
		[]*parserSyntaxEntry{
			{"config enabled BOOL", setIF, ifSubEnabled},
			{"ipv4 addresses address A.B.C.D config prefix-length INTEGER", setIF, ifSubAddress},
			{"vlan config vlan-id INTEGER", setIF, ifSubVLAN},
		},
	},
	{
		"interfaces interface STRING subinterfaces subinterface INTEGER ipv4 addresses address A.B.C.D vrrp vrrp-group INTEGER",
		[]*parserSyntaxEntry{
			{"config virtual-address A.B.C.D...", procSubIFVRRP, ifSubVRRPVirtualAddress},
			{"config priority INTEGER", procSubIFVRRP, ifSubVRRPPriority},
			{"config preempt BOOL", procSubIFVRRP, ifSubVRRPPreempt},
			{"config preempt-delay INTEGER", procSubIFVRRP, ifSubVRRPPreemptDelay},
			{"config accept-mode BOOL", procSubIFVRRP, ifSubVRRPAcceptMode},
			{"config advertisement-interval INTEGER", procSubIFVRRP, ifSubVRRPAdvertisementInterval},
			{"interface-tracking config track-interface STRING", procSubIFVRRP, ifSubVRRPTrackInterface},
			{"interface-tracking config priority-decrement INTEGER", procSubIFVRRP, ifSubVRRPPriorityDecrement},
		},
	},
	{
		"interfaces interface STRING subinterfaces subinterface INTEGER tunnel config",
		[]*parserSyntaxEntry{
			{"address-type STRING", setSubIFTunnel, ifSubTunnelAddressType},
			{"local-inet-address A.B.C.D", setSubIFTunnel, ifSubTunnelLocalAddress},
			{"hop-limit INTEGER", setSubIFTunnel, ifSubTunnelHopLimit},
			{"network-instance STRING", setSubIFTunnel, ifSubTunnelVRF},
			{"encaps-method STRING", setSubIFTunnel, ifSubTunnelEncapsMethod},
			{"remote-inet-address A.B.C.D", setSubIFTunnel, ifSubTunnelRemoteAddress},
			{"security STRING", setSubIFTunnel, ifSubTunnelSecurity},
			{"tos INTEGER", setSubIFTunnel, ifSubTunnelTOS},
		},
	},
	{
		"interfaces interface STRING subinterfaces subinterface INTEGER ipv4 napt config",
		[]*parserSyntaxEntry{
			{"enabled BOOL", procSubIFNAPT, ifSubNAPTEnabled},
			{"maximum-entries INTEGER", procSubIFNAPT, ifSubNAPTMaximumEntries},
			{"aging-time INTEGER", procSubIFNAPT, ifSubNAPTAgingTime},
			{"port-range MIN..MAX", procSubIFNAPT, ifSubNAPTPortRange},
			{"address A.B.C.D", procSubIFNAPT, ifSubNAPTAddress},
		},
	},
}

type ocdcTypeUnexpectedError ocdcType

func (o ocdcTypeUnexpectedError) Error() string {
	return fmt.Sprintf("Unexpected ocdcType %v found", o)
}

type ocdcType int

const (
	niSelf ocdcType = iota
	niEnabled
	niAddressFamily
	niTypes
	niInterface
	niVLAN
	niFdbMacAgingTime
	niFdbMacLearning
	niFdbMaxEntries

	ifSelf
	ifDevice
	ifDriver
	ifEnabled
	ifMTU
	ifTypes
	ifMACAddr
	ifVLANMode
	ifVLANAccess
	ifVLANTrunk
	ifSubSelf
	ifSubEnabled
	ifSubAddress
	ifSubVLAN

	ifTunnelAddressType
	ifTunnelEncapsMethod
	ifTunnelHopLimit
	ifTunnelLocalAddress
	ifTunnelRemoteAddress
	ifTunnelTOS
	ifTunnelVRF
	ifTunnelVNI

	ifSubTunnelAddressType
	ifSubTunnelEncapsMethod
	ifSubTunnelHopLimit
	ifSubTunnelLocalAddress
	ifSubTunnelRemoteAddress
	ifSubTunnelSecurity
	ifSubTunnelTOS
	ifSubTunnelVRF

	ifSubVRRPGroup
	ifSubVRRPVirtualAddress
	ifSubVRRPPriority
	ifSubVRRPPreempt
	ifSubVRRPPreemptDelay
	ifSubVRRPAcceptMode
	ifSubVRRPAdvertisementInterval
	ifSubVRRPTrackInterface
	ifSubVRRPPriorityDecrement

	ifSubNAPTEnabled
	ifSubNAPTMaximumEntries
	ifSubNAPTAgingTime
	ifSubNAPTPortRange
	ifSubNAPTAddress

	sadSPI
	sadSAMode
	sadLifeTimeInSec
	sadLifeTimeInByte
	sadLocalPeer
	sadRemotePeer
	sadESPAuth
	sadESPAuthKey
	sadESPEncrypt
	sadESPEncryptKey
	sadEncapProtocol
	sadEncapSrcPort
	sadEncapDstPort

	spdName
	spdSPI
	spdDestinationAddress
	spdDestinationPort
	spdDestinationPrefix
	spdSourceAddress
	spdSourcePort
	spdSourcePrefix
	spdUpperProtocol
	spdDirection
	spdSecurityProtocol
	spdPriority
	spdPolicy

	// for show command
	niInstances
	niStatus
	niStatusState
	niFdb
	niFdbState
	niFdbMacTable
	niFdbMacEntry
	niIFs
	niIF
	niVLANs
	niSecurity
	niSAD
	niSADEntry
	niSPD
	niSPDEntry

	ifInstances
	ifStatus
	ifStatusState
	ifCounters
	ifTunnel

	ifSubs
	ifSub
	ifSubVLANId
	ifSubState
	ifSubCounters
	ifSubAddresses
	ifSubAddressEnabled
	ifSubTunnel

	ifEthernet

	pbrPriority
	pbrSrcIP
	pbrDstIP
	pbrProto
	pbrDstPort
	pbrSrcPort
	pbrInInterface
	pbrNexthopNI
	pbrNexthopAddress
	pbrNexthopWeight
	pbrNexthopIF
	pbrPass
)

func (o ocdcType) String() string {
	s := map[ocdcType]string{
		niSelf:                   "niSelf",
		niEnabled:                "niEnabled",
		niAddressFamily:          "niAddressFamily",
		niTypes:                  "niType",
		niInterface:              "niInterface",
		niVLAN:                   "niVLAN",
		niFdbMacAgingTime:        "niFdbMacAgingTime",
		niFdbMacLearning:         "niFdbMacLearning",
		niFdbMaxEntries:          "niFdbMaxEntries",
		ifSelf:                   "ifSelf",
		ifDevice:                 "ifDevice",
		ifDriver:                 "ifDriver",
		ifEnabled:                "ifEnabled",
		ifMTU:                    "ifMTU",
		ifTypes:                  "ifType",
		ifMACAddr:                "ifMACAddr",
		ifVLANMode:               "ifVLANMode",
		ifVLANAccess:             "ifVLANAccess",
		ifVLANTrunk:              "ifVLANTrunk",
		ifSubSelf:                "ifSubSelf",
		ifSubEnabled:             "ifSubEnabled",
		ifSubAddress:             "ifSubAddress",
		ifSubVLAN:                "ifSubVLAN",
		ifSubTunnelEncapsMethod:  "ifSubTunnelEncapsMethod",
		ifSubTunnelHopLimit:      "ifSubTunnelHopLimit",
		ifSubTunnelLocalAddress:  "ifSubTunnelLocalAddress",
		ifSubTunnelRemoteAddress: "ifSubTunnelRemoteAddress",
		ifSubTunnelSecurity:      "ifSubTunnelSecurity",
		ifSubTunnelTOS:           "ifSubTunnelTOS",
		ifSubNAPTEnabled:         "ifSubNAPTEnabled",
		ifSubNAPTMaximumEntries:  "ifSubNAPTMaximumEntries",
		ifSubNAPTAgingTime:       "ifSubNAPTAgingTime",
		ifSubNAPTPortRange:       "ifSubNAPTPortRange",
		ifSubNAPTAddress:         "ifSubNAPTAddress",
		sadSPI:                   "sadSPI",
		sadSAMode:                "sadSAMode",
		sadLifeTimeInSec:         "sadLifeTimeInSec",
		sadLifeTimeInByte:        "sadLifeTimeInByte",
		sadLocalPeer:             "sadLocalPeer",
		sadRemotePeer:            "sadRemotePeer",
		sadESPAuth:               "sadESPAuth",
		sadESPAuthKey:            "sadESPAuthKey",
		sadESPEncrypt:            "sadESPEncrypt",
		sadESPEncryptKey:         "sadESPEncryptKey",
		spdName:                  "spdName",
		spdSPI:                   "spdSPI",
		spdDestinationAddress:    "spdDestinationAddress",
		spdDestinationPort:       "spdDestinationPort",
		spdDestinationPrefix:     "spdDestinationPrefix",
		spdSourceAddress:         "spdSourceAddress",
		spdSourcePort:            "spdSourcePort",
		spdSourcePrefix:          "spdSourcePrefix",
		spdUpperProtocol:         "spdUpperProtocol",
		spdDirection:             "spdDirection",
		spdSecurityProtocol:      "spdSecurityProtocol",
		spdPriority:              "spdPriority",
		spdPolicy:                "spdPolicy",

		niInstances:         "niInstances",
		niStatus:            "niStatus",
		niStatusState:       "niStatusState",
		niFdb:               "niFdb",
		niFdbState:          "niFdbState",
		niFdbMacTable:       "niFdbMacTable",
		niFdbMacEntry:       "niFdbMacEntry",
		niIFs:               "niIFs",
		niIF:                "niIF",
		niVLANs:             "niVLANs",
		niSecurity:          "niSecurity",
		niSAD:               "niSAD",
		niSADEntry:          "niSADEntry",
		niSPD:               "niSPD",
		niSPDEntry:          "niSPDEntry",
		ifInstances:         "ifInstances",
		ifStatus:            "ifStatus",
		ifStatusState:       "ifStatusState",
		ifCounters:          "ifCounters",
		ifTunnel:            "ifTunnel",
		ifSubs:              "ifSubs",
		ifSub:               "ifSub",
		ifSubVLANId:         "ifSubVLANId",
		ifSubState:          "ifSubState",
		ifSubCounters:       "ifSubCounters",
		ifSubAddresses:      "ifSubAddresses",
		ifSubAddressEnabled: "ifSubAddressEnable",
		ifSubTunnel:         "ifSubTunnel",
		ifEthernet:          "ifEthernet",

		pbrPriority:       "pbrPriority",
		pbrSrcIP:          "pbrSrcIP",
		pbrDstIP:          "pbrDstIP",
		pbrProto:          "pbrProto",
		pbrSrcPort:        "pbrSrcPort",
		pbrDstPort:        "pbrDstPort",
		pbrInInterface:    "pbrInInterface",
		pbrNexthopNI:      "pbrNexthopNI",
		pbrNexthopAddress: "pbrNexthopAddress",
		pbrNexthopWeight:  "pbrNexthopWeight",
		pbrNexthopIF:      "pbrNexthopIF",
		pbrPass:           "pbrPass",
	}
	return s[o]
}

/*
 * Callbacks called from parser
 */

func setNI(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	oc := (v).(*openconfig)
	ni := oc.getNetworkInstance(args[0].(string))

	switch key {
	case niEnabled:
		ni.setEnabled(args[1].(bool))
	case niAddressFamily:
		ni.addAddressFamily(args[1].(string))
	case niTypes:
		if err := ni.setType(args[1].(string)); err != nil {
			return nil, err
		}
	case niInterface:
		ni.addInterface(args[1].(string), args[2].(int))
	case niVLAN:
		ni.addVID(args[1].(int), args[2].(string))
	case niFdbMacAgingTime:
		ni.setMacAgingTime(args[1].(int))
	case niFdbMacLearning:
		ni.setMacLearning(args[1].(bool))
	case niFdbMaxEntries:
		ni.setMaximumEntries(args[1].(int))
	default:
		return nil, ocdcTypeUnexpectedError(key)
	}

	return ni, nil
}

func setIPSecSAD(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	oc := (v).(*openconfig)
	ni := oc.getNetworkInstance(args[0].(string))
	spi := args[1].(int)

	switch key {
	case sadSAMode:
		ni.setSAMode(spi, args[2].(string))
	case sadLifeTimeInSec:
		ni.setLifeTimeInSeconds(spi, args[2].(int))
	case sadLifeTimeInByte:
		ni.setLifeTimeInByte(spi, args[2].(int))
	case sadLocalPeer:
		ni.setLocalPeer(spi, args[2].(net.IP))
	case sadRemotePeer:
		ni.setRemotePeer(spi, args[2].(net.IP))

	case sadESPAuthKey:
		ni.setAuthKey(spi, args[3].(string))
		fallthrough // We must set algorithm as well
	case sadESPAuth:
		ni.setAuth(spi, args[2].(string))

	case sadESPEncryptKey:
		ni.setEncryptKey(spi, args[3].(string))
		fallthrough // We must set algorithm as well
	case sadESPEncrypt:
		if err := ni.setEncrypt(spi, args[2].(string)); err != nil {
			return nil, err
		}

	case sadEncapProtocol:
		if err := ni.setEncapProtocol(spi, args[2].(string)); err != nil {
			return nil, err
		}

	case sadEncapSrcPort:
		ni.setEncapSrcPort(spi, args[2].(int))

	case sadEncapDstPort:
		ni.setEncapDstPort(spi, args[2].(int))

	default:
		return nil, ocdcTypeUnexpectedError(key)
	}

	return ni, nil
}

func setIPSecSPD(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	oc := (v).(*openconfig)
	ni := oc.getNetworkInstance(args[0].(string))
	name := args[1].(string)

	switch key {
	case spdSPI:
		ni.setSPI(name, args[2].(int))
	case spdDestinationAddress:
		ni.setDstAddress(name, args[2].(net.IP))
	case spdDestinationPort:
		ni.setDstPort(name, args[2].(int))
	case spdDestinationPrefix:
		ni.setDstPrefix(name, args[2].(int))
	case spdSourceAddress:
		ni.setSrcAddress(name, args[2].(net.IP))
	case spdSourcePort:
		ni.setSrcPort(name, args[2].(int))
	case spdSourcePrefix:
		ni.setSrcPrefix(name, args[2].(int))
	case spdUpperProtocol:
		ni.setUpperProtocol(name, args[2].(string))
	case spdDirection:
		ni.setDirection(name, args[2].(string))
	case spdSecurityProtocol:
		ni.setSecurityProtocol(name, args[2].(string))
	case spdPriority:
		ni.setPriority(name, args[2].(int))
	case spdPolicy:
		ni.setPolicy(name, args[2].(string))
	default:
		return nil, ocdcTypeUnexpectedError(key)
	}

	return ni, nil
}

func setIF(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	oc := (v).(*openconfig)
	i := oc.getInterface(args[0].(string))
	var err error

	switch key {
	case ifDevice:
		err = i.setDevice(args[1].(string))
	case ifDriver:
		err = i.setDriver(args[1].(string))
	case ifEnabled:
		i.setEnabled(args[1].(bool))
	case ifMTU:
		i.setMTU(args[1].(int))
	case ifTypes:
		err = i.setType(args[1].(string))
	case ifMACAddr:
		i.setMACAddr(args[1].(net.HardwareAddr))
	case ifVLANMode:
		i.setVLANMode(args[1].(string))
	case ifVLANAccess, ifVLANTrunk:
		i.addVID(args[1].(int))
	case ifSubEnabled:
		i.getSubiface(args[1].(int)).setEnabled(args[2].(bool))
	case ifSubAddress:
		i.getSubiface(args[1].(int)).addAddress(args[2].(net.IP), args[3].(int))
	case ifSubVLAN:
		i.getSubiface(args[1].(int)).setVID(args[2].(int))
	default:
		err = ocdcTypeUnexpectedError(key)
	}

	if err != nil {
		return nil, err
	}
	return i, nil
}

func setIFTunnel(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	oc := (v).(*openconfig)
	i := oc.getInterface(args[0].(string))
	t := i.getTunnel()

	switch key {
	case ifTunnelAddressType:
		t.setAddressType(args[1].(string))
	case ifTunnelEncapsMethod:
		t.setEncapsMethod(args[1].(string))
	case ifTunnelHopLimit:
		t.setHopLimit(args[1].(int))
	case ifTunnelLocalAddress:
		t.setLocalAddress(args[1].(net.IP))
	case ifTunnelRemoteAddress:
		t.addRemoteAddress(args[1].(net.IP))
	case ifTunnelTOS:
		t.setTOS(args[1].(int))
	case ifTunnelVRF:
		t.setVRF(args[1].(string))
	case ifTunnelVNI:
		t.setVNI(args[1].(int))
	default:
		return nil, ocdcTypeUnexpectedError(key)
	}

	return i, nil
}

func setSubIFTunnel(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	oc := (v).(*openconfig)
	i := oc.getInterface(args[0].(string))
	t := i.getSubiface(args[1].(int)).getTunnel()

	switch key {
	case ifSubTunnelAddressType:
		t.setAddressType(args[2].(string))
	case ifSubTunnelEncapsMethod:
		t.setEncapsMethod(args[2].(string))
	case ifSubTunnelHopLimit:
		t.setHopLimit(args[2].(int))
	case ifSubTunnelLocalAddress:
		t.setLocalAddress(args[2].(net.IP))
	case ifSubTunnelRemoteAddress:
		t.addRemoteAddress(args[2].(net.IP))
	case ifSubTunnelSecurity:
		t.setSecurity(args[2].(string))
	case ifSubTunnelTOS:
		t.setTOS(args[2].(int))
	case ifSubTunnelVRF:
		t.setVRF(args[2].(string))
	default:
		return nil, ocdcTypeUnexpectedError(key)
	}

	return i, nil
}

func procSubIFVRRP(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	oc := (v).(*openconfig)
	i := oc.getInterface(args[0].(string))
	vg := i.getSubiface(args[1].(int)).getVrrpGroup(args[2].(net.IP), args[3].(int))

	switch key {
	case ifSubVRRPVirtualAddress:
		for i := 4; i < len(args); i++ {
			vg.AddVirtualAddr(args[i].(net.IP))
		}
	case ifSubVRRPPriority:
		vg.Priority = uint8(args[4].(int))
	case ifSubVRRPPreempt:
		vg.Preempt = args[4].(bool)
	case ifSubVRRPPreemptDelay:
		vg.PreemptDelay = uint16(args[4].(int))
	case ifSubVRRPAcceptMode:
		vg.AcceptMode = args[4].(bool)
	case ifSubVRRPAdvertisementInterval:
		vg.AdvertisementInterval = uint16(args[4].(int))
	case ifSubVRRPTrackInterface:
		vg.TrackInterface = args[4].(string)
	case ifSubVRRPPriorityDecrement:
		vg.PriorityDecrement = uint8(args[4].(int))
	default:
		return nil, ocdcTypeUnexpectedError(key)
	}

	return i, nil
}

func procSubIFNAPT(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	oc := (v).(*openconfig)
	i := oc.getInterface(args[0].(string))
	n := i.getSubiface(args[1].(int)).getNAPT()

	switch key {
	case ifSubNAPTEnabled:
		n.enabled = args[2].(bool)
	case ifSubNAPTMaximumEntries:
		n.maximumEntries = uint(args[2].(int))
	case ifSubNAPTAgingTime:
		n.agingTime = uint(args[2].(int))
	case ifSubNAPTPortRange:
		rv := args[2].(*rangeValue)
		n.portRange = &vswitch.PortRange{Start: uint16(rv.min), End: uint16(rv.max)}
	case ifSubNAPTAddress:
		n.address = args[2].(net.IP)
	default:
		return nil, ocdcTypeUnexpectedError(key)
	}

	return i, nil
}

func procPBR(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	oc := (v).(*openconfig)
	ni := oc.getNetworkInstance(args[0].(string))
	p := ni.getPBREntry(args[1].(string))

	switch key {
	case pbrSrcIP:
		p.srcAddr = args[2].(vswitch.IPAddr)
	case pbrDstIP:
		p.dstAddr = args[2].(vswitch.IPAddr)
	case pbrSrcPort:
		p.srcPort = args[2].(*vswitch.PortRange)
	case pbrDstPort:
		p.dstPort = args[2].(*vswitch.PortRange)
	case pbrProto:
		p.protocol = args[2].(vswitch.IPProto)
	case pbrPriority:
		p.priority = uint(args[2].(int))
	case pbrInInterface:
		p.inInterface = fmt.Sprintf("%s-%d", args[2].(string), args[3].(int))
	default:
		return nil, ocdcTypeUnexpectedError(key)
	}
	return ni, nil
}

func procPBRNextHop(v interface{}, key ocdcType, args []interface{}) (interface{}, error) {
	oc := (v).(*openconfig)
	ni := oc.getNetworkInstance(args[0].(string))
	p := ni.getPBREntry(args[1].(string))
	nh := p.getNexthopEntry(args[2].(string))

	switch key {
	case pbrNexthopNI:
		nh.nhNI = args[3].(string)
	case pbrNexthopAddress:
		nh.addr.IP = args[3].(net.IP)
	case pbrNexthopWeight:
		nh.weight = uint32(args[3].(int))
	case pbrNexthopIF:
		nh.outInterface = fmt.Sprintf("%s-%d", args[3].(string), args[4].(int))
	case pbrPass:
		nh.action = vswitch.PBRActionPass
	default:
		return nil, ocdcTypeUnexpectedError(key)
	}
	return ni, nil
}

/*
* Configration related
 */

const (
	DRIVER_DPDK   = "dpdk"
	DRIVER_RIF    = "rif"
	DRIVER_TUNNEL = "tunnel"
)

// drvType is a Driver type
type drvType int

const (
	DRV_UNKNOWN drvType = iota
	DRV_DPDK
	DRV_LOCAL
)

func (d drvType) String() string {
	str := map[drvType]string{
		DRV_UNKNOWN: "unknown",
		DRV_DPDK:    "dpdk",
		DRV_LOCAL:   "local",
	}
	return str[d]
}

// ifType is an interface type
type ifType int

const (
	IF_UNKNOWN ifType = iota
	IF_ETHERNETCSMACD
	IF_TUNNEL
)

func (i ifType) String() string {
	str := map[ifType]string{
		IF_UNKNOWN:        "unknown",
		IF_ETHERNETCSMACD: "ethernetCsmacd",
		IF_TUNNEL:         "tunnel",
	}
	return str[i]
}

func (i ifType) MarshalJSON() ([]byte, error) {
	return []byte(`"` + i.String() + `"`), nil
}

// niType is a network-instance type
type niType int

const (
	NI_UNKNOWN niType = iota
	NI_L2VSI
	NI_L3VRF
	NI_MAT
)

func (n niType) String() string {
	str := map[niType]string{
		NI_UNKNOWN: "unknown",
		NI_L2VSI:   "L2VSI",
		NI_L3VRF:   "L3VRF",
		NI_MAT:     "LagopusMAT",
	}
	return str[n]
}

func (n niType) MarshalJSON() ([]byte, error) {
	return []byte(`"` + n.String() + `"`), nil
}

// afType is an address family type
type afType int

const (
	AF_IPV4 afType = 1 << iota
	AF_IPV6
)

func (a afType) String() string {
	str := ""
	switch a {
	case AF_IPV4 | AF_IPV6:
		str = "IPV4&6"
	case AF_IPV4:
		str = "IPV4"
	case AF_IPV6:
		str = "IPV6"
	}
	return str
}

// iface represents an interface
type iface struct {
	name    string
	driver  drvType
	device  string
	iftype  ifType
	enabled bool
	mtu     vswitch.MTU
	mac     net.HardwareAddr
	ifmode  vswitch.VLANMode
	vids    map[vswitch.VID]struct{}
	subs    map[int]*subiface
	tunnel  *l2tunnel
}

type ipaddr struct {
	ip   vswitch.IPAddr
	vrrp map[vswitch.VRID]*vswitch.VRRPGroup
}

// subiface represents a subinterface
type subiface struct {
	name    string
	enabled bool
	id      uint32
	iface   *iface
	ni      map[string]*ni
	vid     vswitch.VID
	ipaddr  map[string]*ipaddr
	tunnel  *l3tunnel
	napt    *napt
}

// tunnel represents common part of L2/L3 tunnel configs
type tunnel struct {
	af      vswitch.AddressFamily
	em      vswitch.EncapsMethod
	hl      uint8
	local   net.IP
	remotes []net.IP
	tos     int
	vrf     string
}

// l2tunnel represents L2 Tunnel configuration
type l2tunnel struct {
	*tunnel
	vni uint32
}

// l3tunnel represents L3 Tunnel configuration
type l3tunnel struct {
	*tunnel
	sec vswitch.Security
}

type napt struct {
	enabled        bool
	maximumEntries uint
	agingTime      uint
	portRange      *vswitch.PortRange
	address        net.IP
}

type vlan struct {
	vid    int
	active bool
}

// nexthop entry
type nh struct {
	nhNI         string            // nexthop: ni name
	addr         vswitch.IPAddr    // nexthop: nexthop address
	weight       uint32            // nexthop: nexthop weight
	outInterface string            // nexthop: output interface
	action       vswitch.PBRAction // nexthop: action type
}

// pbr entry
type pe struct {
	priority    uint               // rule: priority
	srcAddr     vswitch.IPAddr     // rule: src address and mask
	dstAddr     vswitch.IPAddr     // rule: dst address and mask
	srcPort     *vswitch.PortRange // rule: src port range
	dstPort     *vswitch.PortRange // rule: dst port range
	inInterface string             // rule: input interface
	protocol    vswitch.IPProto    // rule: protorcol
	nhs         map[string]*nh
}

// ni represents a network-instance
type ni struct {
	// L2VSI/L3VRF Common
	name    string
	niType  niType
	enabled bool
	vifs    map[string]*subiface // key=subinterface name, e.g. "if1-200"
	oc      *openconfig

	// L2VSI/LagopusMAT
	vlans          map[vswitch.VID]bool
	macLearning    bool
	macAgingTime   int
	maximumEntries int

	// L3VRF
	af  afType
	rd  uint64
	sad map[uint32]*vswitch.SA
	spd map[string]*vswitch.SP
	pbr map[string]*pe
}

func newInterface(o *openconfig, name string) *iface {
	return &iface{
		name: name,
		vids: make(map[vswitch.VID]struct{}),
		subs: make(map[int]*subiface),
	}
}

func (i *iface) setDevice(s string) error {
	if i.device != "" && s != "" {
		return fmt.Errorf("Device already set to %v", i.device)
	}
	i.device = s
	return nil
}

func (i *iface) setDriver(s string) error {
	if i.driver != DRV_UNKNOWN {
		return fmt.Errorf("Driver already set to %v", i.driver)
	}
	switch s {
	case "dpdk":
		i.driver = DRV_DPDK
	case "local":
		i.driver = DRV_LOCAL
	}
	return nil
}

func (i *iface) setType(s string) error {
	if i.iftype != IF_UNKNOWN {
		return fmt.Errorf("Driver already set to %v", i.iftype)
	}
	switch s {
	case "ethernetCsmacd":
		i.iftype = IF_ETHERNETCSMACD
	case "tunnel":
		i.iftype = IF_TUNNEL
	}
	return nil
}

func (i *iface) setEnabled(e bool) {
	i.enabled = e
}

func (i *iface) setMTU(mtu int) {
	i.mtu = vswitch.MTU(mtu)
}

func (i *iface) setMACAddr(mac net.HardwareAddr) {
	i.mac = mac
}

func (i *iface) setVLANMode(s string) {
	switch s {
	case "ACCESS":
		i.ifmode = vswitch.AccessMode
	case "TRUNK":
		i.ifmode = vswitch.TrunkMode
	}
}

func (i *iface) addVID(v int) {
	i.vids[vswitch.VID(v)] = struct{}{}
}

func (i *iface) deleteVID(v int) {
	delete(i.vids, vswitch.VID(v))
}

func (i *iface) getSubiface(id int) *subiface {
	s, ok := i.subs[id]

	if !ok {
		s = &subiface{
			name:   fmt.Sprintf("%s-%d", i.name, id),
			iface:  i,
			id:     uint32(id),
			ni:     make(map[string]*ni),
			ipaddr: make(map[string]*ipaddr),
		}
		i.subs[id] = s
	}

	return s
}

func (i *iface) deleteSubiface(id int) {
	delete(i.subs, id)
}

func (i *iface) getTunnel() *l2tunnel {
	if i.tunnel == nil {
		i.tunnel = &l2tunnel{
			tunnel: &tunnel{},
		}
	}
	return i.tunnel
}

func (s *subiface) addNI(ni *ni) {
	s.ni[ni.name] = ni
}

func (s *subiface) deleteNI(ni *ni) {
	delete(s.ni, ni.name)
}

func (s *subiface) setEnabled(e bool) {
	s.enabled = e
}

func createIPAddr(ip net.IP, mask int) vswitch.IPAddr {
	base := 32
	if ip.To4() == nil {
		base = 128
	}
	return vswitch.IPAddr{ip, net.CIDRMask(mask, base)}
}

func (s *subiface) addAddress(ip net.IP, mask int) {
	newip := createIPAddr(ip, mask)
	ipkey := ip.String()
	if s.ipaddr[ipkey] == nil {
		s.ipaddr[ipkey] = &ipaddr{}
	}
	s.ipaddr[ipkey].ip = newip
}

func (s *subiface) deleteAddress(ip net.IP, mask int) {
	delete(s.ipaddr, ip.String())
}

func (s *subiface) setVID(v int) {
	s.vid = vswitch.VID(v)
	if _, ok := s.iface.vids[s.vid]; !ok {
		s.iface.addVID(v)
	}
}

func (s *subiface) getTunnel() *l3tunnel {
	if s.tunnel == nil {
		s.tunnel = &l3tunnel{
			tunnel: &tunnel{},
		}
	}
	return s.tunnel
}

func (s *subiface) getNAPT() *napt {
	if s.napt == nil {
		s.napt = &napt{}
	}
	return s.napt
}

func (s *subiface) deleteVrrp(ip net.IP) {
	delete(s.ipaddr, ip.String())
}

func (s *subiface) deleteVrrpGroup(ip net.IP, vrid int) {
	ipkey := ip.String()
	ipaddr := s.ipaddr[ipkey]
	if ipaddr == nil || ipaddr.vrrp == nil {
		return
	}
	if ipaddr.vrrp[vswitch.VRID(vrid)] != nil {
		delete(s.ipaddr[ipkey].vrrp, vswitch.VRID(vrid))
	}
	if len(s.ipaddr[ipkey].vrrp) == 0 {
		s.ipaddr[ipkey].vrrp = nil
	}
}

func (s *subiface) deleteVrrpVirtualAddress(ip net.IP, vrid int, vip net.IP) {
	ipaddr := s.ipaddr[ip.String()]
	if ipaddr == nil || ipaddr.vrrp == nil {
		return
	}
	if vg := ipaddr.vrrp[vswitch.VRID(vrid)]; vg != nil {
		vg.DeleteVirtualAddr(ip)
	}
}

func (s *subiface) getVrrpGroup(ip net.IP, vrid int) *vswitch.VRRPGroup {
	ipkey := ip.String()
	if s.ipaddr[ipkey] == nil {
		s.ipaddr[ipkey] = &ipaddr{}
	}
	if s.ipaddr[ipkey].vrrp == nil {
		s.ipaddr[ipkey].vrrp = make(map[vswitch.VRID]*vswitch.VRRPGroup)
	}
	vg := s.ipaddr[ipkey].vrrp[vswitch.VRID(vrid)]
	if vg == nil {
		vg = &vswitch.VRRPGroup{VirtualRouterId: vswitch.VRID(vrid)}
		s.ipaddr[ipkey].vrrp[vswitch.VRID(vrid)] = vg
	}
	return vg
}

func (t *tunnel) setAddressType(a string) {
	switch a {
	case "IPV4":
		t.af = vswitch.AF_IPv4
	}
}

func (t *tunnel) setEncapsMethod(m string) {
	switch m {
	case "direct":
		t.em = vswitch.EncapsMethodDirect
	case "gre":
		t.em = vswitch.EncapsMethodGRE
	case "vxlan":
		t.em = vswitch.EncapsMethodVxLAN
	}
}

func (t *tunnel) setHopLimit(v int) {
	t.hl = uint8(v)
}

func (t *tunnel) setLocalAddress(ip net.IP) {
	t.local = ip
}

func (t *tunnel) addRemoteAddress(ip net.IP) {
	t.remotes = append(t.remotes, ip)
}

func (t *tunnel) setTOS(tos int) {
	t.tos = tos
}

func (t *tunnel) setVRF(vrf string) {
	t.vrf = vrf
}

func (t *l2tunnel) setVNI(vni int) {
	t.vni = uint32(vni)
}

func (t *l3tunnel) setSecurity(sec string) {
	switch sec {
	case "none":
		t.sec = vswitch.SecurityNone
	case "ipsec":
		t.sec = vswitch.SecurityIPSec
	}
}

func newNetworkInstance(o *openconfig, name string) *ni {
	return &ni{
		name: name,
		vifs: make(map[string]*subiface),
		oc:   o,
	}
}

func (n *ni) setEnabled(e bool) {
	n.enabled = e
}

func (n *ni) addAddressFamily(s string) {
	switch s {
	case "IPV4":
		n.af |= AF_IPV4
	case "IPV6":
		n.af |= AF_IPV6
	}
}

func (n *ni) deleteAddressFamily(s string) {
	switch s {
	case "IPV4":
		n.af &^= AF_IPV4
	case "IPV6":
		n.af &^= AF_IPV6
	}
}

var rdseq uint64

func (n *ni) setType(s string) error {
	if n.niType.String() == s {
		return nil
	}
	if n.niType != NI_UNKNOWN {
		return fmt.Errorf("Type for %v is already set to %v", n.name, n.niType)
	}
	switch s {
	case "L2VSI":
		n.niType = NI_L2VSI
	case "L3VRF":
		n.niType = NI_L3VRF
		n.rd = rdseq
		rdseq++
	case "LagopusMAT":
		n.niType = NI_MAT
	}
	return nil
}

func (n *ni) addInterface(iface string, id int) {
	s := n.oc.getInterface(iface).getSubiface(id)
	s.addNI(n)
	n.vifs[s.name] = s
}

func (n *ni) deleteInterface(iface string, id uint32) {
	name := fmt.Sprintf("%s-%d", iface, id)
	if s, ok := n.vifs[name]; ok {
		s.deleteNI(n)
		delete(n.vifs, name)
	}
}

func (n *ni) addVID(v int, status string) {
	if n.vlans == nil {
		n.vlans = make(map[vswitch.VID]bool)
	}

	vid := vswitch.VID(v)
	switch status {
	case "ACTIVE":
		n.vlans[vid] = true
	case "SUSPENDED":
		n.vlans[vid] = false
	}
}

func (n *ni) deleteVID(vid int) {
	delete(n.vlans, vswitch.VID(vid))
}

func (n *ni) setMacAgingTime(v int) {
	n.macAgingTime = v
}

func (n *ni) setMaximumEntries(v int) {
	n.maximumEntries = v
}

func (n *ni) setMacLearning(e bool) {
	n.macLearning = e
}

func (n *ni) getSA(index int) *vswitch.SA {
	spi := uint32(index)

	if n.sad == nil {
		n.sad = make(map[uint32]*vswitch.SA)
	}

	sa, ok := n.sad[spi]

	if !ok {
		v := vswitch.NewSA(spi)
		sa = &v
		n.sad[spi] = sa
	}

	return sa
}

func (n *ni) deleteSA(index uint32) {
	delete(n.sad, index)
}

func (n *ni) setSAMode(spi int, mode string) error {
	m := vswitch.ModeUndefined
	switch mode {
	case "tunnel":
		m = vswitch.ModeTunnel
	default:
		return fmt.Errorf("Unknown mode: %v", mode)
	}
	n.getSA(spi).Mode = m
	return nil
}

func (n *ni) setLifeTimeInSeconds(spi, sec int) {
	n.getSA(spi).LifeTimeInSeconds = uint32(sec)
}

func (n *ni) setLifeTimeInByte(spi, bytes int) {
	n.getSA(spi).LifeTimeInByte = uint32(bytes)
}

func (n *ni) setLocalPeer(spi int, ip net.IP) {
	n.getSA(spi).LocalPeer = ip
}

func (n *ni) setRemotePeer(spi int, ip net.IP) {
	n.getSA(spi).RemotePeer = ip
}

func (n *ni) setAuth(spi int, auth string) error {
	a := vswitch.AuthUndefined
	switch auth {
	case "null":
		a = vswitch.AuthNULL
	case "hmac-sha1-96":
		a = vswitch.AuthSHA1
	default:
		return fmt.Errorf("Unknown auth algorithm: %v", auth)
	}
	n.getSA(spi).Auth = a
	return nil
}

func (n *ni) setAuthKey(spi int, key string) {
	n.getSA(spi).AuthKey = key
}

func (n *ni) setEncrypt(spi int, enc string) error {
	e := vswitch.EncryptUndefined
	switch enc {
	case "null":
		e = vswitch.EncryptNULL
	case "aes-128-cbc":
		e = vswitch.EncryptAES
	case "aes-128-gcm":
		e = vswitch.EncryptGCM
	default:
		return fmt.Errorf("Unknown encryption algorithm: %v", enc)
	}
	n.getSA(spi).Encrypt = e
	return nil
}

func (n *ni) setEncryptKey(spi int, key string) {
	n.getSA(spi).EncKey = key
}

func (n *ni) setEncapProtocol(spi int, protocol string) error {
	p := vswitch.IPP_NONE
	switch protocol {
	case "udp":
		p = vswitch.IPP_UDP
	case "none":
		p = vswitch.IPP_NONE
	default:
		return fmt.Errorf("Unknown encap protocol: %v", protocol)
	}
	n.getSA(spi).EncapProtocol = p
	return nil
}

func (n *ni) setEncapSrcPort(spi int, port int) {
	n.getSA(spi).EncapSrcPort = uint16(port)
}

func (n *ni) setEncapDstPort(spi int, port int) {
	n.getSA(spi).EncapDstPort = uint16(port)
}

func (n *ni) getSP(name string) *vswitch.SP {
	if n.spd == nil {
		n.spd = make(map[string]*vswitch.SP)
	}

	sp, ok := n.spd[name]

	if !ok {
		v := vswitch.NewSP(name)
		sp = &v
		n.spd[name] = sp
	}

	return sp
}

func (n *ni) deleteSP(name string) {
	delete(n.spd, name)
}

func (n *ni) setSPI(name string, spi int) {
	n.getSP(name).SPI = uint32(spi)
}

func (n *ni) setDstAddress(name string, ip net.IP) {
	n.getSP(name).DstAddress.IP = ip
}

func (n *ni) setDstPort(name string, port int) {
	n.getSP(name).DstPort = uint16(port)
}

func (n *ni) setDstPrefix(name string, prefix int) {
	n.getSP(name).DstAddress.Mask = net.CIDRMask(prefix, 32)
}

func (n *ni) setSrcAddress(name string, ip net.IP) {
	n.getSP(name).SrcAddress.IP = ip
}

func (n *ni) setSrcPort(name string, port int) {
	n.getSP(name).SrcPort = uint16(port)
}

func (n *ni) setSrcPrefix(name string, prefix int) {
	n.getSP(name).SrcAddress.Mask = net.CIDRMask(prefix, 32)
}

func (n *ni) setUpperProtocol(name, protocol string) error {
	var ipp vswitch.IPProto
	switch protocol {
	case "any":
		ipp = vswitch.IPP_ANY
	case "tcp":
		ipp = vswitch.IPP_TCP
	case "udp":
		ipp = vswitch.IPP_UDP
	case "sctp":
		ipp = vswitch.IPP_SCTP
	case "icmp":
		ipp = vswitch.IPP_ICMP
	default:
		return fmt.Errorf("Unsupported upper-protocol: %v", protocol)
	}
	n.getSP(name).UpperProtocol = ipp
	return nil
}

func (n *ni) setDirection(name, direction string) {
	var d vswitch.Direction
	switch direction {
	case "inbound":
		d = vswitch.Inbound
	case "outbound":
		d = vswitch.Outbound
	}
	n.getSP(name).Direction = d
}

func (n *ni) setSecurityProtocol(name, protocol string) error {
	var ipp vswitch.IPProto
	switch protocol {
	case "esp":
		ipp = vswitch.IPP_ESP
	default:
		return fmt.Errorf("Unsupported security-protocol: %v", protocol)
	}
	n.getSP(name).SecurityProtocol = ipp
	return nil
}

func (n *ni) setPriority(name string, priority int) {
	n.getSP(name).Priority = int32(priority)
}

func (n *ni) setPolicy(name, policy string) error {
	var p vswitch.Policy
	switch policy {
	case "discard":
		p = vswitch.Discard
	case "protect":
		p = vswitch.Protect
	default:
		return fmt.Errorf("Unsupported policy: %v", policy)
	}
	n.getSP(name).Policy = p
	return nil
}

func (n *ni) getPBREntry(name string) *pe {
	if n.pbr == nil {
		n.pbr = make(map[string]*pe)
	}

	pbr, ok := n.pbr[name]

	if !ok {
		pbr = &pe{
			protocol: vswitch.IPP_ANY,
			srcPort:  &vswitch.PortRange{},
			dstPort:  &vswitch.PortRange{},
		}
		n.pbr[name] = pbr
	}

	return pbr
}

func (p *pe) getNexthopEntry(name string) *nh {
	if p.nhs == nil {
		p.nhs = make(map[string]*nh)
	}

	nexthop, ok := p.nhs[name]
	if !ok {
		nexthop = &nh{}
		p.nhs[name] = nexthop
	}

	return nexthop
}

func (i *iface) String() string {
	str := fmt.Sprintf("%s: enabled=%v mtu=%d mac=%v driver=%v device=%v iftype=%v mode=%v VID=",
		i.name, i.enabled, i.mtu, i.mac, i.driver, i.device, i.iftype, i.ifmode)

	if len(i.vids) > 0 {
		for v, _ := range i.vids {
			str += fmt.Sprintf("%d,", v)
		}
		str += "\b "
	} else {
		str += "none"
	}

	for n, s := range i.subs {
		str += fmt.Sprintf("\n\tSUB(%d): vid=%d enabled=%v", n, s.vid, s.enabled)
		if len(s.ipaddr) > 0 {
			str += " ip="
			for _, ipaddr := range s.ipaddr {
				str += ipaddr.ip.IP.String() + ","
			}
		}
		if s.tunnel != nil {
			str += fmt.Sprintf(" %v", s.tunnel)
		}
	}

	return str
}

func (n *ni) String() string {
	str := fmt.Sprintf("%s: %v: enabled=%v interfaces=",
		n.name, n.niType, n.enabled)
	for name := range n.vifs {
		str += name + ","
	}
	str += "\b "

	switch n.niType {
	case NI_L2VSI, NI_MAT:
		str += "vlans="
		for v, s := range n.vlans {
			if s {
				str += fmt.Sprintf("%d,", v)
			} else {
				str += fmt.Sprintf("(%d),", v)
			}
		}
		str += "\b "

		str += fmt.Sprintf("learning=%v agingTime=%d maxEntries=%d",
			n.macLearning, n.macAgingTime, n.maximumEntries)
	case NI_L3VRF:
		str += fmt.Sprintf("af=%v", n.af)
		if n.sad != nil {
			str += fmt.Sprintf("\n%d SAD:\n", len(n.sad))
			for _, sa := range n.sad {
				str += fmt.Sprintf("\t%v\n", *sa)
			}
		}
		if n.spd != nil {
			str += fmt.Sprintf("\n%d SPD:\n", len(n.spd))
			for _, sp := range n.spd {
				str += fmt.Sprintf("\t%v\n", *sp)
			}
		}
	}
	return str
}
