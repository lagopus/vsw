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
	"strconv"
	"strings"
)

const (
	TOKEN_STRING   = "STRING"
	TOKEN_BOOL     = "BOOL"
	TOKEN_INTEGER  = "INTEGER"
	TOKEN_IPV4ADDR = "A.B.C.D"
	TOKEN_MACADDR  = "MACADDR"
)

type radixTree struct {
	nodes []*node
}

type nodeKey []string

type node struct {
	key   nodeKey
	value interface{}
	nodes []*node
	depth int
}

func newRadixTree() *radixTree {
	return &radixTree{}
}

func (nk nodeKey) parseInput(input []string) (int, bool, []interface{}) {
	var args []interface{}
	count := 0
	for n, v := range nk {
		if n >= len(input) {
			return count, false, nil
		}

		switch v {
		case TOKEN_STRING:
			args = append(args, input[n])
		case TOKEN_BOOL:
			if v, err := strconv.ParseBool(input[n]); err == nil {
				args = append(args, v)
			} else {
				return count, false, nil
			}
		case TOKEN_INTEGER:
			if v, err := strconv.Atoi(input[n]); err == nil {
				args = append(args, v)
			} else {
				return count, false, nil
			}
		case TOKEN_IPV4ADDR:
			if ip := net.ParseIP(input[n]); ip != nil {
				args = append(args, ip)
			} else {
				return count, false, nil
			}
		case TOKEN_MACADDR:
			if mac, err := net.ParseMAC(input[n]); err == nil {
				args = append(args, mac)
			} else {
				return count, false, nil
			}
		default:
			if strings.Compare(v, input[n]) != 0 {
				return count, false, nil
			}
		}
		count++
	}
	return count, true, args
}

func (nk nodeKey) compareKey(key []string) (int, bool) {
	count := 0
	for n, v := range nk {
		if n >= len(key) || strings.Compare(v, key[n]) != 0 {
			return count, false
		}
		count++
	}
	return count, true
}

func (r *radixTree) lookup(key []string, parse bool) (*node, int, bool, []interface{}) {
	var args []interface{}
	var rc *node

	nodes := r.nodes
	matchedLength := 0
	matched := true
keyLoop:
	for len(key) > 0 {
		for _, node := range nodes {
			var l int
			var pm bool
			var a []interface{}

			if parse {
				l, pm, a = node.key.parseInput(key)
			} else {
				l, pm = node.key.compareKey(key)
			}

			if pm {
				args = append(args, a...)
				key = key[l:]
				matchedLength += l
				nodes = node.nodes
				rc = node
				continue keyLoop
			}
			if l > 0 {
				// Found logest possible match
				return node, l, false, nil
			}
		}
		matched = false
		break
	}
	return rc, matchedLength, matched, args
}

func (r *radixTree) insert(key []string, value interface{}) bool {
	n, l, matched, _ := r.lookup(key, false)
	if n == nil {
		r.nodes = append(r.nodes, &node{key, value, nil, 0})
	} else {
		if matched {
			return false
		} else {
			if len(n.key) > l {
				// Split the node
				snode := &node{n.key[l:], n.value, n.nodes, n.depth + l}
				n.key = n.key[:l]
				n.value = nil
				n.nodes = []*node{
					snode,
					&node{key[l+n.depth:], value, nil, n.depth + l},
				}
			} else {
				// Append the node
				n.nodes = append(n.nodes, &node{key[l:], value, nil, n.depth + len(n.key)})
			}
		}
	}
	return true
}

func (r *radixTree) String() string {
	str := ""
	for _, n := range r.nodes {
		str += fmt.Sprintf("%v\n", n)
	}
	return str
}

func (n *node) String() string {
	return fmt.Sprintf("key=%v(%d){ nodes=%v }", n.key, n.depth, n.nodes)
}

type configure interface {
	getNetworkInstance(string) *ni
	getInterface(string) *iface
}

type parser struct {
	rt *radixTree
	c  configure
}

type parserCallbackFunc func(configure, ocdcType, []interface{}) (interface{}, error)

type parserSyntaxEntry struct {
	pattern  string
	callback parserCallbackFunc
	ocdcType ocdcType
}

type parserSyntax struct {
	prefix string
	syntax []*parserSyntaxEntry
}

var ocdcSyntax = []*parserSyntax{
	{
		"network-instances network-instance STRING",
		[]*parserSyntaxEntry{
			{"config enabled BOOL", procNI, niEnabled},
			{"config enabled-address-families STRING", procNI, niAddressFamily},
			{"config type STRING", procNI, niTypes},
			{"interfaces interface STRING subinterface INTEGER", procNI, niInterface},
			{"vlans vlan INTEGER config status STRING", procNI, niVLAN},
			{"fdb config mac-aging-time INTEGER", procNI, niFdbMacAgingTime},
			{"fdb config mac-learning BOOL", procNI, niFdbMacLearning},
			{"fdb config maximum-entries INTEGER", procNI, niFdbMaxEntries},
		},
	},
	{
		"network-instances network-instance STRING security ipsec sad sad-entries INTEGER config",
		[]*parserSyntaxEntry{
			{"sa-mode STRING", procIPSecSAD, sadSAMode},
			{"life-time life-time-in-seconds INTEGER", procIPSecSAD, sadLifeTimeInSec},
			{"life-time life-time-in-byte INTEGER", procIPSecSAD, sadLifeTimeInByte},
			{"local-peer ipv4-address A.B.C.D", procIPSecSAD, sadLocalPeer},
			{"remote-peer ipv4-address A.B.C.D", procIPSecSAD, sadRemotePeer},
			{"esp authentication STRING", procIPSecSAD, sadESPAuth},
			{"esp authentication STRING key-str STRING", procIPSecSAD, sadESPAuthKey},
			{"esp encryption STRING", procIPSecSAD, sadESPEncrypt},
			{"esp encryption STRING key-str STRING", procIPSecSAD, sadESPEncryptKey},
		},
	},
	{
		"network-instances network-instance STRING security ipsec spd spd-entries STRING config",
		[]*parserSyntaxEntry{
			{"spi INTEGER", procIPSecSPD, spdSPI},
			{"destination-address ipv4-address A.B.C.D", procIPSecSPD, spdDestinationAddress},
			{"destination-address port-number INTEGER", procIPSecSPD, spdDestinationPort},
			{"destination-address prefix-length INTEGER", procIPSecSPD, spdDestinationPrefix},
			{"source-address ipv4-address A.B.C.D", procIPSecSPD, spdSourceAddress},
			{"source-address port-number INTEGER", procIPSecSPD, spdSourcePort},
			{"source-address prefix-length INTEGER", procIPSecSPD, spdSourcePrefix},
			{"upper-protocol STRING", procIPSecSPD, spdUpperProtocol},
			{"direction STRING", procIPSecSPD, spdDirection},
			{"security-protocol STRING", procIPSecSPD, spdSecurityProtocol},
			{"priority INTEGER", procIPSecSPD, spdPriority},
			{"policy STRING", procIPSecSPD, spdPolicy},
		},
	},
	{
		"interfaces interface STRING config",
		[]*parserSyntaxEntry{
			{"device STRING", procIF, ifDevice},
			{"driver STRING", procIF, ifDriver},
			{"enabled BOOL", procIF, ifEnabled},
			{"mtu INTEGER", procIF, ifMTU},
			{"type STRING", procIF, ifTypes},
		},
	},
	{
		"interfaces interface STRING ethernet",
		[]*parserSyntaxEntry{
			{"config mac-address MACADDR", procIF, ifMACAddr},
			{"switched-vlan config interface-mode STRING", procIF, ifVLANMode},
			{"switched-vlan config access-vlan INTEGER", procIF, ifVLANAccess},
			{"switched-vlan config trunk-vlans INTEGER", procIF, ifVLANTrunk},
		},
	},
	{
		"interfaces interface STRING subinterfaces subinterface INTEGER",
		[]*parserSyntaxEntry{
			{"config enabled BOOL", procIF, ifSubEnabled},
			{"ipv4 addresses address A.B.C.D config prefix-length INTEGER", procIF, ifSubAddress},
			{"vlan config vlan-id INTEGER", procIF, ifSubVLAN},
		},
	},
	{
		"interfaces interface STRING subinterfaces subinterface INTEGER tunnel config",
		[]*parserSyntaxEntry{
			{"address-type STRING", procTunnel, ifSubTunnelAddressType},
			{"encaps-method STRING", procTunnel, ifSubTunnelEncapsMethod},
			{"hop-limit INTEGER", procTunnel, ifSubTunnelHopLimit},
			{"local-inet-address A.B.C.D", procTunnel, ifSubTunnelLocalAddress},
			{"remote-inet-address A.B.C.D", procTunnel, ifSubTunnelRemoteAddress},
			{"security STRING", procTunnel, ifSubTunnelSecurity},
			{"tos INTEGER", procTunnel, ifSubTunnelTOS},
		},
	},
}

type ocdcType int

const (
	niEnabled ocdcType = iota
	niAddressFamily
	niTypes
	niInterface
	niVLAN
	niFdbMacAgingTime
	niFdbMacLearning
	niFdbMaxEntries

	ifDevice
	ifDriver
	ifEnabled
	ifMTU
	ifTypes
	ifMACAddr
	ifVLANMode
	ifVLANAccess
	ifVLANTrunk
	ifSubEnabled
	ifSubAddress
	ifSubVLAN

	ifSubTunnelAddressType
	ifSubTunnelEncapsMethod
	ifSubTunnelHopLimit
	ifSubTunnelLocalAddress
	ifSubTunnelRemoteAddress
	ifSubTunnelSecurity
	ifSubTunnelTOS

	sadSAMode
	sadLifeTimeInSec
	sadLifeTimeInByte
	sadLocalPeer
	sadRemotePeer
	sadESPAuth
	sadESPAuthKey
	sadESPEncrypt
	sadESPEncryptKey

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
)

func (o ocdcType) String() string {
	s := map[ocdcType]string{
		niEnabled:                "niEnabled",
		niAddressFamily:          "niAddressFamily",
		niTypes:                  "niType",
		niInterface:              "niInterface",
		niVLAN:                   "niVLAN",
		niFdbMacAgingTime:        "niFdbMacAgingTime",
		niFdbMacLearning:         "niFdbMacLearning",
		niFdbMaxEntries:          "niFdbMaxEntries",
		ifDevice:                 "ifDevice",
		ifDriver:                 "ifDriver",
		ifEnabled:                "ifEnabled",
		ifMTU:                    "ifMTU",
		ifTypes:                  "ifType",
		ifMACAddr:                "ifMACAddr",
		ifVLANMode:               "ifVLANMode",
		ifVLANAccess:             "ifVLANAccess",
		ifVLANTrunk:              "ifVLANTrunk",
		ifSubEnabled:             "ifSubEnabled",
		ifSubAddress:             "ifSubAddress",
		ifSubVLAN:                "ifSubVLAN",
		ifSubTunnelEncapsMethod:  "ifSubTunnelEncapsMethod",
		ifSubTunnelHopLimit:      "ifSubTunnelHopLimit",
		ifSubTunnelLocalAddress:  "ifSubTunnelLocalAddress",
		ifSubTunnelRemoteAddress: "ifSubTunnelRemoteAddress",
		ifSubTunnelSecurity:      "ifSubTunnelSecurity",
		ifSubTunnelTOS:           "ifSubTunnelTOS",
		sadSAMode:                "sadSAMode",
		sadLifeTimeInSec:         "sadLifeTimeInSec",
		sadLifeTimeInByte:        "sadLifeTimeInByte",
		sadLocalPeer:             "sadLocalPeer",
		sadRemotePeer:            "sadRemotePeer",
		sadESPAuth:               "sadESPAuth",
		sadESPAuthKey:            "sadESPAuthKey",
		sadESPEncrypt:            "sadESPEncrypt",
		sadESPEncryptKey:         "sadESPEncryptKey",
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
	}
	return s[o]
}

type ocdcTypeUnexpectedError ocdcType

func (o ocdcTypeUnexpectedError) Error() string {
	return fmt.Sprintf("Unexpected ocdcType %v found", o)
}

type parserError int

const (
	noMatchingSyntaxError parserError = iota
)

func (p parserError) Error() string {
	msg := map[parserError]string{
		noMatchingSyntaxError: "No matching syntax",
	}
	return msg[p]
}

func newParser(c configure) *parser {
	return &parser{newRadixTree(), c}
}

func (p *parser) register(prefix string, syntax *parserSyntaxEntry) bool {
	return p.rt.insert(strings.Fields(prefix+" "+syntax.pattern), syntax)
}

func (p *parser) parse(pattern []string) (interface{}, error) {
	node, _, match, args := p.rt.lookup(pattern, true)

	if !match || node != nil && node.value == nil {
		return nil, noMatchingSyntaxError
	}

	s, _ := node.value.(*parserSyntaxEntry)
	return s.callback(p.c, s.ocdcType, args)
}

func initParser(c configure) *parser {
	p := newParser(c)
	for _, s := range ocdcSyntax {
		for _, e := range s.syntax {
			p.register(s.prefix, e)
		}
	}
	return p
}

func procNI(c configure, key ocdcType, args []interface{}) (interface{}, error) {
	ni := c.getNetworkInstance(args[0].(string))

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

func procIPSecSAD(c configure, key ocdcType, args []interface{}) (interface{}, error) {
	ni := c.getNetworkInstance(args[0].(string))
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
		ni.setEncrypt(spi, args[2].(string))

	default:
		return nil, ocdcTypeUnexpectedError(key)
	}

	return ni, nil
}

func procIPSecSPD(c configure, key ocdcType, args []interface{}) (interface{}, error) {
	ni := c.getNetworkInstance(args[0].(string))
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

func procIF(c configure, key ocdcType, args []interface{}) (interface{}, error) {
	i := c.getInterface(args[0].(string))
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

func procTunnel(c configure, key ocdcType, args []interface{}) (interface{}, error) {
	i := c.getInterface(args[0].(string))

	switch key {
	case ifSubTunnelAddressType:
		i.getSubiface(args[1].(int)).setAddressType(args[2].(string))
	case ifSubTunnelEncapsMethod:
		i.getSubiface(args[1].(int)).setEncapsMethod(args[2].(string))
	case ifSubTunnelHopLimit:
		i.getSubiface(args[1].(int)).setHopLimit(args[2].(int))
	case ifSubTunnelLocalAddress:
		i.getSubiface(args[1].(int)).setLocalAddress(args[2].(net.IP))
	case ifSubTunnelRemoteAddress:
		i.getSubiface(args[1].(int)).setRemoteAddress(args[2].(net.IP))
	case ifSubTunnelSecurity:
		i.getSubiface(args[1].(int)).setSecurity(args[2].(string))
	case ifSubTunnelTOS:
		i.getSubiface(args[1].(int)).setTOS(args[2].(int))
	default:
		return nil, ocdcTypeUnexpectedError(key)
	}

	return i, nil
}
