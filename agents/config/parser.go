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
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/lagopus/vsw/vswitch"
)

const (
	TOKEN_STRING          = "STRING"
	TOKEN_BOOL            = "BOOL"
	TOKEN_INTEGER         = "INTEGER"
	TOKEN_IPV4ADDR        = "A.B.C.D"
	TOKEN_MACADDR         = "MACADDR"
	TOKEN_RANGE           = "MIN..MAX"
	TOKEN_IPV4ADDR_PREFIX = "A.B.C.D/E"
	TOKEN_PORTRANGE       = "PORTRANGE"
	TOKEN_PROTOCOL        = "PROTOCOL"
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

type rangeValue struct {
	min int
	max int
}

func parseRange(s string) (*rangeValue, error) {
	tokens := strings.Split(s, "..")

	if len(tokens) != 2 {
		return nil, errors.New("Bad format")
	}

	min, err := strconv.Atoi(tokens[0])
	if err != nil {
		return nil, errors.New("Bad min value")
	}

	max, err := strconv.Atoi(tokens[1])
	if err != nil {
		return nil, errors.New("Bad max value")
	}

	if min > max {
		return nil, errors.New("Min value greater than max")
	}

	return &rangeValue{min, max}, nil
}

func parsePortRange(ports string) (*vswitch.PortRange, error) {
	p := &vswitch.PortRange{}
	if ports == "ANY" {
		return p, nil
	}

	tmp := strings.Split(ports, "..")
	len := len(tmp)
	if len > 2 {
		return p, errors.New("Invalid port range.")
	}

	start, _ := strconv.Atoi(tmp[0])
	p.Start = uint16(start)
	if len == 2 {
		end, _ := strconv.Atoi(tmp[1])
		p.End = uint16(end)
	}

	return p, nil
}

func parseProtocol(proto string) (vswitch.IPProto, error) {
	switch proto {
	case "TCP":
		return vswitch.IPP_TCP, nil
	case "UDP":
		return vswitch.IPP_UDP, nil
	case "ICMP":
		return vswitch.IPP_ICMP, nil
	case "IGMP":
		return vswitch.IPP_IGMP, nil
	case "PIM":
		return vswitch.IPP_PIM, nil
	case "RSVP":
		return vswitch.IPP_RSVP, nil
	case "GRE":
		return vswitch.IPP_GRE, nil
	case "AUTH":
		return vswitch.IPP_AH, nil
	case "L2TP":
		return vswitch.IPP_L2TP, nil
	default:
		if v, err := strconv.Atoi(proto); err != nil {
			return 0, err
		} else {
			return vswitch.IPProto(v), nil
		}
	}

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
		case TOKEN_IPV4ADDR_PREFIX:
			if addr, mask, err := net.ParseCIDR(input[n]); err == nil {
				addr := vswitch.IPAddr{
					IP:   addr,
					Mask: mask.Mask,
				}
				args = append(args, addr)
			} else {
				return count, false, nil
			}
		case TOKEN_PORTRANGE:
			if port, err := parsePortRange(input[n]); err == nil {
				args = append(args, port)
			} else {
				return count, false, nil
			}
		case TOKEN_MACADDR:
			if mac, err := net.ParseMAC(input[n]); err == nil {
				args = append(args, mac)
			} else {
				return count, false, nil
			}
		case TOKEN_RANGE:
			if rv, err := parseRange(input[n]); err == nil {
				args = append(args, rv)
			} else {
				return count, false, nil
			}
		case TOKEN_PROTOCOL:
			if proto, err := parseProtocol(input[n]); err == nil {
				args = append(args, proto)
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

type parser struct {
	rt *radixTree
	c  interface{}
}

type parserCallbackFunc func(interface{}, ocdcType, []interface{}) (interface{}, error)

type parserSyntaxEntry struct {
	pattern  string
	callback parserCallbackFunc
	ocdcType ocdcType
}

type parserSyntax struct {
	prefix string
	syntax []*parserSyntaxEntry
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

func newParser(c interface{}) *parser {
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
