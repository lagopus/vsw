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
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/lagopus/vsw/modules/tunnel/ipsec"
)

// MacAddr64Len length of mac addr.
const MacAddr64Len = 8

// NexthopParser Parser.
type NexthopParser struct {
	parserFuncs map[string]func(args *parseNexthopArgs,
		tokens []string, pos int) (int, error)
}

var nexthopParser = newNexthopParser()

func newNexthopParser() *NexthopParser {
	p := &NexthopParser{
		parserFuncs: map[string]func(args *parseNexthopArgs,
			tokens []string, pos int) (int, error){},
	}

	p.parserFuncs["port"] = p.parsePort
	p.parserFuncs["src-mac"] = p.parseSrcMac
	p.parserFuncs["dst-mac"] = p.parseDstMac

	return p
}

func init() {
	rp := GetRootParser()
	if err := rp.RegisterParser("nexthop", nexthopParser); err != nil {
		panic(err)
	}
}

type parseNexthopArgs struct {
	rp     *RootParser
	port   ipsec.CPORT
	srcMAC ipsec.CMAC
	dstMAC ipsec.CMAC
}

func (p *NexthopParser) parsePort(args *parseNexthopArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	if port, err := strconv.ParseUint(tokens[pos], 10, 8); err == nil {
		args.port = ipsec.CPORT(port)
	} else {
		return 0, err
	}

	return pos, nil
}

func (p *NexthopParser) parseSrcMac(args *parseNexthopArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	if mac, err := net.ParseMAC(tokens[pos]); err == nil {
		m := make([]byte, MacAddr64Len)
		copy(m, mac)
		args.srcMAC = ipsec.CMAC(binary.LittleEndian.Uint64(m))
	} else {
		return 0, err
	}

	return pos, nil
}

func (p *NexthopParser) parseDstMac(args *parseNexthopArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	if mac, err := net.ParseMAC(tokens[pos]); err == nil {
		m := make([]byte, MacAddr64Len)
		copy(m, mac)
		args.dstMAC = ipsec.CMAC(binary.LittleEndian.Uint64(m))
	} else {
		return 0, err
	}

	return pos, nil
}

// Public.

// Parse Parse Nexthop
func (p *NexthopParser) Parse(tokens []string) error {
	if len(tokens) < 1 {
		return fmt.Errorf("Bad format")
	}
	args := &parseNexthopArgs{
		rp: GetRootParser(),
	}

	var err error
	pos := 0
	for pos < len(tokens) {
		if f, ok := p.parserFuncs[tokens[pos]]; ok {
			// call parse func.
			if pos, err = f(args, tokens, pos); err != nil {
				return err
			}
			pos++
		} else {
			return fmt.Errorf("unrecognizable input: %v", tokens[pos])
		}
	}

	return ipsec.AddIPsecAddEthaddr(args.port, args.srcMAC, args.dstMAC)
}
