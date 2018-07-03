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
	"strconv"

	"github.com/lagopus/vsw/agents/tunnel/ipsec/spd"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/vswitch"
)

// SPParser Parser.
type SPParser struct {
	parserFuncs map[string]func(args *parseSPArgs,
		tokens []string, pos int) (int, error)
}

var spParser = newSPParser()

func newSPParser() *SPParser {
	p := &SPParser{
		parserFuncs: map[string]func(args *parseSPArgs,
			tokens []string, pos int) (int, error){},
	}

	p.parserFuncs["esp"] = p.parseESP
	p.parserFuncs["protect"] = p.parseProtect
	p.parserFuncs["bypass"] = p.parseBypass
	p.parserFuncs["discard"] = p.parseDiscard
	p.parserFuncs["pri"] = p.parsePriority
	p.parserFuncs["src"] = p.parseSrcIP
	p.parserFuncs["dst"] = p.parseDstIP
	p.parserFuncs["proto"] = p.parseUpperProtocol
	p.parserFuncs["sport"] = p.parseSrcPort
	p.parserFuncs["dport"] = p.parseDstPort
	p.parserFuncs["vrf"] = p.parseVRF

	return p
}

func init() {
	rp := GetRootParser()
	if err := rp.RegisterParser("sp", spParser); err != nil {
		panic(err)
	}
}

type parseSPArgs struct {
	rp       *RootParser
	selector *spd.SPSelector
	value    *spd.SPValue
	isIPv4   bool
}

func (p *SPParser) parseESP(args *parseSPArgs,
	tokens []string,
	pos int) (int, error) {

	args.value.Protocol = ipsec.SecurityProtocolTypeESP
	return pos, nil
}

func (p *SPParser) parseProtect(args *parseSPArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	if spi, err := strconv.ParseUint(tokens[pos], 10, 32); err == nil {
		args.value.Policy = ipsec.PolicyTypeProtect
		args.value.SPI = uint32(spi)
	} else {
		return 0, err
	}

	return pos, nil
}

func (p *SPParser) parseBypass(args *parseSPArgs,
	tokens []string,
	pos int) (int, error) {

	args.value.Policy = ipsec.PolicyTypeBypass
	return pos, nil
}

func (p *SPParser) parseDiscard(args *parseSPArgs,
	tokens []string,
	pos int) (int, error) {

	args.value.Policy = ipsec.PolicyTypeDiscard
	return pos, nil
}

func (p *SPParser) parsePriority(args *parseSPArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	if pri, err := strconv.ParseInt(tokens[pos], 10, 32); err == nil {
		args.value.Priority = int32(pri)
	} else {
		return 0, err
	}

	return pos, nil
}

func (p *SPParser) parseSrcIP(args *parseSPArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	if ip, err := args.rp.ParseIPNet(tokens[pos],
		args.isIPv4); err == nil {
		args.selector.LocalIP = *ip
	} else {
		return 0, err
	}

	return pos, nil
}

func (p *SPParser) parseDstIP(args *parseSPArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	if ip, err := args.rp.ParseIPNet(tokens[pos],
		args.isIPv4); err == nil {
		args.selector.RemoteIP = *ip
	} else {
		return 0, err
	}

	return pos, nil
}

func (p *SPParser) parseUpperProtocol(args *parseSPArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	if pro, err := strconv.ParseUint(tokens[pos], 10, 16); err == nil {
		args.selector.UpperProtocol = ipsec.UpperProtocolType(pro)
	} else {
		return 0, err
	}

	return pos, nil
}

func (p *SPParser) parseSrcPort(args *parseSPArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	if low, high, err := args.rp.ParseRange(tokens[pos]); err == nil {
		args.selector.LocalPortRangeStart = low
		args.selector.LocalPortRangeEnd = high
	} else {
		return 0, err
	}

	return pos, nil
}

func (p *SPParser) parseDstPort(args *parseSPArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	if low, high, err := args.rp.ParseRange(tokens[pos]); err == nil {
		args.selector.RemotePortRangeStart = low
		args.selector.RemotePortRangeEnd = high
	} else {
		return 0, err
	}

	return pos, nil
}

func (p *SPParser) parseVRF(args *parseSPArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	if pri, err := strconv.ParseUint(tokens[pos], 10, 8); err == nil {
		args.selector.VRFIndex = vswitch.VRFIndex(pri)
	} else {
		return 0, err
	}

	return pos, nil
}

// Public.

// Parse SP.
func (p *SPParser) Parse(tokens []string) error {
	if len(tokens) < 3 {
		return fmt.Errorf("Bad format")
	}

	args := &parseSPArgs{
		rp:       GetRootParser(),
		selector: &spd.SPSelector{},
		value:    &spd.SPValue{},
	}

	switch tokens[0] {
	case "ipv4":
		args.isIPv4 = true
	case "ipv6":
		args.isIPv4 = false
	default:
		return fmt.Errorf("unrecognizable input: %v", tokens[0])
	}

	switch tokens[1] {
	case "in":
		args.selector.Direction = ipsec.DirectionTypeIn
	case "out":
		args.selector.Direction = ipsec.DirectionTypeOut
	default:
		return fmt.Errorf("unrecognizable input: %v", tokens[1])
	}

	var err error
	pos := 2
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
	// only support tunnel.
	args.value.Mode = ipsec.ModeTypeTunnel
	args.value.Level = ipsec.LevelTypeRequire
	args.value.State = spd.Completed
	if args.selector.UpperProtocol == 0 {
		// any
		args.selector.UpperProtocol = ipsec.UpperProtocolTypeAny
	}

	// check set esp.
	if args.value.Protocol == ipsec.SecurityProtocolTypeUnspec {
		return fmt.Errorf("missing argument ESP")
	}

	// check set protect/bypass/discard.
	switch args.value.Policy {
	case ipsec.PolicyTypeDiscard:
	case ipsec.PolicyTypeProtect:
	case ipsec.PolicyTypeBypass:
		return fmt.Errorf("missing argument protect or bypass or discard")
	}

	mgr := spd.GetMgr()
	if _, err = mgr.AddSP(args.selector.Direction,
		args.selector,
		args.value); err != nil {
		return err
	}

	return nil
}
