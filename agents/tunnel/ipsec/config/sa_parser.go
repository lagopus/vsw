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
	"strconv"

	"github.com/lagopus/vsw/agents/tunnel/ipsec/sad"
	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/vswitch"
)

const (
	// SAFlagUnspec Unspec
	SAFlagUnspec = 0
)

// SAParser Parser.
type SAParser struct {
	parserFuncs map[string]func(args *parseSAArgs,
		tokens []string, pos int) (int, error)
}

var saParser = newSAParser()
var cipherAlgos = map[string]ipsec.CipherAlgoType{}
var authAlgos = map[string]ipsec.AuthAlgoType{}
var aeadAlgos = map[string]ipsec.AeadAlgoType{}

func newSAParser() *SAParser {
	p := &SAParser{
		parserFuncs: map[string]func(args *parseSAArgs,
			tokens []string, pos int) (int, error){},
	}

	p.parserFuncs["mode"] = p.parseMode
	p.parserFuncs["cipher_algo"] = p.parseCipherAlgo
	p.parserFuncs["auth_algo"] = p.parseAuthAlgo
	p.parserFuncs["aead_algo"] = p.parseAeadAlgo
	p.parserFuncs["src"] = p.parseSrcIP
	p.parserFuncs["dst"] = p.parseDstIP
	p.parserFuncs["vrf"] = p.parseVRF
	p.parserFuncs["udp"] = p.parseUDP

	return p
}

type parseSAArgs struct {
	rp       *RootParser
	selector *sad.SASelector
	value    *sad.SAValue
}

func init() {
	rp := GetRootParser()
	if err := rp.RegisterParser("sa", saParser); err != nil {
		panic(err)
	}

	for algo, value := range ipsec.SupportedCipherAlgoByType {
		cipherAlgos[value.Keyword] = algo
	}

	for algo, value := range ipsec.SupportedAuthAlgoByType {
		authAlgos[value.Keyword] = algo
	}

	for algo, value := range ipsec.SupportedAeadAlgoByType {
		aeadAlgos[value.Keyword] = algo
	}
}

func (p *SAParser) parseMode(args *parseSAArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	switch tokens[pos] {
	case "ipv4-tunnel":
		args.value.Flags = ipsec.IP4Tunnel
	case "ipv6-tunnel":
		args.value.Flags = ipsec.IP6Tunnel
	case "transport":
		args.value.Flags = ipsec.Transport
	default:
		return 0, fmt.Errorf("unrecognizable input: %v", tokens[pos])
	}

	return pos, nil
}

func (p *SAParser) parseCipherAlgo(args *parseSAArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	var algoValue *ipsec.CipherAlgoValues
	if algo, ok := cipherAlgos[tokens[pos]]; ok {
		args.value.CipherAlgoType = algo
		if value, ok := ipsec.SupportedCipherAlgoByType[algo]; ok {
			algoValue = value
		} else {
			return 0, fmt.Errorf("unrecognizable input: %v", tokens[pos])
		}
	} else {
		return 0, fmt.Errorf("unrecognizable input: %v", tokens[pos])
	}

	// Null Algo doesn't have AlgoKey.
	if args.value.CipherAlgoType == ipsec.CipherAlgoTypeNull {
		return pos, nil
	}

	// Key.
	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	var err error
	switch tokens[pos] {
	case "cipher_key":
		if pos, err = p.parseCipherKey(args, algoValue, tokens, pos); err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("unrecognizable input: %v", tokens[pos])
	}

	return pos, nil
}

func (p *SAParser) parseCipherKey(args *parseSAArgs,
	algoValue *ipsec.CipherAlgoValues,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	if key, err := ParseHexKey(tokens[pos], ":"); err == nil {
		args.value.CipherKey = key
	} else {
		return 0, err
	}

	if uint16(len(args.value.CipherKey)) != algoValue.KeyLen {
		return 0, fmt.Errorf("unrecognizable input: %v", tokens[pos])
	}

	return pos, nil
}

func (p *SAParser) parseAuthAlgo(args *parseSAArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	var algoValue *ipsec.AuthAlgoValues
	if algo, ok := authAlgos[tokens[pos]]; ok {
		args.value.AuthAlgoType = algo
		if value, ok := ipsec.SupportedAuthAlgoByType[algo]; ok {
			algoValue = value
		} else {
			return 0, fmt.Errorf("unrecognizable input: %v", tokens[pos])
		}
	} else {
		return 0, fmt.Errorf("unrecognizable input: %v", tokens[pos])
	}

	// Null and combined Algos doesn't have AlgoKey.
	if algoValue.KeyNotReq {
		return pos, nil
	}

	// Key.
	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	var err error
	switch tokens[pos] {
	case "auth_key":
		if pos, err = p.parseAuthKey(args, algoValue, tokens, pos); err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("unrecognizable input: %v", tokens[pos])
	}

	return pos, nil
}

func (p *SAParser) parseAuthKey(args *parseSAArgs,
	algoValue *ipsec.AuthAlgoValues,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	if key, err := ParseHexKey(tokens[pos], ":"); err == nil {
		args.value.AuthKey = key
	} else {
		return 0, err
	}

	if uint16(len(args.value.AuthKey)) != algoValue.KeyLen {
		return 0, fmt.Errorf("unrecognizable input: %v", tokens[pos])
	}

	return pos, nil
}

func (p *SAParser) parseAeadAlgo(args *parseSAArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	var algoValue *ipsec.AeadAlgoValues
	if algo, ok := aeadAlgos[tokens[pos]]; ok {
		args.value.AeadAlgoType = algo
		if value, ok := ipsec.SupportedAeadAlgoByType[algo]; ok {
			algoValue = value
		} else {
			return 0, fmt.Errorf("unrecognizable input: %v", tokens[pos])
		}
	} else {
		return 0, fmt.Errorf("unrecognizable input: %v", tokens[pos])
	}

	// Key.
	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	var err error
	switch tokens[pos] {
	case "aead_key":
		if pos, err = p.parseAeadKey(args, algoValue, tokens, pos); err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("unrecognizable input: %v", tokens[pos])
	}

	return pos, nil
}

func (p *SAParser) parseAeadKey(args *parseSAArgs,
	algoValue *ipsec.AeadAlgoValues,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	if key, err := ParseHexKey(tokens[pos], ":"); err == nil {
		args.value.AeadKey = key
	} else {
		return 0, err
	}

	if uint16(len(args.value.AeadKey)) != algoValue.KeyLen {
		return 0, fmt.Errorf("unrecognizable input: %v", tokens[pos])
	}

	return pos, nil
}

func (p *SAParser) parseSrcIP(args *parseSAArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	var isIPv4 bool
	switch args.value.Flags {
	case ipsec.IP4Tunnel:
		isIPv4 = true
	case ipsec.IP6Tunnel:
		isIPv4 = false
	default:
		return 0, fmt.Errorf("unrecognizable input: %v", tokens[pos])
	}

	if ip, err := args.rp.ParseIP(tokens[pos], isIPv4); err == nil {
		args.value.LocalEPIP = ip
	} else {
		return 0, err
	}

	return pos, nil
}

func (p *SAParser) parseDstIP(args *parseSAArgs,
	tokens []string,
	pos int) (int, error) {

	pos++
	if pos >= len(tokens) {
		return 0, fmt.Errorf("Bad format")
	}

	var isIPv4 bool
	switch args.value.Flags {
	case ipsec.IP4Tunnel:
		isIPv4 = true
	case ipsec.IP6Tunnel:
		isIPv4 = false
	default:
		return 0, fmt.Errorf("unrecognizable input: %v", tokens[pos])
	}

	if ip, err := args.rp.ParseIP(tokens[pos], isIPv4); err == nil {
		args.value.RemoteEPIP = ip
	} else {
		return 0, err
	}

	return pos, nil
}

func (p *SAParser) parseVRF(args *parseSAArgs,
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

func (p *SAParser) parseUDP(args *parseSAArgs,
	tokens []string,
	pos int) (int, error) {
	var ports [2]uint16 // 0: src port, 1: dst port

	for i := 0; i < 2; i++ {
		pos++
		if pos >= len(tokens) {
			return 0, fmt.Errorf("Bad format")
		}

		if port, err := strconv.ParseUint(tokens[pos], 10, 16); err == nil {
			ports[i] = uint16(port)
		} else {
			return 0, err
		}
	}
	args.value.EncapSrcPort = ports[0]
	args.value.EncapDstPort = ports[1]
	args.value.EncapProtocol = ipsec.EncapProtoUDP
	args.value.EncapType = ipsec.UDPEncapESPinUDP

	return pos, nil
}

// Public.

// Parse Parse SA.
func (p *SAParser) Parse(tokens []string) error {
	if len(tokens) < 3 {
		return fmt.Errorf("Bad format")
	}

	args := &parseSAArgs{
		rp:       GetRootParser(),
		selector: &sad.SASelector{},
		value:    &sad.SAValue{},
	}

	var mgr *sad.Mgr
	switch tokens[0] {
	case "in":
		mgr = sad.GetMgr(ipsec.DirectionTypeIn)
	case "out":
		mgr = sad.GetMgr(ipsec.DirectionTypeOut)
	default:
		return fmt.Errorf("unrecognizable input: %v", tokens[0])
	}

	// SPI.
	var spi uint64
	var err error
	if spi, err = strconv.ParseUint(tokens[1], 10, 32); err == nil {
		args.selector.SPI = sad.SPI(spi)
	} else {
		return err
	}

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

	if args.value.CipherAlgoType != ipsec.CipherAlgoTypeUnknown ||
		args.value.AuthAlgoType != ipsec.AuthAlgoTypeUnknown {
		// check set cipherAlgo.
		if args.value.CipherAlgoType == ipsec.CipherAlgoTypeUnknown {
			return fmt.Errorf("missing cipher options")
		}

		// check set authAlgo.
		if args.value.AuthAlgoType == ipsec.AuthAlgoTypeUnknown {
			return fmt.Errorf("missing auth options")
		}

		// check set aeadAlgo.
		if args.value.AeadAlgoType != ipsec.AeadAlgoTypeUnknown {
			return fmt.Errorf("missing aead options")
		}
	} else {
		// check set aeadAlgo.
		if args.value.AeadAlgoType == ipsec.AeadAlgoTypeUnknown {
			return fmt.Errorf("missing aead options")
		}
	}

	// check set mode.
	if args.value.Flags == SAFlagUnspec {
		return fmt.Errorf("missing mode option")
	}

	if err = mgr.AddSA(args.selector, args.value); err != nil {
		return err
	}
	err = mgr.EnableSA(args.selector)

	return err
}

// CipherAlgos Get supported cipher algos.
func CipherAlgos() map[string]ipsec.CipherAlgoType {
	return cipherAlgos
}

// AuthAlgos Get supported auth algos.
func AuthAlgos() map[string]ipsec.AuthAlgoType {
	return authAlgos
}

// AeadAlgos Get supported AEAD algos.
func AeadAlgos() map[string]ipsec.AeadAlgoType {
	return aeadAlgos
}
