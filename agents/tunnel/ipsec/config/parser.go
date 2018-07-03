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
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

// Parser Parser.
type Parser interface {
	Parse(tokens []string) error
}

// RootParser Root parser.
type RootParser struct {
	parsers map[string]*Parser
	lock    sync.Mutex
}

var rootParser = newRootParser()

func newRootParser() *RootParser {
	p := &RootParser{
		parsers: map[string]*Parser{},
	}
	return p
}

func (p *RootParser) scanFile(file *os.File) error {
	scanner := bufio.NewScanner(file)
	var err error
	var tokens string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		length := len(line)
		if length > 0 {
			// commnet.
			if line[0:1] == "#" {
				if len(tokens) != 0 {
					return fmt.Errorf("Can't parse continuation line")
				}
				continue
			}

			// Continuation line.
			if line[length-1:length] == "\\" {
				tokens += line[:length-1]
				continue
			}
			tokens += line
		} else {
			// Blank line.
			if len(tokens) != 0 {
				return fmt.Errorf("Can't parse continuation line")
			}
			continue
		}

		if ts := strings.Fields(tokens); len(tokens) != 0 {
			rootToken := ts[0]
			if p, ok := p.parsers[rootToken]; ok {
				// Call Parse func.
				if err = (*p).Parse(ts[1:]); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("Not found %v", rootToken)
			}
		}
		tokens = ""
	}
	err = scanner.Err()

	return err
}

// Public.

// ParseIP Parse IP addr.
func (p *RootParser) ParseIP(str string, isIPv4 bool) (net.IP, error) {
	var ip net.IP
	if ip = net.ParseIP(str); ip == nil {
		return nil, fmt.Errorf("Invalid IP address: %v", str)
	}

	// is IPv4
	ipv4 := ip.To4()
	if ipv4 != nil { // IPv4 addr.
		if !isIPv4 {
			return nil, fmt.Errorf("Invalid IP address: %v", str)
		}

		ip = ipv4
	} else if isIPv4 { // IPv6 addr.
		return nil, fmt.Errorf("Invalid IP address: %v", str)
	}

	return ip, nil
}

// ParseIPNet Parse IP addr & mask.
func (p *RootParser) ParseIPNet(str string, isIPv4 bool) (*net.IPNet, error) {
	var ipNet *net.IPNet
	var err error

	if _, ipNet, err = net.ParseCIDR(str); err != nil {
		return nil, err
	}

	// is IPv4
	ipv4 := ipNet.IP.To4()
	if ipv4 != nil { // IPv4 addr.
		if !isIPv4 {
			return nil, fmt.Errorf("Invalid IP address: %v", str)
		}

		ipNet.IP = ipv4
	} else if isIPv4 { // IPv6 addr.
		return nil, fmt.Errorf("Invalid IP address: %v", str)
	}

	return ipNet, nil
}

// ParseRange Parse range format.
func (p *RootParser) ParseRange(str string) (uint16, uint16, error) {
	ts := strings.Split(str, ":")
	if len(ts) != 2 {
		return 0, 0, fmt.Errorf("Invalid range: %v", str)
	}

	var low uint64
	var high uint64
	var err error
	if low, err = strconv.ParseUint(ts[0], 10, 16); err != nil {
		return 0, 0, err
	}
	if high, err = strconv.ParseUint(ts[1], 10, 16); err != nil {
		return 0, 0, err
	}
	if low > high {
		return 0, 0, fmt.Errorf("bad low(%v) > high(%v)", low, high)
	}
	return uint16(low), uint16(high), nil
}

// ParseConfigFile Parse config file.
func (p *RootParser) ParseConfigFile(fileName string) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	var file *os.File
	var err error
	if file, err = os.Open(fileName); err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	return p.scanFile(file)
}

// RegisterParser  Register parser.
func (p *RootParser) RegisterParser(rootToken string, parser Parser) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	if _, ok := p.parsers[rootToken]; !ok {
		p.parsers[rootToken] = &parser
		return nil
	}
	return fmt.Errorf("Already exists : %v", rootToken)
}

// GetRootParser  Get RootParser instance.
func GetRootParser() *RootParser {
	return rootParser
}
