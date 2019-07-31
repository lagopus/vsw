//
// Copyright 2018-2019 Nippon Telegraph and Telephone Corporation.
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

package vswitch

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

// SAObserver needs to be implemented to observe changes in the SAD/SPD.
type SAObserver interface {
	SADEntryAdded(*VRF, SA)
	SADEntryUpdated(*VRF, SA)
	SADEntryDeleted(*VRF, SA)
	SPDEntryAdded(*VRF, SP)
	SPDEntryUpdated(*VRF, SP)
	SPDEntryDeleted(*VRF, SP)
}

// Security Assocication Entry
type SA struct {
	SPI               uint32     // Security Parameters Index (SPI)
	Mode              SAMode     // sa-mode
	LifeTimeInSeconds uint32     // life-time-in-seconds
	LifeTimeInByte    uint32     // life-time-in-byte
	LocalPeer         net.IP     // local-peer
	RemotePeer        net.IP     // remote-peer
	Auth              ESPAuth    // authentication
	AuthKey           string     // authentication key-str
	Encrypt           ESPEncrypt // encryption
	EncKey            string     // encryption key-str
	EncapProtocol     IPProto    // encap-protocol
	EncapSrcPort      uint16     // encap-src-port
	EncapDstPort      uint16     // encap-dst-port
}

// Security Policy Entry
type SP struct {
	Name             string    // SP name
	SPI              uint32    // Security Parameters Index (SPI)
	DstAddress       IPAddr    // destination-address ipv4-address
	SrcAddress       IPAddr    // source-address ipv4-address
	DstPort          uint16    // destination-address port-number
	SrcPort          uint16    // source-address port-number
	UpperProtocol    IPProto   // upper-protocol
	Direction        Direction // direction
	SecurityProtocol IPProto   // security-protocol
	Priority         int32     // priority
	Policy           Policy    // policy
}

func (sa SA) String() string {
	return fmt.Sprintf("SPI=%d Mode=%v LifeTimeInSeconds=%d LifeTimeInByte=%d "+
		"LocalPeer=%v RemotePeer=%v Auth=%v(%s) Encrypt=%v(%s) Encap=%v(src: %d, dst: %d)",
		sa.SPI, sa.Mode, sa.LifeTimeInSeconds, sa.LifeTimeInByte,
		sa.LocalPeer, sa.RemotePeer, sa.Auth, sa.AuthKey, sa.Encrypt, sa.EncKey,
		sa.EncapProtocol, sa.EncapSrcPort, sa.EncapDstPort)

}

func (sa SA) Equal(t SA) bool {
	return sa.SPI == t.SPI && sa.Mode == t.Mode &&
		sa.LifeTimeInSeconds == t.LifeTimeInSeconds &&
		sa.LifeTimeInByte == t.LifeTimeInByte &&
		sa.Auth == t.Auth && sa.Encrypt == t.Encrypt &&
		sa.AuthKey == t.AuthKey && sa.EncKey == t.EncKey &&
		sa.LocalPeer.Equal(t.LocalPeer) && sa.RemotePeer.Equal(t.RemotePeer)
}

func (sp SP) String() string {
	return fmt.Sprintf("%v: SPI=%d Dst=%v(%d) Src=%v(%d) UpperProtocol=%v Diretion=%v SecurityProtocol=%v Priority=%d Policy=%v",
		sp.Name, sp.SPI, sp.DstAddress, sp.DstPort, sp.SrcAddress, sp.SrcPort,
		sp.UpperProtocol, sp.Direction, sp.SecurityProtocol, sp.Priority, sp.Policy)
}

func (sp SP) Equal(t SP) bool {
	return sp.SPI == t.SPI &&
		sp.DstPort == t.DstPort && sp.SrcPort == t.SrcPort &&
		sp.UpperProtocol == t.UpperProtocol &&
		sp.Direction == t.Direction &&
		sp.SecurityProtocol == t.SecurityProtocol &&
		sp.Priority == t.Priority && sp.Policy == t.Policy &&
		sp.DstAddress.Equal(t.DstAddress) && sp.SrcAddress.Equal(t.SrcAddress)
}

// SA mode
type SAMode int

const (
	ModeUndefined SAMode = iota
	ModeTunnel
)

func (e SAMode) String() string {
	s := map[SAMode]string{
		ModeUndefined: "undefined",
		ModeTunnel:    "tunnel",
	}
	return s[e]
}

func (e SAMode) MarshalJSON() ([]byte, error) {
	return []byte(`"` + e.String() + `"`), nil
}

// IPsec Authentication Algorithm
type ESPAuth int

const (
	AuthUndefined ESPAuth = iota
	AuthNULL
	AuthSHA1
)

func (e ESPAuth) String() string {
	s := map[ESPAuth]string{
		AuthUndefined: "undefiend",
		AuthNULL:      "null",
		AuthSHA1:      "hmac-sha1-96",
	}
	return s[e]
}

func (e ESPAuth) MarshalJSON() ([]byte, error) {
	return []byte(`"` + e.String() + `"`), nil
}

// IPsec Encryption Algorithm
type ESPEncrypt int

const (
	EncryptUndefined ESPEncrypt = iota
	EncryptNULL
	EncryptAES
	EncryptGCM
)

func (e ESPEncrypt) String() string {
	s := map[ESPEncrypt]string{
		EncryptUndefined: "undefiend",
		EncryptNULL:      "null",
		EncryptAES:       "aes-128-cbc",
		EncryptGCM:       "aes-128-gcm",
	}
	return s[e]
}

func (e ESPEncrypt) MarshalJSON() ([]byte, error) {
	return []byte(`"` + e.String() + `"`), nil
}

type Direction int

const (
	Inbound Direction = iota
	Outbound
)

func (d Direction) String() string {
	s := map[Direction]string{
		Inbound:  "inbound",
		Outbound: "outbound",
	}
	return s[d]
}

func (d Direction) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.String() + `"`), nil
}

type Policy int

const (
	Discard Policy = iota
	Bypass
	Protect
)

func (p Policy) String() string {
	s := map[Policy]string{
		Discard: "DISCARD",
		Bypass:  "BYPASS",
		Protect: "PROTECT",
	}
	return s[p]
}

func (p Policy) MarshalJSON() ([]byte, error) {
	return []byte(`"` + p.String() + `"`), nil
}

// NewSA creates new SA entry for the given SPI.
func NewSA(spi uint32) SA {
	return SA{
		SPI:           spi,
		Mode:          ModeUndefined,
		Auth:          AuthUndefined,
		Encrypt:       EncryptUndefined,
		EncapProtocol: IPP_NONE,
	}
}

// NewSP creates new SP entry for the given name.
func NewSP(name string) SP {
	defaultMask := net.CIDRMask(32, 32)
	return SP{
		Name:          name,
		DstAddress:    IPAddr{Mask: defaultMask},
		SrcAddress:    IPAddr{Mask: defaultMask},
		UpperProtocol: IPP_ANY,
	}
}

// Security Assocication Databases
type SADatabases struct {
	sad      map[uint32]SA
	spd      map[string]SP
	lock     sync.Mutex
	observer SAObserver
	vrf      *VRF
}

// newSADatabases creates new Security Association Databases.
func newSADatabases(vrf *VRF) *SADatabases {
	return &SADatabases{
		sad: make(map[uint32]SA),
		spd: make(map[string]SP),
		vrf: vrf,
	}
}

// RegisterObserver registeres an observer of SAD/SPD
func (s *SADatabases) RegisterObserver(observer SAObserver) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.observer != nil {
		return errors.New("Observer already registered.")
	}

	if observer == nil {
		return errors.New("Observer can't be nil.")
	}

	s.observer = observer

	for _, entry := range s.sad {
		observer.SADEntryAdded(s.vrf, entry)
	}

	for _, entry := range s.spd {
		observer.SPDEntryAdded(s.vrf, entry)
	}

	return nil
}

// AddSADEntry adds an SA to the SAD.
func (s *SADatabases) AddSADEntry(entry SA) {
	s.lock.Lock()
	defer s.lock.Unlock()

	old, found := s.sad[entry.SPI]

	if found && old.Equal(entry) {
		return
	}

	s.sad[entry.SPI] = entry

	if s.observer != nil {
		if found {
			s.observer.SADEntryUpdated(s.vrf, entry)
		} else {
			s.observer.SADEntryAdded(s.vrf, entry)
		}
	}
}

// DeleteSADEntry deletes SA identified by the SPI.
func (s *SADatabases) DeleteSADEntry(spi uint32) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if entry, found := s.sad[spi]; found {
		delete(s.sad, spi)
		if s.observer != nil {
			s.observer.SADEntryDeleted(s.vrf, entry)
		}
	}
}

// SAD returns all SA entries in the SAD
func (s *SADatabases) SAD() []SA {
	s.lock.Lock()
	defer s.lock.Unlock()

	sad := make([]SA, len(s.sad))
	n := 0
	for _, entry := range s.sad {
		sad[n] = entry
		n++
	}
	return sad
}

// AddSPDEntry adds an SP entry to the SPD.
func (s *SADatabases) AddSPDEntry(entry SP) {
	s.lock.Lock()
	defer s.lock.Unlock()

	old, found := s.spd[entry.Name]

	if found && old.Equal(entry) {
		return
	}

	s.spd[entry.Name] = entry

	if s.observer != nil {
		if found {
			s.observer.SPDEntryUpdated(s.vrf, entry)
		} else {
			s.observer.SPDEntryAdded(s.vrf, entry)
		}
	}
}

// DeleteSPDEntry deletes SP entry identified by the name.
func (s *SADatabases) DeleteSPDEntry(name string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if entry, found := s.spd[name]; found {
		delete(s.spd, name)
		if s.observer != nil {
			s.observer.SPDEntryDeleted(s.vrf, entry)
		}
	}
}

// SPD returns all SP entries in the SPD
func (s *SADatabases) SPD() []SP {
	s.lock.Lock()
	defer s.lock.Unlock()

	spd := make([]SP, len(s.spd))
	n := 0
	for _, entry := range s.spd {
		spd[n] = entry
		n++
	}
	return spd
}
