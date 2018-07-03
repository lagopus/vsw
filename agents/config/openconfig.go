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
	err     error
}

// subiface represents a subinterface
type subiface struct {
	name    string
	enabled bool
	id      uint32
	iface   *iface
	ni      map[string]*ni
	vid     vswitch.VID
	ipaddr  map[string]vswitch.IPAddr
	tunnel  *vswitch.Tunnel
}

type vlan struct {
	vid    int
	active bool
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
			ipaddr: make(map[string]vswitch.IPAddr),
		}
		i.subs[id] = s
	}

	return s
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
	ipaddr := createIPAddr(ip, mask)
	s.ipaddr[ipaddr.String()] = ipaddr
}

func (s *subiface) deleteAddress(ip net.IP, mask int) {
	delete(s.ipaddr, createIPAddr(ip, mask).String())
}

func (s *subiface) setVID(v int) {
	s.vid = vswitch.VID(v)
	if _, ok := s.iface.vids[s.vid]; !ok {
		s.iface.addVID(v)
	}
}

func (s *subiface) getTunnel() *vswitch.Tunnel {
	if s.tunnel == nil {
		s.tunnel = vswitch.NewTunnel()
	}
	return s.tunnel
}

func (s *subiface) setAddressType(a string) {
	t := s.getTunnel()
	switch a {
	case "IPV4":
		t.SetAddressType(vswitch.AF_IPv4)
	}
}

func (s *subiface) setEncapsMethod(m string) {
	t := s.getTunnel()
	switch m {
	case "direct":
		t.SetEncapsMethod(vswitch.EncapsMethodDirect)
	case "gre":
		t.SetEncapsMethod(vswitch.EncapsMethodGRE)
	}
}

func (s *subiface) setHopLimit(v int) {
	s.getTunnel().SetHopLimit(uint8(v))
}

func (s *subiface) setLocalAddress(ip net.IP) {
	s.getTunnel().SetLocalAddress(ip)
}

func (s *subiface) setRemoteAddress(ip net.IP) {
	s.getTunnel().SetRemoteAddress(ip)
}

func (s *subiface) setSecurity(sec string) {
	t := s.getTunnel()
	switch sec {
	case "none":
		t.SetSecurity(vswitch.SecurityNone)
	case "ipsec":
		t.SetSecurity(vswitch.SecurityIPSec)
	}
}

func (s *subiface) setTOS(t int) {
	s.getTunnel().SetTOS(int8(t))
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
	default:
		return fmt.Errorf("Unknown encryption algorithm: %v", enc)
	}
	n.getSA(spi).Encrypt = e
	return nil
}

func (n *ni) setEncryptKey(spi int, key string) {
	n.getSA(spi).EncKey = key
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
			for ip := range s.ipaddr {
				str += ip + ","
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

type openconfig struct {
	nis map[string]*ni
	ifs map[string]*iface
}

func (o *openconfig) getNetworkInstance(name string) *ni {
	n, ok := o.nis[name]
	if !ok {
		n = newNetworkInstance(o, name)
		o.nis[name] = n
	}
	return n
}

func (o *openconfig) getInterface(name string) *iface {
	i, ok := o.ifs[name]
	if !ok {
		i = newInterface(o, name)
		o.ifs[name] = i
	}
	return i
}

func (o *openconfig) free() {
	o.nis = make(map[string]*ni)
	o.ifs = make(map[string]*iface)
}

func newOpenConfig() *openconfig {
	return &openconfig{
		nis: make(map[string]*ni),
		ifs: make(map[string]*iface),
	}
}
