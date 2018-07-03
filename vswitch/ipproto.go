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

package vswitch

import "syscall"

// IP Protocol Type
type IPProto int

const (
	IPP_AH       = IPProto(syscall.IPPROTO_AH)
	IPP_COMP     = IPProto(syscall.IPPROTO_COMP)
	IPP_DCCP     = IPProto(syscall.IPPROTO_DCCP)
	IPP_DSTOPTS  = IPProto(syscall.IPPROTO_DSTOPTS)
	IPP_EGP      = IPProto(syscall.IPPROTO_EGP)
	IPP_ENCAP    = IPProto(syscall.IPPROTO_ENCAP)
	IPP_ESP      = IPProto(syscall.IPPROTO_ESP)
	IPP_FRAGMENT = IPProto(syscall.IPPROTO_FRAGMENT)
	IPP_GRE      = IPProto(syscall.IPPROTO_GRE)
	IPP_HOPOPTS  = IPProto(syscall.IPPROTO_HOPOPTS)
	IPP_ICMP     = IPProto(syscall.IPPROTO_ICMP)
	IPP_ICMPV6   = IPProto(syscall.IPPROTO_ICMPV6)
	IPP_IDP      = IPProto(syscall.IPPROTO_IDP)
	IPP_IGMP     = IPProto(syscall.IPPROTO_IGMP)
	IPP_IP       = IPProto(syscall.IPPROTO_IP)
	IPP_IPIP     = IPProto(syscall.IPPROTO_IPIP)
	IPP_IPV6     = IPProto(syscall.IPPROTO_IPV6)
	IPP_MTP      = IPProto(syscall.IPPROTO_MTP)
	IPP_NONE     = IPProto(syscall.IPPROTO_NONE)
	IPP_PIM      = IPProto(syscall.IPPROTO_PIM)
	IPP_PUP      = IPProto(syscall.IPPROTO_PUP)
	IPP_RAW      = IPProto(syscall.IPPROTO_RAW)
	IPP_ROUTING  = IPProto(syscall.IPPROTO_ROUTING)
	IPP_RSVP     = IPProto(syscall.IPPROTO_RSVP)
	IPP_SCTP     = IPProto(syscall.IPPROTO_SCTP)
	IPP_TCP      = IPProto(syscall.IPPROTO_TCP)
	IPP_TP       = IPProto(syscall.IPPROTO_TP)
	IPP_UDP      = IPProto(syscall.IPPROTO_UDP)
	IPP_UDPLITE  = IPProto(syscall.IPPROTO_UDPLITE)
	IPP_ANY      = IPProto(-1)
)

func (ipp IPProto) String() string {
	s := map[IPProto]string{
		IPP_AH:       "AH",
		IPP_COMP:     "COMP",
		IPP_DCCP:     "DCCP",
		IPP_DSTOPTS:  "DSTOPTS",
		IPP_EGP:      "EGP",
		IPP_ENCAP:    "ENCAP",
		IPP_ESP:      "ESP",
		IPP_FRAGMENT: "FRAGMENT",
		IPP_GRE:      "GRE",
		IPP_ICMP:     "ICMP",
		IPP_ICMPV6:   "ICMPV6",
		IPP_IDP:      "IDP",
		IPP_IGMP:     "IGMP",
		IPP_IP:       "IP or HOPOPTS",
		IPP_IPIP:     "IPIP",
		IPP_IPV6:     "IPV6",
		IPP_MTP:      "MTP",
		IPP_NONE:     "NONE",
		IPP_PIM:      "PIM",
		IPP_PUP:      "PUP",
		IPP_RAW:      "RAW",
		IPP_ROUTING:  "ROUTING",
		IPP_RSVP:     "RSVP",
		IPP_SCTP:     "SCTP",
		IPP_TCP:      "TCP",
		IPP_TP:       "TP",
		IPP_UDP:      "UDP",
		IPP_UDPLITE:  "UDPLITE",
		IPP_ANY:      "ANY",
	}
	return s[ipp]
}
