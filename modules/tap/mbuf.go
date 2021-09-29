package tap

/*
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
*/
import "C"

import (
	"errors"
	"net"
	"unsafe"

	"github.com/lagopus/vsw/dpdk"
	"golang.org/x/net/ipv4"
)

const (
	icmpMsgChecksumIndex = 2
	ipv4HdrChecksumIndex = 10
)

func updateChecksum(data []byte, cksumIdx int) {
	// set checksum to 0
	data[cksumIdx] = 0
	data[cksumIdx+1] = 0

	checksum := uint16(C.rte_raw_cksum(unsafe.Pointer(&data[0]), C.size_t(len(data))))
	if checksum != 0xffff {
		checksum = ^checksum
	}

	data[cksumIdx] = byte(checksum & 0xff)
	data[cksumIdx+1] = byte(checksum >> 8)
}

func rewriteICMPEchoToReply(mbuf *dpdk.Mbuf) {
	eh := mbuf.EtherHdr()
	esrc := []byte{eh[6], eh[7], eh[8], eh[9], eh[10], eh[11]}
	eh.SetSrcAddr(eh.DstAddr())
	eh.SetDstAddr(net.HardwareAddr(esrc))

	iph, _ := ipv4Header(mbuf)
	iph.swapSrcAndDst()
	updateChecksum(iph.rawData, ipv4HdrChecksumIndex)

	icmp := icmpMessage(mbuf, iph.optSize, iph.dataSize)
	icmp.setICMPType(ipv4.ICMPTypeEchoReply)
	updateChecksum(icmp, icmpMsgChecksumIndex)
}

// ipv4Header returns an IPv4 header from an mbuf.
func ipv4Header(mbuf *dpdk.Mbuf) (*ipv4Hdr, error) {
	rawData := ([]byte)((*[1 << 30]byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&mbuf.Data()[0])) + uintptr(C.sizeof_struct_ether_hdr)))[:ipv4MaxHeaderLen:ipv4MaxHeaderLen])

	if rawData[0]>>4 != ipv4.Version {
		return nil, errors.New("Not IPv4 Header")
	}

	return newIPv4Header(rawData), nil
}

type icmpMsg []byte

func (i icmpMsg) icmpType() ipv4.ICMPType {
	return ipv4.ICMPType(i[0])
}

func (i icmpMsg) setICMPType(t ipv4.ICMPType) {
	i[0] = byte(t)
}

// icmpMessage returns an ICMP message from an mbuf.
func icmpMessage(mbuf *dpdk.Mbuf, iphOptSize int, size uint16) icmpMsg {
	return (icmpMsg)((*[1 << 30]byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&mbuf.Data()[0])) + uintptr(C.sizeof_struct_ether_hdr) + uintptr(C.sizeof_struct_ipv4_hdr) + uintptr(iphOptSize)))[:size:size])
}
