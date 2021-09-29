package tap

/*
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
*/
import "C"

import "golang.org/x/net/ipv4"

const ipv4MaxHeaderLen = uint(60)

type ipv4Hdr struct {
	rawData  []byte
	ihl      int
	protocol int
	dst      uint32
	optSize  int
	dataSize uint16
}

func newIPv4Header(rawData []byte) *ipv4Hdr {
	iph := new(ipv4Hdr)
	iph.ihl = int((rawData[0] & 0x0f) << 2)
	iph.optSize = iph.ihl - ipv4.HeaderLen
	iph.dataSize = (uint16(rawData[2])<<8 | uint16(rawData[3])) - uint16(iph.ihl)
	iph.protocol = int(rawData[9])
	iph.dst = uint32(rawData[16])<<24 | uint32(rawData[17])<<16 | uint32(rawData[18])<<8 | uint32(rawData[19])
	iph.rawData = rawData[:iph.ihl:iph.ihl]
	return iph
}

func (iph *ipv4Hdr) swapSrcAndDst() {
	// dst
	iph.rawData[16] = iph.rawData[12]
	iph.rawData[17] = iph.rawData[13]
	iph.rawData[18] = iph.rawData[14]
	iph.rawData[19] = iph.rawData[15]
	// src
	iph.rawData[12] = byte(iph.dst >> 24)
	iph.rawData[13] = byte(iph.dst >> 16)
	iph.rawData[14] = byte(iph.dst >> 8)
	iph.rawData[15] = byte(iph.dst)
}
