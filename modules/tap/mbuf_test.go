package tap

import (
	"bytes"
	"net"
	"reflect"
	"syscall"
	"testing"

	"github.com/lagopus/vsw/dpdk"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func TestMbuf(t *testing.T) {
	// preparation
	mbuf := pool.AllocMbuf()
	expRep := pool.AllocMbuf()

	// echo request
	echoReq := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		},
	}
	expIcmp, _ := echoReq.Marshal(nil)

	opt := []byte{7, 7, 4, 0, 0, 0, 0, 0}
	iph := &ipv4.Header{
		Version:  4,
		Len:      28, // header + option
		TOS:      0,
		TotalLen: 46, // header + option + icmp message
		ID:       100,
		Flags:    0,
		FragOff:  0,
		TTL:      64,
		Protocol: syscall.IPPROTO_TCP,
		Checksum: 0,
		Src:      net.IPv4(10, 10, 0, 10),
		Dst:      net.IPv4(172, 16, 120, 10),
		Options:  opt,
	}
	iphRaw, _ := iph.Marshal()
	iphRaw = append(iphRaw, expIcmp...)
	expIph := newIPv4Header(iphRaw)

	eh := make(dpdk.EtherHdr, 14)
	eh.SetEtherType(dpdk.ETHER_TYPE_IPv4)
	src, err := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	dst, err := net.ParseMAC("11:22:33:44:55:66")
	eh.SetSrcAddr(src)
	eh.SetDstAddr(dst)
	eh = append(eh, iphRaw...)

	mbuf.SetData(eh)

	// echo repty
	eh = make(dpdk.EtherHdr, 14)
	eh.SetEtherType(dpdk.ETHER_TYPE_IPv4)
	eh.SetSrcAddr(dst)
	eh.SetDstAddr(src)
	tmp := iph.Src
	iph.Src = iph.Dst
	iph.Dst = tmp
	iph.Checksum = 16177
	iphRaw, _ = iph.Marshal()
	echoReq.Type = ipv4.ICMPTypeEchoReply
	repRaw, _ := echoReq.Marshal(nil)
	eh = append(eh, iphRaw...)
	eh = append(eh, repRaw...)
	expRep.SetData(eh)

	// test
	// ipv4Header()
	rstIph, err := ipv4Header(mbuf)
	if (err != nil) || !reflect.DeepEqual(rstIph, expIph) {
		log.Fatalf("Unexpected IPv4 header: error=%v result=%v expected=%v\n", err, rstIph, expIph)
	}

	// icmoMessage()
	rstIcmp := icmpMessage(mbuf, expIph.optSize, rstIph.dataSize)
	if !bytes.Equal(rstIcmp, expIcmp) {
		log.Fatalf("Unexpected ICMP message:\n result=%v \nexpected=%v %v %v %v %v\n", rstIcmp, expIcmp, len(rstIcmp), cap(rstIcmp), len(expIcmp), cap(expIcmp))
	}

	// updateChecksum()
	updateChecksum(rstIcmp, icmpMsgChecksumIndex)
	rstCksum := (uint16(rstIcmp[2]) << 8) | uint16(rstIcmp[3])
	expCksum := (uint16(expIcmp[2]) << 8) | uint16(expIcmp[3])
	if rstCksum != expCksum {
		log.Fatalf("Unexpected checksum: result=%v expected=%v\n", rstCksum, expCksum)
	}

	// rewriteICMPEchoToReply()
	rewriteICMPEchoToReply(mbuf)
	if !bytes.Equal(mbuf.Data(), expRep.Data()) {
		t.Fatalf("Failed to rewrite ICMP echo to reply: \nresult=%v \nexpected=%v %v %v\n", mbuf.Data(), expRep.Data(), len(mbuf.Data()), len(expRep.Data()))
	}

	mbuf.Free()
	t.Log("Test is passed\n")

}
