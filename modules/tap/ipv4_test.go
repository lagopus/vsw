package tap

import (
	"bytes"
	"flag"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/vswitch"
	"golang.org/x/net/ipv4"
)

func TestIPv4Hdr(t *testing.T) {
	// preparation
	opt := []byte{7, 7, 4, 0, 0, 0, 0, 0}
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	expHdr := &ipv4.Header{
		Version:  4,
		Len:      28, // header + option
		TOS:      0,
		TotalLen: 38, // header + option + payload
		ID:       100,
		Flags:    0,
		FragOff:  0,
		TTL:      64,
		Protocol: syscall.IPPROTO_TCP,
		Checksum: 0, // caluclate when execute SetIPv4Hdr()
		Src:      net.IPv4(10, 0, 0, 2),
		Dst:      net.IPv4(10, 1, 0, 2),
		Options:  opt,
	}
	expRaw, _ := expHdr.Marshal()
	expRaw = append(expRaw, data...)
	expSrc := uint32(expHdr.Src[12])<<24 | uint32(expHdr.Src[13])<<16 | uint32(expHdr.Src[14])<<8 | uint32(expHdr.Src[15])
	expDst := uint32(expHdr.Dst[12])<<24 | uint32(expHdr.Dst[13])<<16 | uint32(expHdr.Dst[14])<<8 | uint32(expHdr.Dst[15])

	// test
	// newIPv4Header
	iph := newIPv4Header(expRaw)
	if iph.ihl != expHdr.Len {
		t.Fatalf("[ERROR] Unexpected header length: result=%v expected=%v\n", iph.ihl, expHdr.Len)
	}

	if iph.protocol != expHdr.Protocol {
		t.Fatalf("[ERROR] Unexpected protocol: reuslt=%v expected=%v\n", iph.protocol, expHdr.Protocol)
	}

	if iph.dst != expDst {
		t.Fatalf("[ERROR] Unexpected destination address: result=%v.%v.%v.%v\n expected=%v", iph.dst>>24, (iph.dst&0xff0000)>>16, (iph.dst&0xff00)>>8, iph.dst&0xff, expHdr.Dst.String())
	}

	if int(iph.dataSize) != len(data) {
		t.Fatalf("[ERROR] Unexpected data size: result=%v expected=%v\n", iph.dataSize, len(data))
	}

	if !bytes.Equal(iph.rawData, expRaw[:expHdr.Len]) {
		t.Fatalf("[ERROR] Unexpected raw data: result=%v expected=%v\n", iph.rawData, expRaw[:expHdr.Len])
	}

	// swapSrcAndDst
	iph.swapSrcAndDst()
	rstSrc := uint32(iph.rawData[12])<<24 | uint32(iph.rawData[13])<<16 | uint32(iph.rawData[14])<<8 | uint32(iph.rawData[15])
	rstDst := uint32(iph.rawData[16])<<24 | uint32(iph.rawData[17])<<16 | uint32(iph.rawData[18])<<8 | uint32(iph.rawData[19])
	if (rstSrc != expDst) || (rstDst != expSrc) {
		t.Fatal("Failed to swap Src and Dst address")
	}

	t.Log("Test is passed\n")
}

var pool *dpdk.MemPool

func TestMain(m *testing.M) {
	if err := vswitch.Init("/usr/local/etc/vsw.conf"); err != nil {
		log.Err("[TEST] vswitch init failed: %v\n", err)
	}
	pool = vswitch.GetDpdkResource().Mempool

	// Execute test
	flag.Parse()
	rc := m.Run()

	// Tear down
	pool.Free()

	// Done
	os.Exit(rc)
}
