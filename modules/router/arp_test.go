package router

import (
	"net"
	"testing"
)

func TestARPMarshal(t *testing.T) {
	senderHW := NewEtherAddr(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x01})
	arp := NewARPRequest(NewIPv4Addr(192, 168, 0, 1), NewIPv4Addr(10, 10, 0, 1), senderHW)

	t.Logf("orig> %v\n", arp)

	buf := arp.Encode()
	t.Logf("bin > % x\n", buf)

	arp2 := new(ARPPacket)
	if err := arp2.Decode(buf); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	t.Logf("prsd> %v\n", arp2)

	if arp.String() != arp2.String() {
		t.Fatalf("Encode -> Decode didn't match")
	}

	t.Logf("matched")

	t.Logf("test short buffer")
	if err := arp2.Decode(make([]byte, 41)); err != nil {
		t.Logf("Decode failed as expected: %v", err)
	} else {
		t.Fatalf("Decode succeeded....")
	}

	t.Logf("test bad arp packet")
	if err := arp2.Decode(make([]byte, 42)); err != nil {
		t.Logf("Decode failed as expected: %v", err)
	} else {
		t.Fatalf("Decode succeeded....")
	}
}
