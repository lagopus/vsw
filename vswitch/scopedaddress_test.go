package vswitch

import "testing"
import "net"

func TestScopedAddress(t *testing.T) {
	// Test that fails to create ScopedAddress instance
	sa, err := NewScopedAddress(net.IPv4(192, 168, 1, 0), nil)
	if sa != nil || err == nil {
		t.Errorf("Unexpected result: when vif is nil, do not create sa and return a err")
	}

	// Test that fails to create ScopedAddress instance
	sa, err = NewScopedAddress(nil, &VIF{index: 2, name: "test-vif"})
	if sa != nil || err == nil {
		t.Errorf("Unexpected result: when address is nil, do not create sa and return a err")
	}

	// Test that success to create ScopedAddress instance
	sa, err = NewScopedAddress(net.IPv4(192, 168, 1, 0), &VIF{index: 2, name: "test-vif"})
	if sa == nil || err != nil {
		t.Errorf("Unexpected result: fail to create ScopedAddress instnce")
	}

	// Test that stringer of ScopedAddress instance
	expect := "vif: test-vif (2), address: 192.168.1.0"
	s := sa.String()
	if expect != s {
		t.Errorf("Unexpected result: Expected: %v, Result: %v", expect, s)
	}
	t.Logf("Result: %v. ok", s)
}
