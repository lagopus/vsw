package vswitch

import (
	"errors"
	"fmt"
	"net"
)

// ScopedAddress represents ScopedAddress
type ScopedAddress struct {
	address net.IP
	vif     *VIF
}

// NewScopedAddress creates a ScopedAddress instance.
// VIF is can not be nil.
func NewScopedAddress(addr net.IP, vif *VIF) (*ScopedAddress, error) {
	if vif == nil {
		return nil, errors.New("VIF can not be nil.")
	}
	if addr == nil {
		return nil, errors.New("Address can not be nil.")
	}
	return &ScopedAddress{address: addr, vif: vif}, nil
}

func (sa *ScopedAddress) String() string {
	return fmt.Sprintf("vif: %v (%v), address: %v", sa.vif.Name(), sa.vif.Index(), sa.address)
}

func (sa *ScopedAddress) Address() net.IP {
	return sa.address
}

func (sa *ScopedAddress) VIF() *VIF {
	return sa.vif
}
