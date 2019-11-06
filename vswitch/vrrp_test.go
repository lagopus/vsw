package vswitch

import "testing"
import "net"

func TestVRRPGroup(t *testing.T) {
	// Expected results
	type testCase struct {
		proc      func(*VRRPGroup)
		expectLen int
	}
	tests := []testCase{
		{
			proc: func(vg *VRRPGroup) {
				vg.AddVirtualAddr(net.IPv4(192, 168, 0, 1))
			},
			expectLen: 1,
		},
		{
			proc: func(vg *VRRPGroup) {
				vg.AddVirtualAddr(net.IPv4(192, 168, 0, 1))
			},
			expectLen: 1,
		},
		{
			proc: func(vg *VRRPGroup) {
				vg.AddVirtualAddr(net.IPv4(172, 16, 110, 2))
			},
			expectLen: 2,
		},
		{
			proc: func(vg *VRRPGroup) {
				vg.DeleteVirtualAddr(net.IPv4(172, 16, 110, 2))
			},
			expectLen: 1,
		},
		{
			proc: func(vg *VRRPGroup) {
				vg.DeleteVirtualAddr(net.IPv4(10, 10, 0, 10))
			},
			expectLen: 1,
		},
	}
	vg := NewVRRPGroup(3)
	for _, test := range tests {
		test.proc(vg)
		t.Log(vg.VirtualAddrs())
		l := len(vg.virtualAddrs)
		if test.expectLen != l {
			t.Errorf("Added virtual address, expected length is %v but %v\n", test.expectLen, l)
		}
	}
}

func TestVRRP(t *testing.T) {
	type testCase struct {
		proc      func(*VRRP)
		expectLen int
	}
	tests := []testCase{
		{
			proc: func(v *VRRP) {
				vg := NewVRRPGroup(3)
				vg.Priority = 100
				v.AddVRRPGroup(vg)
			},
			expectLen: 1,
		},
		{
			proc: func(v *VRRP) {
				vg := NewVRRPGroup(128)
				vg.Priority = 30
				vg.Preempt = true
				vg.PreemptDelay = 278
				vg.AcceptMode = true
				vg.AdvertisementInterval = 300
				vg.TrackInterface = "if-0"
				vg.PriorityDecrement = 3
				vg.AddVirtualAddr(net.IPv4(192, 168, 1, 1))
				vg.AddVirtualAddr(net.IPv4(172, 16, 30, 1))
				v.AddVRRPGroup(vg)
			},
			expectLen: 2,
		},
		{
			proc: func(v *VRRP) {
				vg := NewVRRPGroup(255)
				vg.Priority = 200
				v.AddVRRPGroup(vg)
			},
			expectLen: 3,
		},
		{
			proc: func(v *VRRP) {
				v.DeleteVRRPGroup(3)
			},
			expectLen: 2,
		},
		{
			proc: func(v *VRRP) {
				v.DeleteVRRPGroup(123)
			},
			expectLen: 2,
		},
	}
	v := &VRRP{}
	for _, test := range tests {
		test.proc(v)
		l := len(v.vrrps)
		if test.expectLen != l {
			t.Errorf("Added vrrp group, expected length is %v buf %v\n", test.expectLen, l)
		}
	}
	t.Log(v.vrrps)
	vgs := v.ListVRRPGroups()
	for i, val := range vgs {
		t.Logf("VRRPGroup[%d]%s", i, val.String())
	}

	evg := &VRRPGroup{
		VirtualRouterId:       128,
		Priority:              30,
		Preempt:               true,
		PreemptDelay:          278,
		AcceptMode:            true,
		AdvertisementInterval: 300,
		TrackInterface:        "if-0",
		PriorityDecrement:     3,
	}
	evg.AddVirtualAddr(net.IPv4(192, 168, 1, 1))
	evg.AddVirtualAddr(net.IPv4(172, 16, 30, 1))
	vg := v.VRRPGroupById(128)
	if !vg.Equal(evg) {
		t.Errorf("Get VRRPGroup by VRID, expected %v but %v\n", vg, evg)
	}
}
