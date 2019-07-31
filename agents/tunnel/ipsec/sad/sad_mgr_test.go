//
// Copyright 2017-2019 Nippon Telegraph and Telephone Corporation.
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

package sad

import (
	"net"
	"testing"
	"time"

	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/vswitch"
	"github.com/stretchr/testify/suite"
)

// init Test Suite

type sadMgrTestSuite struct {
	suite.Suite
	in       *Mgr
	out      *Mgr
	selector *SASelector
}

const vrfIndex vswitch.VRFIndex = 0

func (suite *sadMgrTestSuite) SetupSuite() {
	setupTest() // testutil
	suite.in = GetMgr(ipsec.DirectionTypeIn)
	suite.in.vrfs[vrfIndex] = suite.in.newVRF(vrfIndex)
	suite.in.vrfs[vrfIndex].csad = &mockCSAD{
		BaseCSAD: ipsec.NewBaseCSAD(0, ipsec.DirectionTypeIn),
	}
	suite.out = GetMgr(ipsec.DirectionTypeOut)
	suite.out.vrfs[vrfIndex] = suite.out.newVRF(vrfIndex)
	suite.out.vrfs[vrfIndex].csad = &mockCSAD{
		BaseCSAD: ipsec.NewBaseCSAD(0, ipsec.DirectionTypeOut),
	}
	suite.selector = &SASelector{
		VRFIndex: vrfIndex,
	}
}

func (suite *sadMgrTestSuite) TearDownSuite() {
	teardownTest() // testutil
}

func (suite *sadMgrTestSuite) SetupTest() {
	// suite.in -> blank
	// suite.out -> set some SA for debug
	base := SAValue{
		CSAValue: ipsec.CSAValue{
			CipherAlgoType: ipsec.CipherAlgoTypeNull,
			AuthAlgoType:   ipsec.AuthAlgoTypeNull,
			LocalEPIP:      mkIP("192.168.0.1"),
		},
	}
	var sav SAValue
	sav = base
	sav.RemoteEPIP = mkIP("192.168.1.1")
	sav.inStat = reserved
	suite.out.vrfs[vrfIndex].sad[1] = sav
	sav = base
	sav.RemoteEPIP = mkIP("192.168.1.2")
	sav.inStat = newing
	suite.out.vrfs[vrfIndex].sad[2] = sav
	sav = base
	sav.RemoteEPIP = mkIP("192.168.1.3")
	sav.inStat = valid
	suite.out.vrfs[vrfIndex].sad[3] = sav
	sav = base
	sav.RemoteEPIP = mkIP("192.168.1.4")
	sav.inStat = updating
	suite.out.vrfs[vrfIndex].sad[4] = sav
	sav = base
	sav.RemoteEPIP = mkIP("192.168.1.5")
	sav.inStat = softExpired
	suite.out.vrfs[vrfIndex].sad[5] = sav
	sav = base
	sav.RemoteEPIP = mkIP("192.168.1.6")
	sav.inStat = hardExpired
	suite.out.vrfs[vrfIndex].sad[6] = sav
	sav = base
	sav.RemoteEPIP = mkIP("192.168.1.7")
	sav.inStat = deleting
	suite.out.vrfs[vrfIndex].sad[7] = sav
}

func (suite *sadMgrTestSuite) TearDownTest() {
	clearSAD(suite.in)
	clearSAD(suite.out)
}

func TestSADMgrTestSuites(t *testing.T) {
	tests := new(sadMgrTestSuite)
	suite.Run(t, tests)
}

// define Tests

func (suite *sadMgrTestSuite) TestGetMgr() {
	in := GetMgr(ipsec.DirectionTypeIn)
	suite.NotNil(in)
	suite.Empty(in.vrfs[vrfIndex].sad)

	out := GetMgr(ipsec.DirectionTypeOut)
	suite.NotNil(out)
	suite.NotEmpty(out.vrfs[vrfIndex].sad)

	suite.NotEqual(in, out)

	suite.Equal(GetMgr(ipsec.DirectionTypeIn), in)
	suite.Equal(GetMgr(ipsec.DirectionTypeOut), out)
}

func (suite *sadMgrTestSuite) TestReserveSA() {
	// using preset-SAD
	mgr := suite.out
	selector := suite.selector
	vrf := mgr.vrfs[selector.VRFIndex]
	firstLen := len(vrf.sad)

	// reserve 0 (error. InvalidSPI)
	selector.SPI = 0
	suite.Error(mgr.ReserveSA(selector))
	suite.Len(vrf.sad, firstLen)

	// reserve 1-7 (error. AlreadyExists)
	selector.SPI = 1
	suite.Error(mgr.ReserveSA(selector))
	suite.Equal(reserved, vrf.sad[1].inStat) // not changed
	selector.SPI = 2
	suite.Error(mgr.ReserveSA(selector))
	suite.Equal(newing, vrf.sad[2].inStat) // not changed
	selector.SPI = 3
	suite.Error(mgr.ReserveSA(selector))
	suite.Equal(valid, vrf.sad[3].inStat) // not changed
	selector.SPI = 4
	suite.Error(mgr.ReserveSA(selector))
	suite.Equal(updating, vrf.sad[4].inStat) // not changed
	selector.SPI = 5
	suite.Error(mgr.ReserveSA(selector))
	suite.Equal(softExpired, vrf.sad[5].inStat) // not changed
	selector.SPI = 6
	suite.Error(mgr.ReserveSA(selector))
	suite.Equal(hardExpired, vrf.sad[6].inStat) // not changed
	selector.SPI = 7
	suite.Error(mgr.ReserveSA(selector))
	suite.Equal(deleting, vrf.sad[7].inStat) // not changed
	suite.Len(vrf.sad, firstLen)

	// reserve 10
	selector.SPI = 10
	suite.NoError(mgr.ReserveSA(selector))
	suite.Len(vrf.sad, firstLen+1)
	suite.Equal(reserved, vrf.sad[10].inStat)

	// reserve 10 again (error. AlreadyExists)
	suite.Error(mgr.ReserveSA(selector))
	suite.Len(vrf.sad, firstLen+1)
	suite.Equal(reserved, vrf.sad[10].inStat)

	// reserve 11
	selector.SPI = 11
	suite.NoError(mgr.ReserveSA(selector))
	suite.Len(vrf.sad, firstLen+2)
	suite.Equal(reserved, vrf.sad[11].inStat)
}

func (suite *sadMgrTestSuite) TestAddSA() {
	// using preset-SAD
	mgr := suite.out
	selector := suite.selector
	vrf := mgr.vrfs[selector.VRFIndex]
	firstLen := len(vrf.sad)

	sav := &SAValue{
		CSAValue: ipsec.CSAValue{
			CipherAlgoType: ipsec.CipherAlgoTypeAes128Cbc,
		},
	}

	// add 0 (error. InvalidSPI)
	selector.SPI = 0
	suite.Error(mgr.AddSA(selector, sav))
	suite.Len(vrf.sad, firstLen)

	// add 1
	selector.SPI = 1
	suite.Error(mgr.AddSA(selector, sav))
	// add 2-7 (error. AlreadyExists)
	selector.SPI = 2
	suite.Error(mgr.AddSA(selector, sav))
	suite.Equal(newing, vrf.sad[2].inStat)                           // not changed
	suite.Equal(ipsec.CipherAlgoTypeNull, vrf.sad[2].CipherAlgoType) // not changed
	selector.SPI = 3
	suite.Error(mgr.AddSA(selector, sav))
	suite.Equal(valid, vrf.sad[3].inStat)                            // not changed
	suite.Equal(ipsec.CipherAlgoTypeNull, vrf.sad[3].CipherAlgoType) // not changed
	selector.SPI = 4
	suite.Error(mgr.AddSA(selector, sav))
	suite.Equal(updating, vrf.sad[4].inStat)                         // not changed
	suite.Equal(ipsec.CipherAlgoTypeNull, vrf.sad[4].CipherAlgoType) // not changed
	selector.SPI = 5
	suite.Error(mgr.AddSA(selector, sav))
	suite.Equal(softExpired, vrf.sad[5].inStat)                      // not changed
	suite.Equal(ipsec.CipherAlgoTypeNull, vrf.sad[5].CipherAlgoType) // not changed
	selector.SPI = 6
	suite.Error(mgr.AddSA(selector, sav))
	suite.Equal(hardExpired, vrf.sad[6].inStat)                      // not changed
	suite.Equal(ipsec.CipherAlgoTypeNull, vrf.sad[6].CipherAlgoType) // not changed
	selector.SPI = 7
	suite.Error(mgr.AddSA(selector, sav))
	suite.Equal(deleting, vrf.sad[7].inStat)                         // not changed
	suite.Equal(ipsec.CipherAlgoTypeNull, vrf.sad[7].CipherAlgoType) // not changed
	suite.Len(vrf.sad, firstLen)

	// add 10
	selector.SPI = 10
	suite.NoError(mgr.AddSA(selector, sav))
	suite.Len(vrf.sad, firstLen+1)
	suite.Equal(reserved, vrf.sad[10].inStat)
	suite.Equal(ipsec.CipherAlgoTypeAes128Cbc, vrf.sad[10].CipherAlgoType)

	// add 10 again (no error. update.)
	sav2 := &SAValue{
		CSAValue: ipsec.CSAValue{
			CipherAlgoType: ipsec.CipherAlgoType3desCbc,
		},
	}
	suite.Error(mgr.AddSA(selector, sav2))

	// add 11
	selector.SPI = 11
	suite.NoError(mgr.AddSA(selector, sav))
	suite.Len(vrf.sad, firstLen+2)
	suite.Equal(reserved, vrf.sad[11].inStat)
	suite.Equal(ipsec.CipherAlgoTypeAes128Cbc, vrf.sad[11].CipherAlgoType)
}

func (suite *sadMgrTestSuite) TestUpdateSA() {
	// using preset-SAD
	mgr := suite.out
	selector := suite.selector
	vrf := mgr.vrfs[selector.VRFIndex]
	firstLen := len(vrf.sad)

	sav := &SAValue{
		CSAValue: ipsec.CSAValue{
			CipherAlgoType: ipsec.CipherAlgoTypeAes128Cbc,
		},
	}

	// update 0 (error. InvalidSPI)
	selector.SPI = 0
	suite.Error(mgr.UpdateSA(selector, sav))
	suite.Len(vrf.sad, firstLen)

	// update 1-6 (no error)
	selector.SPI = 1
	suite.NoError(mgr.UpdateSA(selector, sav))
	suite.Equal(reserved, vrf.sad[1].inStat)                              // not changed
	suite.Equal(ipsec.CipherAlgoTypeAes128Cbc, vrf.sad[1].CipherAlgoType) // changed
	selector.SPI = 2
	suite.NoError(mgr.UpdateSA(selector, sav))
	suite.Equal(newing, vrf.sad[2].inStat)                                // not changed
	suite.Equal(ipsec.CipherAlgoTypeAes128Cbc, vrf.sad[2].CipherAlgoType) // changed
	selector.SPI = 3
	suite.NoError(mgr.UpdateSA(selector, sav))
	suite.Equal(valid, vrf.sad[3].inStat)                                 // not changed
	suite.Equal(ipsec.CipherAlgoTypeAes128Cbc, vrf.sad[3].CipherAlgoType) // changed
	selector.SPI = 4
	suite.NoError(mgr.UpdateSA(selector, sav))
	suite.Equal(updating, vrf.sad[4].inStat)                              // not changed
	suite.Equal(ipsec.CipherAlgoTypeAes128Cbc, vrf.sad[4].CipherAlgoType) // changed
	selector.SPI = 5
	suite.NoError(mgr.UpdateSA(selector, sav))
	suite.Equal(softExpired, vrf.sad[5].inStat)                           // not changed
	suite.Equal(ipsec.CipherAlgoTypeAes128Cbc, vrf.sad[5].CipherAlgoType) // changed
	selector.SPI = 6
	suite.NoError(mgr.UpdateSA(selector, sav))
	suite.Equal(hardExpired, vrf.sad[6].inStat)                           // not changed
	suite.Equal(ipsec.CipherAlgoTypeAes128Cbc, vrf.sad[6].CipherAlgoType) // changed
	// update 7 (error. already marked as 'deleting')
	selector.SPI = 7
	suite.Error(mgr.UpdateSA(selector, sav))
	suite.Equal(deleting, vrf.sad[7].inStat)                         // not changed
	suite.Equal(ipsec.CipherAlgoTypeNull, vrf.sad[7].CipherAlgoType) // not changed
	suite.Len(vrf.sad, firstLen)

	// update 10 (error. NotExists)
	selector.SPI = 10
	suite.Error(mgr.UpdateSA(selector, sav))
	suite.Len(vrf.sad, firstLen)
}

func (suite *sadMgrTestSuite) TestEnableSA() {
	// using preset-SAD
	mgr := suite.out
	selector := suite.selector
	vrf := mgr.vrfs[selector.VRFIndex]
	firstLen := len(vrf.sad)

	// update 0 (error. InvalidSPI)
	selector.SPI = 0
	suite.Error(mgr.EnableSA(selector))
	suite.Len(vrf.sad, firstLen)

	// update 1-2 (no error, change state 'newing')
	selector.SPI = 1
	suite.NoError(mgr.EnableSA(selector))
	suite.Equal(newing, vrf.sad[1].inStat)
	selector.SPI = 2
	suite.NoError(mgr.EnableSA(selector))
	suite.Equal(newing, vrf.sad[2].inStat)
	// update 3 (no error, change state 'updating')
	selector.SPI = 3
	suite.NoError(mgr.EnableSA(selector))
	suite.Equal(updating, vrf.sad[3].inStat)
	selector.SPI = 4
	suite.NoError(mgr.EnableSA(selector))
	suite.Equal(updating, vrf.sad[4].inStat)
	selector.SPI = 5
	suite.NoError(mgr.EnableSA(selector))
	suite.Equal(updating, vrf.sad[5].inStat)
	// update 6,7 (error. already marked as 'hardExpired' or 'deleting')
	selector.SPI = 6
	suite.Error(mgr.EnableSA(selector))
	suite.Equal(hardExpired, vrf.sad[6].inStat)
	selector.SPI = 7
	suite.Error(mgr.EnableSA(selector))
	suite.Equal(deleting, vrf.sad[7].inStat) // not changed
	suite.Len(vrf.sad, firstLen)

	// update 10 (error. NotExists)
	selector.SPI = 10
	suite.Error(mgr.EnableSA(selector))
	suite.Len(vrf.sad, firstLen)
}

func (suite *sadMgrTestSuite) TestDeleteSA() {
	// using preset-SAD
	mgr := suite.out
	selector := suite.selector
	vrf := mgr.vrfs[selector.VRFIndex]
	firstLen := len(vrf.sad)

	// delete 0 (error. InvalidSPI)
	selector.SPI = 0
	suite.Error(mgr.DeleteSA(selector))
	suite.Len(vrf.sad, firstLen)

	// delete 1-6 (no error)
	selector.SPI = 1
	suite.NoError(mgr.DeleteSA(selector))
	suite.NotContains(vrf.sad, 1) // deleted
	selector.SPI = 2
	suite.NoError(mgr.DeleteSA(selector))
	suite.NotContains(vrf.sad, 2) // deleted
	selector.SPI = 3
	suite.NoError(mgr.DeleteSA(selector))
	suite.Equal(deleting, vrf.sad[3].inStat) // changed
	selector.SPI = 4
	suite.NoError(mgr.DeleteSA(selector))
	suite.Equal(deleting, vrf.sad[4].inStat) // changed
	selector.SPI = 5
	suite.NoError(mgr.DeleteSA(selector))
	suite.Equal(deleting, vrf.sad[5].inStat) // changed
	selector.SPI = 6
	suite.NoError(mgr.DeleteSA(selector))
	suite.Equal(deleting, vrf.sad[6].inStat) // changed
	suite.Len(vrf.sad, firstLen-2)
	// delete 7 (error. already marked as 'deleting')
	selector.SPI = 7
	suite.Error(mgr.DeleteSA(selector))      // error
	suite.Equal(deleting, vrf.sad[7].inStat) // not changed
	suite.Len(vrf.sad, firstLen-2)

	// delete 10 (error. NotExists)
	selector.SPI = 10
	suite.Error(mgr.DeleteSA(selector))
	suite.Len(vrf.sad, firstLen-2)
}

func (suite *sadMgrTestSuite) TestFindSA() {
	// using preset-SAD
	mgr := suite.out
	selector := suite.selector
	vrf := mgr.vrfs[selector.VRFIndex]
	firstLen := len(vrf.sad)
	var ret *SAValue
	var err error

	// find 0 (error. InvalidSPI)
	selector.SPI = 0
	ret, err = mgr.FindSA(selector)
	suite.Error(err)
	suite.Nil(ret)

	// find 1-5 (no error, found
	selector.SPI = 1
	ret, err = mgr.FindSA(selector)
	suite.NoError(err)
	suite.Equal(vrf.sad[1], *ret)
	selector.SPI = 2
	ret, err = mgr.FindSA(selector)
	suite.NoError(err)
	suite.Equal(vrf.sad[2], *ret)
	selector.SPI = 3
	ret, err = mgr.FindSA(selector)
	suite.NoError(err)
	suite.Equal(vrf.sad[3], *ret)
	selector.SPI = 4
	ret, err = mgr.FindSA(selector)
	suite.NoError(err)
	suite.Equal(vrf.sad[4], *ret)
	selector.SPI = 5
	ret, err = mgr.FindSA(selector)
	suite.NoError(err)
	suite.Equal(vrf.sad[5], *ret)
	// find 6 (error, hardExpired)
	selector.SPI = 6
	ret, err = mgr.FindSA(selector)
	suite.Error(err)
	suite.Nil(ret)
	// find 7 (error, deleting)
	selector.SPI = 7
	ret, err = mgr.FindSA(selector)
	suite.Error(err)
	suite.Nil(ret)

	// find 10 (error. NotExists)
	selector.SPI = 10
	ret, err = mgr.FindSA(selector)
	suite.Error(err)
	suite.Nil(ret)

	suite.Len(vrf.sad, firstLen)
}

func (suite *sadMgrTestSuite) TestFindSAbyIP() {
	// using preset-SAD
	mgr := suite.out
	selector := suite.selector
	vrf := mgr.vrfs[selector.VRFIndex]
	firstLen := len(vrf.sad)
	var retk SPI
	var retv *SAValue
	var err error

	local := net.ParseIP("192.168.0.1")

	// find 1-5 (no error, found)
	retk, retv, err = mgr.FindSAbyIP(selector, local, net.ParseIP("192.168.1.1"))
	suite.NoError(err)
	suite.Equal(SPI(1), retk)
	suite.Equal(vrf.sad[1], *retv)
	retk, retv, err = mgr.FindSAbyIP(selector, local, net.ParseIP("192.168.1.2"))
	suite.NoError(err)
	suite.Equal(SPI(2), retk)
	suite.Equal(vrf.sad[2], *retv)
	retk, retv, err = mgr.FindSAbyIP(selector, local, net.ParseIP("192.168.1.3"))
	suite.NoError(err)
	suite.Equal(SPI(3), retk)
	suite.Equal(vrf.sad[3], *retv)
	retk, retv, err = mgr.FindSAbyIP(selector, local, net.ParseIP("192.168.1.4"))
	suite.NoError(err)
	suite.Equal(SPI(4), retk)
	suite.Equal(vrf.sad[4], *retv)
	retk, retv, err = mgr.FindSAbyIP(selector, local, net.ParseIP("192.168.1.5"))
	suite.NoError(err)
	suite.Equal(SPI(5), retk)
	suite.Equal(vrf.sad[5], *retv)
	// find 6 (error, hardExpired)
	retk, retv, err = mgr.FindSAbyIP(selector, local, net.ParseIP("192.168.1.6"))
	suite.Error(err)
	suite.Equal(InvalidSPI, retk)
	suite.Nil(retv)
	// find 7 (error, deleting)
	retk, retv, err = mgr.FindSAbyIP(selector, local, net.ParseIP("192.168.1.7"))
	suite.Error(err)
	suite.Equal(InvalidSPI, retk)
	suite.Nil(retv)

	// not found
	retk, retv, err = mgr.FindSAbyIP(selector, net.IP{}, net.IP{})
	suite.Error(err)
	suite.Equal(InvalidSPI, retk)
	suite.Nil(retv)
	retk, retv, err = mgr.FindSAbyIP(selector, local, net.ParseIP("192.168.1.0"))
	suite.Error(err)
	suite.Equal(InvalidSPI, retk)
	suite.Nil(retv)
	retk, retv, err = mgr.FindSAbyIP(selector, net.ParseIP("192.168.1.1"), local)
	suite.Error(err)
	suite.Equal(InvalidSPI, retk)
	suite.Nil(retv)

	remote := net.ParseIP("192.168.1.10")
	sav10 := &SAValue{
		CSAValue: ipsec.CSAValue{
			LocalEPIP:  local,
			RemoteEPIP: remote,
		},
		LifeTimeCurrent: time.Unix(10000, 0),
	}
	sav11 := &SAValue{
		CSAValue: ipsec.CSAValue{
			LocalEPIP:  local,
			RemoteEPIP: remote,
		},
		LifeTimeCurrent: time.Unix(20000, 0),
	}
	// add 10
	selector.SPI = 10
	suite.NoError(mgr.AddSA(selector, sav10))

	// find 10 (or 11) (10 found)
	retk, retv, err = mgr.FindSAbyIP(selector, local, remote)
	suite.NoError(err)
	suite.Equal(SPI(10), retk)
	suite.Equal(vrf.sad[10], *retv)

	// add 11
	selector.SPI = 11
	suite.NoError(mgr.AddSA(selector, sav11))

	// find 10 or 11 (11 found)
	retk, retv, err = mgr.FindSAbyIP(selector, local, remote)
	suite.NoError(err)
	suite.Equal(SPI(11), retk)
	suite.Equal(vrf.sad[11], *retv)

	// force modify 10 currentTime
	sav10x := vrf.sad[10]
	sav10x.LifeTimeCurrent = time.Unix(30000, 0)
	vrf.sad[10] = sav10x

	// find 10 or 11 (10 found)
	retk, retv, err = mgr.FindSAbyIP(selector, local, remote)
	suite.NoError(err)
	suite.Equal(SPI(10), retk)
	suite.Equal(vrf.sad[10], *retv)

	// ip6
	sav20 := &SAValue{
		CSAValue: ipsec.CSAValue{
			LocalEPIP:  net.ParseIP("fe80::1"),
			RemoteEPIP: net.ParseIP("fe80::2"),
		},
	}
	selector.SPI = 20
	suite.NoError(mgr.AddSA(selector, sav20))
	// find 20 (found)
	retk, retv, err = mgr.FindSAbyIP(selector, net.ParseIP("fe80::1"), net.ParseIP("fe80::2"))
	suite.NoError(err)
	suite.Equal(SPI(20), retk)
	suite.Equal(vrf.sad[20], *retv)

	suite.Len(vrf.sad, firstLen+3)
}

func (suite *sadMgrTestSuite) TestPushSA() {
	// using preset-SAD
	mgr := suite.out
	selector := suite.selector
	vrf := mgr.vrfs[selector.VRFIndex]
	// now, sad is ...
	// SPI  Go-SAD        Next  Curr
	// ----------------------------------
	//  1   reserved      x     x
	//  2   newing        x     x
	//  3   valid         x     x
	//  4   updating      x     x
	//  5   softExpired   x     x
	//  6   hardExpired   x     x
	//  7   deleting      x     x
	suite.Len(vrf.sad, 7)

	var err error

	// push
	err = mgr.PushSAD()
	suite.NoError(err)

	// now, sad is ...
	// SPI  Go-SAD        Next  Curr
	// ----------------------------------
	//  1   reserved      x     x
	//  2   VALID         O.    x
	//  3   valid         O.    x
	//  4   VALID         O.    x
	//  5   softExpired   O.    x
	//  6   (NIL)         x*    x
	//  7   (NIL)         x*    x
	suite.Len(vrf.sad, 5)
	suite.Equal(reserved, vrf.sad[1].inStat)
	suite.Equal(valid, vrf.sad[2].inStat)
	suite.Equal(valid, vrf.sad[3].inStat)
	suite.Equal(valid, vrf.sad[4].inStat)
	suite.Equal(softExpired, vrf.sad[5].inStat)

	// push again (nothing to push)
	err = mgr.PushSAD()
	suite.NoError(err)

	// now, sad is ...
	// SPI  Go-SAD        Next  Curr
	// ----------------------------------
	//  1   reserved      x     x
	//  2   valid         o.    x
	//  3   valid         o.    x
	//  4   valid         o.    x
	//  5   softExpired   o.    x
	//  6   (nil)         x     x
	//  7   (nil)         x     x
	suite.Len(vrf.sad, 5)
	suite.Equal(reserved, vrf.sad[1].inStat)
	suite.Equal(valid, vrf.sad[2].inStat)
	suite.Equal(valid, vrf.sad[3].inStat)
	suite.Equal(valid, vrf.sad[4].inStat)
	suite.Equal(softExpired, vrf.sad[5].inStat)
	// TBD: check Next

	// force modify stat
	vrf.sad.changeStatus(1, newing)
	vrf.sad.changeStatus(2, updating)
	vrf.sad.changeStatus(3, updating)
	vrf.sad.changeStatus(4, deleting)
	vrf.sad.changeStatus(5, hardExpired)
	// now, sad is ...
	// SPI  Go-SAD        Next  Curr
	// ----------------------------------
	//  1   NEWING        x     x
	//  2   UPDATING      o     x
	//  3   UPDATING      o     x
	//  4   DELETING      o     x
	//  5   HARDEXPIRED   o     x
	//  :
	suite.Len(vrf.sad, 5)

	// push
	err = mgr.PushSAD()
	suite.NoError(err)

	// now, sad is ...
	// SPI  Go-SAD        Next  Curr
	// ----------------------------------
	//  1   VALID         O.    x
	//  2   VALID         O.    x
	//  3   VALID         O.    x
	//  4   (NIL)         x*    x
	//  5   (NIL)         x*    x
	//  :
	suite.Len(vrf.sad, 3)
	suite.Equal(valid, vrf.sad[1].inStat)
	suite.Equal(valid, vrf.sad[2].inStat)
	suite.Equal(valid, vrf.sad[3].inStat)
	// TBD: check NextSAD
}

func (suite *sadMgrTestSuite) TestCheckSATimeSoft() {
	// using preset-SAD
	mgr := suite.out
	selector := suite.selector
	vrf := mgr.vrfs[selector.VRFIndex]
	firstLen := len(vrf.sad)
	now := time.Now()

	suite.NoError(mgr.CheckLifetime())
	suite.Equal(reserved, vrf.sad[1].inStat)    // not changed
	suite.Equal(newing, vrf.sad[2].inStat)      // not changed
	suite.Equal(valid, vrf.sad[3].inStat)       // not changed
	suite.Equal(updating, vrf.sad[4].inStat)    // not changed
	suite.Equal(softExpired, vrf.sad[5].inStat) // not changed
	suite.Equal(hardExpired, vrf.sad[6].inStat) // not changed
	suite.Equal(deleting, vrf.sad[7].inStat)    // not changed
	suite.Len(vrf.sad, firstLen)

	// force set LifeTimeSoft/Hard
	for k, v := range vrf.sad {
		v.LifeTimeSoft = now.Add(time.Duration(-10 * time.Minute))
		v.LifeTimeHard = now.Add(time.Duration(10 * time.Minute))
		v.LifeTimeCurrent = now
		v.LifeTimeByteSoft = 10
		v.LifeTimeByteHard = 20
		v.LifeTimeByteCurrent = 5
		vrf.sad[k] = v
	}
	suite.NoError(mgr.CheckLifetime())
	suite.Equal(reserved, vrf.sad[1].inStat)    // not changed
	suite.Equal(newing, vrf.sad[2].inStat)      // not changed
	suite.Equal(softExpired, vrf.sad[3].inStat) // changed
	suite.Equal(updating, vrf.sad[4].inStat)    // not changed
	suite.Equal(softExpired, vrf.sad[5].inStat) // not changed
	suite.Equal(hardExpired, vrf.sad[6].inStat) // not changed
	suite.Equal(deleting, vrf.sad[7].inStat)    // not changed
	suite.Len(vrf.sad, firstLen)
}

func (suite *sadMgrTestSuite) TestCheckSAByteSoft() {
	// using preset-SAD
	mgr := suite.out
	selector := suite.selector
	vrf := mgr.vrfs[selector.VRFIndex]
	firstLen := len(vrf.sad)
	now := time.Now()

	suite.NoError(mgr.CheckLifetime())
	suite.Equal(reserved, vrf.sad[1].inStat)    // not changed
	suite.Equal(newing, vrf.sad[2].inStat)      // not changed
	suite.Equal(valid, vrf.sad[3].inStat)       // not changed
	suite.Equal(updating, vrf.sad[4].inStat)    // not changed
	suite.Equal(softExpired, vrf.sad[5].inStat) // not changed
	suite.Equal(hardExpired, vrf.sad[6].inStat) // not changed
	suite.Equal(deleting, vrf.sad[7].inStat)    // not changed
	suite.Len(vrf.sad, firstLen)

	// force set LifeTimeSoft/Hard
	for k, v := range vrf.sad {
		v.LifeTimeSoft = now.Add(time.Duration(10 * time.Minute))
		v.LifeTimeHard = now.Add(time.Duration(20 * time.Minute))
		v.LifeTimeCurrent = now
		v.LifeTimeByteSoft = 10
		v.LifeTimeByteHard = 20
		v.LifeTimeByteCurrent = 15
		vrf.sad[k] = v
	}
	suite.NoError(mgr.CheckLifetime())
	suite.Equal(reserved, vrf.sad[1].inStat)    // not changed
	suite.Equal(newing, vrf.sad[2].inStat)      // not changed
	suite.Equal(softExpired, vrf.sad[3].inStat) // changed
	suite.Equal(updating, vrf.sad[4].inStat)    // not changed
	suite.Equal(softExpired, vrf.sad[5].inStat) // not changed
	suite.Equal(hardExpired, vrf.sad[6].inStat) // not changed
	suite.Equal(deleting, vrf.sad[7].inStat)    // not changed
	suite.Len(vrf.sad, firstLen)
}

func (suite *sadMgrTestSuite) TestCheckSATimeHard() {
	// using preset-SAD
	mgr := suite.out
	selector := suite.selector
	vrf := mgr.vrfs[selector.VRFIndex]
	firstLen := len(vrf.sad)
	now := time.Now()

	suite.NoError(mgr.CheckLifetime())
	suite.Equal(reserved, vrf.sad[1].inStat)    // not changed
	suite.Equal(newing, vrf.sad[2].inStat)      // not changed
	suite.Equal(valid, vrf.sad[3].inStat)       // not changed
	suite.Equal(updating, vrf.sad[4].inStat)    // not changed
	suite.Equal(softExpired, vrf.sad[5].inStat) // not changed
	suite.Equal(hardExpired, vrf.sad[6].inStat) // not changed
	suite.Equal(deleting, vrf.sad[7].inStat)    // not changed
	suite.Len(vrf.sad, firstLen)

	// force set LifeTimeSoft/Hard
	for k, v := range vrf.sad {
		v.LifeTimeSoft = now.Add(time.Duration(-20 * time.Minute))
		v.LifeTimeHard = now.Add(time.Duration(-10 * time.Minute))
		v.LifeTimeCurrent = now
		v.LifeTimeByteSoft = 10
		v.LifeTimeByteHard = 20
		v.LifeTimeByteCurrent = 5
		vrf.sad[k] = v
	}
	suite.NoError(mgr.CheckLifetime())
	suite.NotContains(vrf.sad, 1)               // deleted
	suite.NotContains(vrf.sad, 2)               // deleted
	suite.Equal(hardExpired, vrf.sad[3].inStat) // changed
	suite.Equal(hardExpired, vrf.sad[4].inStat) // changed
	suite.Equal(hardExpired, vrf.sad[5].inStat) // changed
	suite.Equal(hardExpired, vrf.sad[6].inStat) // not changed
	suite.Equal(deleting, vrf.sad[7].inStat)    // not changed
	suite.Len(vrf.sad, firstLen-2)
}

func (suite *sadMgrTestSuite) TestCheckSAByteHard() {
	// using preset-SAD
	mgr := suite.out
	selector := suite.selector
	vrf := mgr.vrfs[selector.VRFIndex]
	firstLen := len(vrf.sad)
	now := time.Now()

	suite.NoError(mgr.CheckLifetime())
	suite.Equal(reserved, vrf.sad[1].inStat)    // not changed
	suite.Equal(newing, vrf.sad[2].inStat)      // not changed
	suite.Equal(valid, vrf.sad[3].inStat)       // not changed
	suite.Equal(updating, vrf.sad[4].inStat)    // not changed
	suite.Equal(softExpired, vrf.sad[5].inStat) // not changed
	suite.Equal(hardExpired, vrf.sad[6].inStat) // not changed
	suite.Equal(deleting, vrf.sad[7].inStat)    // not changed
	suite.Len(vrf.sad, firstLen)

	// force set LifeTimeSoft/Hard
	for k, v := range vrf.sad {
		v.LifeTimeSoft = now.Add(time.Duration(10 * time.Minute))
		v.LifeTimeHard = now.Add(time.Duration(20 * time.Minute))
		v.LifeTimeCurrent = now
		v.LifeTimeByteSoft = 10
		v.LifeTimeByteHard = 20
		v.LifeTimeByteCurrent = 25
		vrf.sad[k] = v
	}
	suite.NoError(mgr.CheckLifetime())
	suite.NotContains(vrf.sad, 1)               // deleted
	suite.NotContains(vrf.sad, 2)               // deleted
	suite.Equal(hardExpired, vrf.sad[3].inStat) // changed
	suite.Equal(hardExpired, vrf.sad[4].inStat) // changed
	suite.Equal(hardExpired, vrf.sad[5].inStat) // changed
	suite.Equal(hardExpired, vrf.sad[6].inStat) // not changed
	suite.Equal(deleting, vrf.sad[7].inStat)    // not changed
	suite.Len(vrf.sad, firstLen-2)
}

func (suite *sadMgrTestSuite) TestCloneSA() {
	// check len (copied only not marked as 'deleting')
	selector := suite.selector
	outCopy := suite.out.CloneSAD(selector)
	suite.Len(suite.out.vrfs[selector.VRFIndex].sad, 7)
	suite.Len(outCopy, 6)

	// copy (empty)
	inCopy := suite.in.CloneSAD(selector)
	suite.Empty(suite.in.vrfs[selector.VRFIndex].sad)
	suite.Empty(inCopy)
}
