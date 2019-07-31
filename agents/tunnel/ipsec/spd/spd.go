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

package spd

import (
	"fmt"

	"github.com/lagopus/vsw/modules/tunnel/ipsec"
	"github.com/lagopus/vsw/modules/tunnel/log"
	"github.com/lagopus/vsw/vswitch"
)

// SPD.

type db map[string]*SPValue

// NOTE: no lock, need to lock it.
type spd struct {
	vrfIndex vswitch.VRFIndex
	dbs      map[ipsec.DirectionType]db
	cspd     ipsec.SPD
}

func newSPD(vrfIndex vswitch.VRFIndex) *spd {
	s := &spd{
		vrfIndex: vrfIndex,
		dbs: map[ipsec.DirectionType]db{
			ipsec.DirectionTypeOut: {},
			ipsec.DirectionTypeIn:  {},
			ipsec.DirectionTypeFwd: {},
		},
	}
	return s
}

func newSPD4(vrfIndex vswitch.VRFIndex) *spd {
	s := newSPD(vrfIndex)
	s.cspd = ipsec.NewCSPD4()
	return s
}

func newSPD6(vrfIndex vswitch.VRFIndex) *spd {
	s := newSPD(vrfIndex)
	s.cspd = ipsec.NewCSPD6()
	return s
}

func (s *spd) string() string {
	return s.cspd.String()
}

func (s *spd) freeRules(r ipsec.CACLRules) {
	s.cspd.FreeRules(r)
}

func (s *spd) newRules(db db) (ipsec.CACLRules, uint32, error) {
	size := uint32(len(db))
	if rules := s.cspd.AllocRules(size); rules != nil {
		var index uint32
		for _, value := range db {
			if value.State != Completed || value.SPI == 0 {
				continue
			}

			args := &ipsec.CACLParamsArgs{
				CSPSelector: value.CSPSelector,
				CSPValue:    value.CSPValue,
			}
			params := s.cspd.NewParams(args)

			if err := s.cspd.SetRule(index, rules, params); err != nil {
				log.Logger.Err("%v", err)
				return nil, 0, err
			}
			index++
		}

		return rules, index, nil
	}
	return nil, 0, fmt.Errorf("No memory")
}

func (s *spd) dumpRulesSPD(rules ipsec.CACLRules,
	size uint32) {
	s.cspd.DumpRules(rules, size)
}

func (s *spd) makeSPD() error {
	var rulesIn, rulesOut ipsec.CACLRules
	var sizeIn, sizeOut uint32
	var err error

	if rulesIn, sizeIn, err = s.newRules(s.dbs[ipsec.DirectionTypeIn]); err != nil {
		log.Logger.Err("%v", err)
		return err
	}
	defer s.freeRules(rulesIn)

	if rulesOut, sizeOut, err = s.newRules(s.dbs[ipsec.DirectionTypeOut]); err != nil {
		log.Logger.Err("%v", err)
		return err
	}
	defer s.freeRules(rulesOut)

	directions := []ipsec.DirectionType{ipsec.DirectionTypeIn, ipsec.DirectionTypeOut}
	for _, direction := range directions {
		if cspd, err := s.cspd.ModuleCSPD(s.vrfIndex, direction); err == nil {
			if err := s.cspd.Make(cspd, rulesIn, sizeIn,
				rulesOut, sizeOut); err != nil {
				log.Logger.Err("%v", err)
				return err
			}
		} else {
			log.Logger.Err("%v", err)
			return err
		}
	}

	return nil
}

func (s *spd) statsSPD() error {
	for direction, db := range s.dbs {
		if direction == ipsec.DirectionTypeIn || direction == ipsec.DirectionTypeOut {
			cspd, err := s.cspd.ModuleCSPD(s.vrfIndex, direction)
			if err == nil {
				for _, value := range db {
					if stats, err := s.cspd.Stats(cspd, value.SPI); err == nil {
						value.setSPStats(newSPStats(stats))
					} else {
						log.Logger.Err("%v", err)
						return err
					}
				}
			} else {
				log.Logger.Err("%v", err)
				return err
			}
		} else {
			continue
		}
	}

	return nil
}

func (s *spd) iterate(fn func(string, *SPValue) error) error {
	for _, db := range s.dbs {
		for key, value := range db {
			if err := fn(key, value); err != nil {
				log.Logger.Err("%v", err)
				return err
			}
		}
	}
	return nil
}

func (s *spd) addSP(direction ipsec.DirectionType,
	key string,
	value *SPValue) {
	s.dbs[direction][key] = value
}

func (s *spd) deleteSP(direction ipsec.DirectionType,
	key string) {
	delete(s.dbs[direction], key)
}

func (s *spd) findSP(direction ipsec.DirectionType,
	key string) (*SPValue, bool) {
	v, ok := s.dbs[direction][key]
	return v, ok
}

func (s *spd) isEmpty() bool {
	return len(s.dbs[ipsec.DirectionTypeOut]) == 0 &&
		len(s.dbs[ipsec.DirectionTypeIn]) == 0
}

func (s *spd) clearSPD() {
	for _, db := range s.dbs {
		for key := range db {
			delete(db, key)
		}
	}
}
