//
// Copyright 2017 Nippon Telegraph and Telephone Corporation.
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
	"fmt"
	"time"
)

// SAD sad
type SAD map[SPI]SAValue

func (sad SAD) logString(spi SPI) string {
	sav := sad[spi]
	return fmt.Sprintf("spi=%d state=%s val=%+v", spi, sav.inStat, sav)
}

func (sad SAD) logStringChanged(spi SPI, from internalState) string {
	if sav, exists := sad[spi]; exists {
		return fmt.Sprintf("spi=%d state=%s->%s val=%+v", spi, from, sav.inStat, sav)
	}
	return fmt.Sprintf("spi=%d state=%s->X val=X", spi, from)
}

func (sad SAD) changeStatus(spi SPI, next internalState) (err error) {
	if spi != InvalidSPI {
		if sav, exists := sad[spi]; exists {
			if next == deleted {
				delete(sad, spi)
			} else {
				sav.inStat = next
				sav.State = next.saState()
				sad[spi] = sav
			}
		} else {
			err = fmt.Errorf("cannot changeStatus: SA Not exists: spi=%d", spi)
		}
	} else {
		err = fmt.Errorf("cannot changeStatus: Invalid SPI: %v", spi)
	}
	return
}

func (sad SAD) enable(spi SPI) (next internalState, err error) {
	next = sad[spi].inStat.enable()
	switch next {
	case newing, updating:
		err = sad.changeStatus(spi, next)
	default:
		err = fmt.Errorf("cannot Enable: current status is %s (spi=%d)", sad[spi].inStat, spi)
	}
	return
}

func (sad SAD) delete(spi SPI) (next internalState, err error) {
	current := sad[spi].inStat
	next = current.delete()
	if current != deleting {
		err = sad.changeStatus(spi, next)
	} else { // already marked as 'deleting'
		err = fmt.Errorf("cannot Delete: SA Not Exists: spi=%d", spi)
	}
	return
}

func (sad SAD) pushed(spi SPI) (next internalState, err error) {
	current := sad[spi].inStat
	next = current.done()
	if current != next {
		err = sad.changeStatus(spi, next)
	}
	return
}

func (sad SAD) softExpired(spi SPI) (next internalState, err error) {
	next = softExpired
	err = sad.changeStatus(spi, next)
	return
}

func (sad SAD) hardExpired(spi SPI) (next internalState, err error) {
	next = sad[spi].inStat.hardExpire()
	err = sad.changeStatus(spi, next)
	return
}

func (sad SAD) changeLifetimeCurrent(spi SPI, time time.Time, byte uint64) {
	sav := sad[spi]
	sav.LifeTimeCurrent = time
	sav.LifeTimeByteCurrent = byte
	sad[spi] = sav
}

func (sad SAD) reserve(spi SPI) (err error) {
	if spi != InvalidSPI {
		if _, exists := sad[spi]; !exists {
			sad[spi] = SAValue{inStat: reserved}
		} else {
			err = fmt.Errorf("cannot Reserve: SA Already exists: spi=%d", spi)
		}
	} else {
		err = fmt.Errorf("cannot Reserve: Invalid SPI: %d", spi)
	}
	return
}

func (sad SAD) update(spi SPI, new *SAValue) (err error) {
	if spi != InvalidSPI {
		if new != nil {
			if old, exists := sad[spi]; exists {
				if old.inStat != deleting {
					sad[spi] = *new
					sad.changeStatus(spi, old.inStat)
				} else {
					err = fmt.Errorf("cannot Update: SA Not Exists: %v", spi)
				}
			} else {
				err = fmt.Errorf("cannot Update: SA Not exists: %v", spi)
			}
		} else {
			err = fmt.Errorf("cannot Update: specified SAValue is nil")
		}
	} else {
		err = fmt.Errorf("cannot Update: Invalid SPI: %v", spi)
	}
	return
}

func (sad SAD) add(spi SPI, value *SAValue) (err error) {
	if spi != InvalidSPI {
		err = sad.reserve(spi)
		if err == nil {
			err = sad.update(spi, value)
			if err != nil {
				sad.changeStatus(spi, deleted)
			}
		}
	} else {
		err = fmt.Errorf("cannot Add: Invalid SPI: %d", spi)
	}
	return
}

func (sad SAD) collectPush() (map[SPI]SAValue, []SPI) {
	entries := map[SPI]SAValue{}
	expires := []SPI{}
	for spi, sav := range sad {
		if sav.inStat.pushable() {
			entries[spi] = sav
		}
		if sav.inStat.needDetach() {
			expires = append(expires, spi)
		}
	}
	return entries, expires
}

func (sad SAD) countChanged() (ret uint32) {
	for _, v := range sad {
		if v.inStat.changed() {
			ret++
		}
	}
	return
}

func (sad SAD) clone() SAD {
	ret := SAD{}
	if len(sad) != 0 {
		for spi, sav := range sad {
			if sav.inStat.clonable() {
				ret[spi] = sav
			}
		}
	}
	return ret
}
