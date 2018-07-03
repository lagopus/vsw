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

// SPI SPI.
type SPI uint32

// InvalidSPI is invalid SPI
const InvalidSPI SPI = 0

// SAState SADB_SASTATE_*
type SAState uint8

// SADB_SASTATE_*
const (
	Larval SAState = iota
	Mature
	Dying
	Dead
)

type internalState uint8

const (
	deleted     internalState = iota // deleted in C & Go plane. use for argument only
	reserved                         // SPI reserved. do not push to C plane.
	newing                           // wait for first push to C plane.
	valid                            // pushed C plane. lifetime not expired
	updating                         // pushed C plane. updated by PFKEY. need to more push
	softExpired                      // pushed C plane. soft lifetime expired.
	hardExpired                      // hard lifetime expired. need to delete from C plane.
	deleting                         // deleted by PFKEY. need to delete from C plane.
)

func (s internalState) String() string {
	switch s {
	case reserved:
		return "Reserved"
	case newing:
		return "Newing"
	case valid:
		return "Valid"
	case updating:
		return "Updating"
	case softExpired:
		return "SoftExpired"
	case hardExpired:
		return "HardExpired"
	case deleting:
		return "Deleting"
	case deleted:
		return "X"
	}
	return "Unknown"
}

func (s internalState) saState() SAState {
	switch s {
	case reserved, newing:
		return Larval
	case valid, updating:
		return Mature
	case softExpired:
		return Dying
	case hardExpired, deleting:
		return Dead
	}
	return Dead
}

func (s internalState) findable() bool {
	switch s {
	case reserved, newing, valid, updating, softExpired:
		return true
	case hardExpired, deleting:
		return false
	}
	return false
}

func (s internalState) clonable() bool {
	switch s {
	case reserved, newing, valid, updating, softExpired, hardExpired:
		return true
	case deleting:
		return false
	}
	return false
}

func (s internalState) pushable() bool {
	switch s {
	case newing, valid, updating, softExpired:
		return true
	case reserved, hardExpired, deleting:
		return false
	}
	return false
}

func (s internalState) needDetach() bool {
	switch s {
	case updating, hardExpired, deleting:
		return true
	case reserved, newing, valid, softExpired:
		return false
	}
	return false
}

func (s internalState) changed() bool {
	switch s {
	case newing, updating, hardExpired, deleting:
		return true
	case valid, softExpired, reserved:
		return false
	}
	return false
}

func (s internalState) pullable() bool {
	switch s {
	case valid, updating, softExpired:
		return true
	case newing, reserved, hardExpired, deleting:
		return false
	}
	return false
}

func (s internalState) notPushed() bool {
	switch s {
	case reserved, newing:
		return true
	case valid, updating, softExpired, hardExpired, deleting:
		return false
	}
	return false
}

func (s internalState) done() (next internalState) {
	switch s {
	case newing, updating:
		return valid
	case hardExpired, deleting:
		return deleted
	case reserved, valid, softExpired:
		return s
	}
	return s
}

func (s internalState) delete() (next internalState) {
	if s.notPushed() {
		return deleted
	}
	return deleting
}

func (s internalState) hardExpire() (next internalState) {
	if s.notPushed() {
		return deleted
	}
	return hardExpired
}

func (s internalState) enable() (next internalState) {
	switch s {
	case reserved, newing:
		return newing
	case valid, updating, softExpired:
		return updating
	case hardExpired, deleting:
		return s
	}
	return s
}
