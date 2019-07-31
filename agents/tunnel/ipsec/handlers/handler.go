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

package handlers

import (
	"github.com/lagopus/vsw/vswitch"
)

// Handler Handler.
type Handler interface {
	Start() error
	Stop()
}

// BaseHandler Base of handler.
type BaseHandler struct {
	name    string
	vrf     *vswitch.VRF
	running bool
}

// NewBaseHandler Create base of handler.
func NewBaseHandler(vrf *vswitch.VRF) BaseHandler {
	return BaseHandler{
		name: vrf.Name(),
		vrf:  vrf,
	}
}

// VRF Get VRF.
func (h *BaseHandler) VRF() *vswitch.VRF {
	return h.vrf
}

// Running Is running handler.
func (h *BaseHandler) Running() bool {
	return h.running
}

// SetRunning Set running.
func (h *BaseHandler) SetRunning() {
	h.running = true
}

// UnsetRunning Unset running.
func (h *BaseHandler) UnsetRunning() {
	h.running = false
}

// Name Get name.
func (h *BaseHandler) Name() string {
	return h.name
}

// String Return Name.
func (h *BaseHandler) String() string {
	return h.name
}
