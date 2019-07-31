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

package openconfigd

import (
	"github.com/lagopus/vsw/agents/tunnel/ipsec/handlers"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/openconfigd/sad"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/openconfigd/spd"
	"github.com/lagopus/vsw/modules/tunnel/log"
	"github.com/lagopus/vsw/vswitch"
)

// Handler openconfigd handler.
type Handler struct {
	handlers.BaseHandler
}

// NewHandler Create openconfigd handler.
func NewHandler(vrf *vswitch.VRF) *Handler {
	return &Handler{
		BaseHandler: handlers.NewBaseHandler(vrf),
	}
}

// public

// SADEntryAdded Add SA.
func (h *Handler) SADEntryAdded(vrf *vswitch.VRF, sa vswitch.SA) {
	sad.AddSA(vrf, &sa)
}

// SADEntryUpdated Update SA.
func (h *Handler) SADEntryUpdated(vrf *vswitch.VRF, sa vswitch.SA) {
	sad.UpdateSA(vrf, &sa)
}

// SADEntryDeleted Delete SA.
func (h *Handler) SADEntryDeleted(vrf *vswitch.VRF, sa vswitch.SA) {
	sad.DeleteSA(vrf, &sa)
}

// SPDEntryAdded Add SP.
func (h *Handler) SPDEntryAdded(vrf *vswitch.VRF, sp vswitch.SP) {
	spd.AddSP(vrf, &sp)
}

// SPDEntryUpdated Update SP.
func (h *Handler) SPDEntryUpdated(vrf *vswitch.VRF, sp vswitch.SP) {
	spd.UpdateSP(vrf, &sp)
}

// SPDEntryDeleted Delete SP.
func (h *Handler) SPDEntryDeleted(vrf *vswitch.VRF, sp vswitch.SP) {
	spd.DeleteSP(vrf, &sp)
}

// Start Start openconfigd handler.
func (h *Handler) Start() error {
	if h.Running() {
		return nil
	}

	log.Logger.Info("%v: Start openconfigd handler", h)

	vrf := h.VRF()
	sadbs := vrf.SADatabases()
	sadbs.RegisterObserver(h)

	h.SetRunning()

	return nil
}

// Stop Stop openconfigd handler.
func (h *Handler) Stop() {
	if !h.Running() {
		return
	}

	log.Logger.Info("%v: Stop openconfigd handler", h)

	h.UnsetRunning()
}
