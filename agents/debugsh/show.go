//
// Copyright 2019 Nippon Telegraph and Telephone Corporation.
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
package debugsh

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/vswitch"
	"github.com/reiver/go-telnet"
	"github.com/reiver/go-telnet/telsh"
)

func outputResult(out io.Writer, data interface{}) {
	outputJSON(out, &msg{Status: Success, Data: data})
}

func outputErr(out io.Writer, f string, args ...interface{}) {
	outputJSON(out, &msg{Status: Error, Message: fmt.Sprintf(f, args...)})
}

func outputJSON(out io.Writer, msg *msg) {
	b, err := json.MarshalIndent(msg, "", "\t")
	if err != nil {
		logger.Err("json.MarshalIndent failed: %v", err)
		b = internalErrMsg
	}
	b = append(b, '\r', '\n')
	if n, err := out.Write(b); err != nil {
		logger.Err("Write failed after writing %d/%d: %v", n, len(b), err)
	}
}

//
// show for modules
//
func showModules(out io.Writer, args ...string) {
	type instance struct {
		Name string   `json:"name"`
		Subs []string `json:"subinstances,omitempty"`
	}

	type status struct {
		Name      string             `json:"name"`
		Type      vswitch.ModuleType `json:"type"`
		Instances []instance         `json:"instances,omitempty"`
	}

	var output []status

	for _, m := range vswitch.Modules() {
		s := status{
			Name: m.Name(),
			Type: m.Type(),
		}

		for _, name := range m.Instances() {
			is := instance{
				Name: name,
				Subs: m.Subinstances(name),
			}
			s.Instances = append(s.Instances, is)
		}

		output = append(output, s)
	}

	outputResult(out, output)
}

//
// show for agent
//
func showAgent(out io.Writer, args ...string) {
	type status struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}

	var output []status

	ea := make(map[string]struct{})
	for _, agent := range vswitch.EnabledAgents() {
		ea[agent.String()] = struct{}{}
	}

	agents := vswitch.RegisteredAgents()
	for _, agent := range agents {
		_, enabled := ea[agent.String()]
		output = append(output, status{agent.String(), enabled})
	}

	outputResult(out, output)
}

//
// show for VRF
//
func showVRF(out io.Writer, args ...string) {
	type status struct {
		Name    string         `json:"name"`
		RD      uint64         `json:"router-distinguisher"`
		Enabled bool           `json:"enabled"`
		VIF     []*vswitch.VIF `json:"vif,omitempty"`
		SAD     []vswitch.SA   `json:"sad,omitempty"`
		SPD     []vswitch.SP   `json:"spd,omitempty"`
	}

	var output []*status

	// if no args, list all VRF
	var vrfs []*vswitch.VRF
	if len(args) == 0 {
		vrfs = vswitch.GetAllVRF()
	} else {
		vrf := vswitch.GetVRFByName(args[0])
		if vrf == nil {
			outputErr(out, "VRF %v not found.", args[0])
			return
		}
		vrfs = append(vrfs, vrf)
	}

	for _, v := range vrfs {
		s := &status{
			Name:    v.Name(),
			RD:      v.RD(),
			Enabled: v.IsEnabled(),
			VIF:     v.VIF(),
		}

		if v.HasSADatabases() {
			s.SAD = v.SADatabases().SAD()
			s.SPD = v.SADatabases().SPD()
		}

		output = append(output, s)
	}

	outputResult(out, output)
}

//
// show for VRF Routing Table
//
func showRoutingTable(out io.Writer, args ...string) {
	type status struct {
		Name  string          `json:"name"`
		Table []vswitch.Route `json:"routing-table"`
	}

	if len(args) == 0 {
		outputErr(out, "VRF shall be specified.")
		return
	}

	v := vswitch.GetVRFByName(args[0])
	if v == nil {
		outputErr(out, "VRF %v not found.", args[0])
		return
	}

	outputResult(out, &status{
		Name:  args[0],
		Table: v.ListEntries(),
	})
}

//
// show for VSI
//
func showVSI(out io.Writer, args ...string) {
	type status struct {
		Name    string               `json:"name"`
		Enabled bool                 `json:"enabled"`
		VID     map[vswitch.VID]bool `json:"vlans"`
		VIF     []*vswitch.VIF       `json:"vif,omitempty"`
	}

	var output []*status

	// if no args, list all VSI
	var vsis []*vswitch.VSI
	if len(args) == 0 {
		vsis = vswitch.VSIs()
	} else {
		vsi := vswitch.GetVSI(args[0])
		if vsi == nil {
			outputErr(out, "VSI %v not found.", args[0])
			return
		}
		vsis = append(vsis, vsi)
	}

	for _, v := range vsis {
		s := &status{
			Name:    v.String(),
			Enabled: v.IsEnabled(),
			VIF:     v.VIF(),
			VID:     v.VID(),
		}

		output = append(output, s)
	}

	outputResult(out, output)
}

//
// show for FDB
//
func showFDB(out io.Writer, args ...string) {
	type macEntry struct {
		VID        vswitch.VID       `json:"vlan"`
		MACAddress macAddress        `json:"mac-address"`
		Age        uint64            `json:"age"`
		VIF        *vswitch.VIF      `json:"vif"`
		EntryType  vswitch.EntryType `json:"entry-type"`
	}

	type status struct {
		Name         string     `json:"name"`
		MACLearning  bool       `json:"mac-learning"`
		MACAgingTime int        `json:"mac-aging-time"`
		MaxEntries   int        `json:"max-entries"`
		FDB          []macEntry `json:"mac-table"`
	}

	if len(args) == 0 {
		outputErr(out, "VSI shall be specified.")
		return
	}

	v := vswitch.GetVSI(args[0])
	if v == nil {
		outputErr(out, "VSI %v not found.", args[0])
		return
	}

	mt := v.MACTable()
	table := make([]macEntry, 0, len(mt))
	for _, e := range mt {
		table = append(table, macEntry{
			VID:        e.VID,
			MACAddress: macAddress(e.MACAddress),
			Age:        e.Age,
			VIF:        e.VIF,
			EntryType:  e.EntryType,
		})
	}

	outputResult(out, &status{
		Name:         args[0],
		MACLearning:  v.MACLearning(),
		MACAgingTime: v.MACAgingTime(),
		MaxEntries:   v.MaximumEntries(),
		FDB:          table,
	})
}

type linkStatuser interface {
	LinkStatus() (bool, error)
}

func decodeLinkStatus(s linkStatuser) string {
	ls, err := s.LinkStatus()

	if err != nil {
		return "unknown"
	}

	if ls {
		return "up"
	}
	return "down"
}

//
// show for Interface
//
func showIF(out io.Writer, args ...string) {
	type status struct {
		Name       string           `json:"name"`
		Driver     string           `json:"driver"`
		Device     interface{}      `json:"device,omitempty"`
		Enabled    bool             `json:"enabled"`
		MACAddress macAddress       `json:"mac-address"`
		MTU        vswitch.MTU      `json:"mtu"`
		Mode       vswitch.VLANMode `json:"mode"`
		VID        []vswitch.VID
		VIF        []*vswitch.VIF
		Tunnel     *vswitch.L2Tunnel `json:"tunnel,omitempty"`
		Counter    *vswitch.Counter  `json:"counters"`
		Status     string            `json:"oper-status"`
		LastChange time.Time         `json:"last-change"`
	}
	var output []*status

	// if no args, list all interfaces
	var ifs []*vswitch.Interface
	if len(args) == 0 {
		ifs = vswitch.Interfaces()
	} else {
		i := vswitch.GetInterface(args[0])
		if i == nil {
			outputErr(out, "Interface %v not found.", args[0])
			return
		}
		ifs = append(ifs, i)
	}

	for _, i := range ifs {
		s := &status{
			Name:       i.String(),
			Driver:     i.Driver(),
			Enabled:    i.IsEnabled(),
			MACAddress: macAddress(i.MACAddress()),
			MTU:        i.MTU(),
			Mode:       i.InterfaceMode(),
			VID:        i.VID(),
			VIF:        i.VIF(),
			Tunnel:     i.Tunnel(),
			Counter:    i.Counter(),
			Status:     decodeLinkStatus(i),
			LastChange: i.LastChange(),
		}

		if device, ok := i.Private().(string); ok {
			s.Device = device
		}

		output = append(output, s)
	}

	outputResult(out, output)
}

//
// show for VIF
//
func showVIF(out io.Writer, args ...string) {
	type status struct {
		Name       string            `json:"name"`
		Index      vswitch.VIFIndex  `json:"index"`
		Enabled    bool              `json:"enabled"`
		VID        vswitch.VID       `json:"vid"`
		IPAddrs    []vswitch.IPAddr  `json:"ip-address,omitempty"`
		Tunnel     *vswitch.L3Tunnel `json:"tunnel,omitempty"`
		Counter    *vswitch.Counter  `json:"counters"`
		Status     string            `json:"oper-status"`
		NAPT       *vswitch.NAPT     `json:"napt,omitempty"`
		LastChange time.Time         `json:"last-change"`
	}
	var output []*status

	// if no args, list all interfaces
	var vifs []*vswitch.VIF
	if len(args) == 0 {
		vifs = vswitch.VIFs()
	} else {
		vif := vswitch.GetVIFByName(args[0])
		if vif == nil {
			outputErr(out, "VIF %v not found.", args[0])
			return
		}
		vifs = append(vifs, vif)
	}

	for _, v := range vifs {
		s := &status{
			Name:       v.String(),
			Index:      v.Index(),
			Enabled:    v.IsEnabled(),
			VID:        v.VID(),
			IPAddrs:    v.ListIPAddrs(),
			Tunnel:     v.Tunnel(),
			Counter:    v.Counter(),
			Status:     decodeLinkStatus(v),
			NAPT:       v.NAPT(),
			LastChange: v.LastChange(),
		}
		output = append(output, s)
	}

	outputResult(out, output)
}

type macAddress net.HardwareAddr

func (a macAddress) MarshalJSON() ([]byte, error) {
	return []byte(`"` + net.HardwareAddr(a).String() + `"`), nil
}

//
// show DPDK Ring Status
//
func showRingStatus(out io.Writer, args ...string) {
	if stat, err := dpdk.RingListDump(); err == nil {
		io.WriteString(out, stat)
	} else {
		outputErr(out, "RingListDump failed: %v", err)
	}
}

//
// show DPDK Mempool Status
//
func showMempoolStatus(out io.Writer, args ...string) {
	if stat, err := dpdk.MempoolListDump(); err == nil {
		io.WriteString(out, stat)
	} else {
		outputErr(out, "MempoolListDump failed: %v", err)
	}
}

//
// show command
//
type showFunc func(out io.Writer, args ...string)

var showCmds = map[string]showFunc{
	"agent":     showAgent,
	"module":    showModules,
	"vrf":       showVRF,
	"vsi":       showVSI,
	"fdb":       showFDB,
	"interface": showIF,
	"vif":       showVIF,
	"route":     showRoutingTable,
	"ring":      showRingStatus,
	"mempool":   showMempoolStatus,
}

var validTypes string

func showHandler(stdin io.ReadCloser, stdout io.WriteCloser, stderr io.WriteCloser, args ...string) error {
	logger.Info("show: %v", args)

	if len(args) == 0 {
		outputErr(stdout, "valid types are: %v", validTypes)
		return nil
	}

	if showFn, ok := showCmds[args[0]]; ok {
		showFn(stdout, args[1:]...)
	} else {
		outputErr(stdout, "unknown type: %s", args[0])
	}

	return nil
}

func showProducer(ctx telnet.Context, name string, args ...string) telsh.Handler {
	return telsh.PromoteHandlerFunc(showHandler, args...)
}

func init() {
	var types []string
	for t := range showCmds {
		types = append(types, t)
	}
	validTypes = strings.Join(types, ", ")
}
