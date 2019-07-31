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

package pfkey

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/lagopus/vsw/agents/tunnel/ipsec/connections"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/handlers"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/pfkey"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/pfkey/receiver"
	"github.com/lagopus/vsw/modules/tunnel/log"
	"github.com/lagopus/vsw/vswitch"
)

const (
	// SockPath path to unix domain socket.
	SockPath = "/var/tmp"
	// SockFile Name of unix domain socket.
	SockFile = SockPath + "/lagopus-%v.sock"
)

// Handler PFKey handler.
// Nolock
type Handler struct {
	handlers.BaseHandler
	sock     string
	listener *net.UnixListener
	conns    *conns
	wg       *sync.WaitGroup
}

// NewHandler Create PFKey handler.
func NewHandler(vrf *vswitch.VRF) *Handler {
	return &Handler{
		BaseHandler: handlers.NewBaseHandler(vrf),
		conns:       newConns(),
		wg:          &sync.WaitGroup{},
	}
}

func (h *Handler) clean() {
	os.Remove(h.sock)
}

func (h *Handler) handlePFkeyConn(c net.Conn) error {
	defer h.wg.Done()

	conn := connections.NewConnection(c)
	h.conns.add(conn)

	defer h.conns.closeAndDelete(conn)

	vrf := h.VRF()
	msgMux := receiver.NewMsgMuxForVRF(vrf.Index())
	defer msgMux.Free()
	for h.Running() {
		_, err := pfkey.HandlePfkey(c, conn, msgMux.MsgMux)
		if err != nil {
			if err != io.EOF {
				log.Logger.Err("%v: error %v", h, err)
			}
			return err
		}
	}

	return nil
}

func (h *Handler) mainLoop() {
	defer h.wg.Done()
	// for graceful shutdown.
	defer h.conns.allClose()

	for h.Running() {
		if conn, err := h.listener.Accept(); err == nil {
			log.Logger.Info("%v: accept %v", h, conn)
			h.wg.Add(1)
			go h.handlePFkeyConn(conn)
		} else {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Logger.Err("%v: error %v", h, err)
			}
		}
	}
}

// public.

// Start Start PHKey handler.
func (h *Handler) Start() error {
	if h.Running() {
		return nil
	}

	h.sock = fmt.Sprintf(SockFile, h.Name())
	h.clean()

	log.Logger.Info("%v: Start pfkey handler: %v", h, h.sock)

	var err error
	if h.listener, err = net.ListenUnix("unixpacket",
		&net.UnixAddr{Name: h.sock, Net: "unixpacket"}); err != nil {
		log.Logger.Err("%v: Can't create listener", h)
		return err
	}

	h.SetRunning()

	h.wg.Add(1)
	go h.mainLoop()

	return nil
}

// Stop Stop PHKey handler.
func (h *Handler) Stop() {
	if !h.Running() {
		return
	}

	defer h.clean()

	log.Logger.Info("%v: Stop pfkey handler", h)

	h.UnsetRunning()

	// for graceful shutdown.
	h.listener.Close()
	h.wg.Wait()
}
