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

package ipsec

import (
	"log"
	"net"
	"sync"

	"github.com/lagopus/vsw/agents/tunnel/ipsec/config"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/handlers"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/handlers/openconfigd"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/handlers/pfkey"
	_ "github.com/lagopus/vsw/agents/tunnel/ipsec/ifaces"
	"github.com/lagopus/vsw/utils/notifier"
	"github.com/lagopus/vsw/vswitch"
)

const (
	// AgentName Name of IPsec agent.
	AgentName = "ipsec"
)

var (
	// IPsecConf Config file for ipsec.
	IPsecConf = "./ipsec.conf"
)

func init() {
	// Parse config.
	rp := config.GetRootParser()
	err := rp.ParseConfigFile(IPsecConf)
	if err != nil {
		// ignore error.
		log.Print(err)
	}

	// Register agent.
	a := &agent{
		name:     AgentName,
		handlers: map[*vswitch.VRF][]handlers.Handler{},
		wg:       &sync.WaitGroup{},
	}
	vswitch.RegisterAgent(a)
}

type agent struct {
	name     string
	listener *net.UnixListener
	vswch    chan notifier.Notification
	lock     sync.Mutex
	handlers map[*vswitch.VRF][]handlers.Handler
	wg       *sync.WaitGroup
}

func (a *agent) addVRF(vrf *vswitch.VRF) error {
	if _, ok := a.handlers[vrf]; ok {
		// ignore: already exists.
		return nil
	}
	handlers := []handlers.Handler{
		// NOTE: Add a new handler here.
		pfkey.NewHandler(vrf),
		openconfigd.NewHandler(vrf),
	}
	a.handlers[vrf] = handlers

	for _, handler := range handlers {
		if err := handler.Start(); err != nil {
			return err
		}
	}

	return nil
}

func (a *agent) deleteVRF(vrf *vswitch.VRF) {
	if handlers, ok := a.handlers[vrf]; ok {
		for _, handler := range handlers {
			handler.Stop()
		}
		delete(a.handlers, vrf)
	}
	// ignore: not found.
}

func (a *agent) allDeleteVRFs() {
	for vrf := range a.handlers {
		a.deleteVRF(vrf)
	}
}

func (a *agent) handleNotify(entry notifier.Notification) error {
	switch target := entry.Target.(type) {
	case *vswitch.VRF:
		switch entry.Value.(type) {
		case nil: // add/del VRF.
			switch entry.Type {
			case notifier.Add:
				if err := a.addVRF(target); err != nil {
					log.Printf("%v: Cat't add VRF(%v).", a, entry)
					return err
				}
			case notifier.Delete:
				a.deleteVRF(target)
			}
		}
	}
	return nil
}

func (a *agent) listen() {
	// clean up.
	defer a.wg.Done()
	defer a.allDeleteVRFs()

	for {
		select {
		case entry, ok := <-a.vswch:
			if !ok {
				return
			}
			if err := a.handleNotify(entry); err != nil {
				return
			}
		}
	}
}

// Enable Enable for ipsec agent.
func (a *agent) Enable() error {
	a.lock.Lock()
	defer a.lock.Unlock()

	log.Printf("Enable agent %v.", a)

	a.vswch = vswitch.GetNotifier().Listen()
	a.wg.Add(1)
	go a.listen()

	return nil
}

// Disable Disable for ipsec agent.
func (a *agent) Disable() {
	a.lock.Lock()
	defer a.lock.Unlock()

	log.Printf("Disable agent %v.", a)
	vswitch.GetNotifier().Close(a.vswch)
	a.wg.Wait()
}

func (a *agent) String() string {
	return a.name
}
