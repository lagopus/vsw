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

package ocdc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	pb "github.com/coreswitch/openconfigd/proto"
	"github.com/lagopus/vsw/vswitch"
	"google.golang.org/grpc"
)

var log = vswitch.Logger

// ConfigType is a type of configuration service
type ConfigType int

const (
	CT_Set    = ConfigType(pb.ConfigType_SET)
	CT_Delete = ConfigType(pb.ConfigType_DELETE)
)

func (ct ConfigType) String() string {
	if ct == CT_Set {
		return "Set"
	}
	return "Delete"
}

// ConfigMode is a configuration mode of a transaction.
type ConfigMode int

const (
	CM_Validate ConfigMode = iota
	CM_Commit
)

func (cm ConfigMode) String() string {
	if cm == CM_Validate {
		return "Validate"
	}
	return "Commit"
}

type Config struct {
	Path []string
	Type ConfigType
}

type ConfigMessage struct {
	Mode    ConfigMode
	Configs []*Config
}

type Subscriber struct {
	paths [][]string
	conn  *connect
	C     chan *ConfigMessage
	RC    chan bool
}

type connect struct {
	cliconn *grpc.ClientConn
	stream  pb.Config_DoConfigClient

	confc            chan *pb.ConfigReply
	errorc           chan error
	subscribers      map[*Subscriber]struct{}
	subscribersMutex sync.RWMutex
	subscribedPaths  map[string]struct{}
	subedPathMutex   sync.Mutex
	refcnt           int
}

const defaultServer = ":2650"

var ocdServer = defaultServer

// SetOcdServer allows to override OpenConfigd network address.
// host is server address, and can be "" for localhost.
// port is port number of OpenConfigd.
func SetOcdServer(host string, port uint16) {
	ocdServer = fmt.Sprintf("%s:%d", host, port)
}

// Subscribe subscribes to ocdclient, and creates a new Subscriber. paths are
// subscribed to OpenConfigd.
func Subscribe(paths [][]string) (*Subscriber, error) {
	if len(paths) == 0 {
		return nil, errors.New("Doesn't save paths to subscribe.")
	}

	return newSubscriber(paths)
}

// newSubscriber creates a Subscriber.
func newSubscriber(paths [][]string) (*Subscriber, error) {
	c, err := getConnection()
	if err != nil {
		return nil, err
	}

	s := &Subscriber{
		paths: paths,
		conn:  c,
		C:     make(chan *ConfigMessage, 1),
		RC:    make(chan bool),
	}
	c.registerSubscriber(s)
	c.registerSubscribedPaths(paths)

	return s, nil
}

var (
	connMutex sync.Mutex
	conn      *connect
)

// getConnection returns a connection to OpenConfigd. Connect to it, if the connection
// is not existing.
func getConnection() (*connect, error) {
	connMutex.Lock()
	defer connMutex.Unlock()

	if conn != nil {
		conn.refcnt++
		return conn, nil
	}

	log.Printf("ocdclient: Connect to \"%s\"\n", ocdServer)
	cliconn, err := grpc.Dial(ocdServer, grpc.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("Crerating a client connection failed: %v", err)
	}
	client := pb.NewConfigClient(cliconn)
	stream, err := client.DoConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("Creating a client stream failed: %v", err)
	}

	conn = &connect{
		cliconn: cliconn,
		stream:  stream,

		confc:           make(chan *pb.ConfigReply),
		errorc:          make(chan error),
		subscribers:     make(map[*Subscriber]struct{}),
		subscribedPaths: make(map[string]struct{}),
		refcnt:          1,
	}
	go conn.control()
	go conn.receive()

	return conn, nil
}

func (c *connect) registerSubscriber(s *Subscriber) {
	c.subscribersMutex.Lock()
	c.subscribers[s] = struct{}{}
	c.subscribersMutex.Unlock()
}

// registerSubscribePaths registers subscribedPaths on connect struct.
// If a path is not subscribed, subscribes to OpenConfigd befor registering.
func (c *connect) registerSubscribedPaths(paths [][]string) {
	c.subedPathMutex.Lock()
	for _, p := range paths {
		key := strings.Join(p, " ")
		if _, ok := c.subscribedPaths[key]; ok {
			continue
		}

		for {
			if err := c.send(pb.ConfigType_SUBSCRIBE, p); err == nil {
				break
			}
		}
		c.subscribedPaths[key] = struct{}{}
	}
	c.subedPathMutex.Unlock()
}

const moduleName = "ocdclient"

// send sends a configuration request to OpenConfigd.
func (c *connect) send(ct pb.ConfigType, path []string) error {
	cr := &pb.ConfigRequest{
		Type:   ct,
		Module: moduleName,
		Path:   path,
	}

	return c.stream.Send(cr)
}

// receive receives a configuration from OpenConfigd.
func (c *connect) receive() {
	for {
		conf, err := c.stream.Recv()
		if err != nil {
			c.errorc <- err
			return
		}
		c.confc <- conf
	}
}

// control controls received configuration.
func (c *connect) control() {
	var confs []*Config // configurations that is received in a transaction

	for {
		select {
		// configuration
		case recvConf := <-c.confc:
			switch recvConf.Type {
			case pb.ConfigType_VALIDATE_START, pb.ConfigType_COMMIT_START:
				confs = nil

			case pb.ConfigType_SET, pb.ConfigType_DELETE:
				c := &Config{
					Path: recvConf.Path,
					Type: ConfigType(recvConf.Type),
				}
				confs = append(confs, c)

			case pb.ConfigType_VALIDATE_END:
				ct := pb.ConfigType_VALIDATE_SUCCESS

				if ok := c.notifyConfig(confs, CM_Validate); !ok {
					ct = pb.ConfigType_VALIDATE_FAILED
				}

				for {
					if err := c.send(ct, nil); err == nil {
						break
					}
				}

			case pb.ConfigType_COMMIT_END:
				c.notifyConfig(confs, CM_Commit)

			default:
				log.Printf("ocdclient: Unexecuted message received")
				continue
			}

		// receive error
		case err := <-c.errorc:
			log.Printf("ocdclient receives error: %v", err)
			c.subscribersMutex.RLock()
			for s := range c.subscribers {
				s.notifyEOS()
			}
			c.subscribersMutex.RUnlock()
			return
		}
	}
}

// notifyConfig notifys configurations to each subscriber.
func (c *connect) notifyConfig(recvs []*Config, mode ConfigMode) bool {
	c.subscribersMutex.RLock()
	defer c.subscribersMutex.RUnlock()
	pairs := c.selectPaths(recvs)
	if len(pairs) == 0 {
		return false
	}

	for s, confs := range pairs {
		s.C <- &ConfigMessage{
			Mode:    mode,
			Configs: confs,
		}

		if rc := <-s.RC; !rc {
			return false
		}
	}

	return true
}

// selectPaths selects paths that a subscriber was subscribed from recvs,
// and returns pairs of the subscriber and the paths.
func (c *connect) selectPaths(recvs []*Config) map[*Subscriber][]*Config {
	pairs := make(map[*Subscriber][]*Config)

	for s := range c.subscribers {
		var selects []*Config

		for _, path := range s.paths {
		next:
			for _, r := range recvs {
				for i, p := range path {
					if p != r.Path[i] {
						continue next
					}
				}
				selects = append(selects, r)
			}
		}

		if len(selects) > 0 {
			pairs[s] = selects
		}
	}
	return pairs
}

// notifyEOS notifys the end of stream by closing a channel.
func (s *Subscriber) notifyEOS() {
	close(s.C)
}

// free decreases reference count of the connect, and frees connection
// when the count equals 0.
func (c *connect) free() {
	connMutex.Lock()
	defer connMutex.Unlock()
	c.refcnt--

	if c.refcnt > 0 {
		return
	}

	log.Printf("ocdclient: Close connection.\n")
	c.stream.CloseSend()
	c.cliconn.Close()

	conn = nil
}

func (c *connect) unregisterSubscriber(s *Subscriber) {
	c.subscribersMutex.Lock()
	delete(c.subscribers, s)
	c.subscribersMutex.Unlock()
}

// Unsubscribe unsubscribes to ocdclient. Don't use the subscriber
// after unsubscribing.
func (s *Subscriber) Unsubscribe() {
	s.conn.unregisterSubscriber(s)
	s.conn.free()
}
