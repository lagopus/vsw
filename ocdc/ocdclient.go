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
	"fmt"
	pb "github.com/lagopus/openconfigd/proto"
	"github.com/lagopus/vsw/vswitch"
	"google.golang.org/grpc"
	"io"
	"math"
	"os"
	"reflect"
	"sync"
)

var log = vswitch.Logger

type ConfigType int

const (
	TypeSet    ConfigType = ConfigType(pb.ConfigType_SET)
	TypeDelete            = ConfigType(pb.ConfigType_DELETE)
)

var ConfigTypeStrings = map[ConfigType]string{
	TypeSet:    "Set",
	TypeDelete: "Delete",
}

func (c ConfigType) String() string {
	return ConfigTypeStrings[c]
}

type Config struct {
	Path []string
	Type ConfigType
}

// Validate is true when a Type of received message is VALIDATE.
// Config is configuration received from openconfig and module has subscribed to paths.
type ConfigMessage struct {
	Validate bool
	Configs  []*Config
}

// Each modules have a Handle that is used to subscribe, validate or commit.
type Handle struct {
	subscriberId int
	paths        [][]string
	name         string
	conn         *connect

	ConfigMessage chan *ConfigMessage
	Rc            chan bool
}

// connect is a parameter to connect openconfig.
type connect struct {
	client  pb.ConfigClient
	connect *grpc.ClientConn
	stream  pb.Config_DoConfigClient

	handles map[int]*Handle
}

const (
	DefaultServer = ":2650"
	ServerNameEnv = "OPENCONFIGD_SERVER"
)

// Connect to the server
func connectServer() (pb.ConfigClient, *grpc.ClientConn, error) {
	var err error

	server := os.Getenv(ServerNameEnv)
	if server == "" {
		server = DefaultServer
	}

	log.Printf("Connecting to the server: \"%s\"\n", server)

	cliconn, err := grpc.Dial(server, grpc.WithInsecure())
	if err != nil {
		return nil, nil, fmt.Errorf("ocdclient: Can't create a new config client.")
	}

	client := pb.NewConfigClient(cliconn)
	if client == nil {
		return nil, nil, fmt.Errorf("ocdclient: can't create a new config client.")
	}

	log.Printf("Connected: client=%v\n", client)
	return client, cliconn, nil
}

func startConnection() *connect {
	client, cliconn, err := connectServer()
	if err != nil {
		log.Fatalf("%v\n", err)
	}

	stream, err := client.DoConfig(context.Background())
	if err != nil {
		log.Fatalf("Creating a client stub faild: %v", err)
	}

	c := &connect{
		client:  client,
		connect: cliconn,
		stream:  stream,
		handles: make(map[int]*Handle),
	}

	go c.receive()
	go c.send()

	return c
}

type sendMsg struct {
	confReq *pb.ConfigRequest
	err     chan error
}

var (
	sMsg = &sendMsg{
		confReq: &pb.ConfigRequest{},
		err:     make(chan error),
	}
	sc = make(chan *sendMsg)
)

func (c *connect) send() {
	//	log.Printf("start send\n")
	for {
		sMsg := <-sc
		//		log.Printf("Send message confRep = %v\n", sMsg.confReq)
		sMsg.err <- c.stream.Send(sMsg.confReq)
	}
}

// receive receives configurations from openconfig.
func (c *connect) receive() {
	//	log.Printf("start receive\n")

	var (
		confs    []*Config // configurations received in one transaction
		validate = false
	)

	for {
		// in is receive configration
		in, err := c.stream.Recv()

		if err == io.EOF {
			log.Printf("EOF detected.\n")
		} else if err != nil {
			log.Fatalf("Receive failed: %v", err)
		}

		switch in.Type {
		case pb.ConfigType_SET, pb.ConfigType_DELETE:
			// duplicate path check
			if !checkDuplicate(in.Path, confs) {
				c := &Config{
					Path: in.Path,
					Type: ConfigType(in.Type),
				}
				//				log.Printf("%v %v\n", c.Type, c.Path)
				confs = append(confs, c)
			}

		case pb.ConfigType_VALIDATE_START:
			validate = true

		case pb.ConfigType_COMMIT_START:
			validate = false

		case pb.ConfigType_VALIDATE_END:
			if len(confs) > 0 {
				sMsg.confReq.Type = c.selectPaths(validate, confs)
				sc <- sMsg
				<-sMsg.err

				confs = make([]*Config, 0)
			}
			sMsg.confReq = &pb.ConfigRequest{}

		case pb.ConfigType_COMMIT_END:
			if len(confs) > 0 {
				c.selectPaths(validate, confs)
				confs = make([]*Config, 0)
			}

		default:
			log.Printf("Unexecuted message received")
			continue
		}
	}
}

func (c *connect) selectPaths(validate bool, confs []*Config) pb.ConfigType {
	cType := pb.ConfigType_VALIDATE_SUCCESS

	for _, h := range c.handles {
		confToSend := make([]*Config, 0)

		for _, path := range h.paths {
		nextConfRep:
			for _, conf := range confs {
				for i, p := range path {
					if p != conf.Path[i] {
						continue nextConfRep
					}
				}
				confToSend = append(confToSend, conf)
			}
		}

		if len(confToSend) > 0 {
			cmsg := &ConfigMessage{
				Validate: validate,
				Configs:  confToSend,
			}
			log.Printf("Send configuration to module\n")
			h.ConfigMessage <- cmsg

			rc := <-h.Rc
			if validate && !rc {
				cType = pb.ConfigType_VALIDATE_FAILED
				break
			}
		}
	}
	return cType
}

// checkDuplicate checks duplicate paths.
// Return true when it is same recvPath and Path in confs.
func checkDuplicate(recvPath []string, confs []*Config) bool {
	if len(confs) == 0 {
		return false
	}

	for _, c := range confs {
		if reflect.DeepEqual(c.Path, recvPath) {
			return true
		}
	}
	return false
}

var (
	subscriberId = 0

	conn       *connect
	streamOnce sync.Once
	subMutex   sync.Mutex
)

// Subscribe subscribes paths to openconfig.
// paths are paths that modules want to subscribe.
func Subscribe(name string, paths [][]string) *Handle {
	if len(paths) == 0 {
		log.Printf("module doesn't have paths for Subscribe.")
		return nil
	}

	streamOnce.Do(func() {
		conn = startConnection()
	})

	subMutex.Lock()
	defer subMutex.Unlock()
	log.Printf("subscriberId: %d\n", subscriberId)

	if subscriberId == math.MaxInt32 {
		log.Printf("Can't create subscriber anymore.\n")
		return nil
	}

	name = fmt.Sprintf("%v-%v", name, subscriberId)
	handle := &Handle{
		subscriberId: subscriberId,
		paths:        paths,
		name:         name,
		conn:         conn,

		ConfigMessage: make(chan *ConfigMessage),
		Rc:            make(chan bool),
	}
	conn.handles[subscriberId] = handle

	// set a message to send openconfig
	sMsg.confReq.Type = pb.ConfigType_SUBSCRIBE
	sMsg.confReq.Module = name

	// subscribe paths to the server
	for _, path := range paths {

		sMsg.confReq.Path = path
		sc <- sMsg
		err := <-sMsg.err

		if err != nil {
			log.Printf("Sending subscription message faild: %v", err)
			conn.stream.CloseSend()
			defer delete(conn.handles, subscriberId)
			return nil
		}
	}
	sMsg.confReq = &pb.ConfigRequest{}

	log.Printf("Subscribe success\n")
	subscriberId++
	return handle
}

func (h *Handle) Unsubscribe() {
	// close hadnle for h.subscriberId
	subMutex.Lock()
	defer subMutex.Unlock()

	if _, ok := h.conn.handles[h.subscriberId]; ok {
		log.Printf("unsubscribe: name= %v id= %v\n", h.name, h.subscriberId)
		delete(h.conn.handles, h.subscriberId)
	}

	if len(h.conn.handles) == 0 {
		log.Printf("close conn\n")
		h.conn.closeConn()
	}
	log.Printf("Unsubscribe() done\n")
}

// close disconnect to the server when ocdc does't have subscriber.
func (c *connect) closeConn() {

	if c.stream != nil {
		if err := c.stream.CloseSend(); err != nil {
			log.Fatalf("Can't close stream: %v\n", err)
		}

		if err := c.connect.Close(); err != nil {
			log.Fatalf("Can't disconnect to the server.\n")
		}
		c.client = nil
	}
}
