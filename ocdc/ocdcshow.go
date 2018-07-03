//
// Copyright 2018 Nippon Telegraph and Telephone Corporation.
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
	"encoding/json"
	"errors"
	"fmt"
	rpc "github.com/coreswitch/openconfigd/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"net"
)

const serverName = "ocdcServer"

type Server struct {
	rpcServer *grpc.Server
	conn      *connect
	C         chan string
	RC        chan string
}

// RegisterServer registers an ocdclient server to an RPC server and OpenConfigd,
// and starts to serve.
func RegisterServer(cmdSpec string, port uint16) (*Server, error) {
	if cmdSpec == "" {
		return nil, errors.New("comand specifications are empty string")
	}
	conn, err := getConnection()
	if err != nil {
		return nil, err
	}

	s := &Server{
		rpcServer: grpc.NewServer(),
		conn:      conn,
		C:         make(chan string, 1),
		RC:        make(chan string),
	}

	req := &rpc.RegisterModuleRequest{
		Module: serverName,
		Port:   fmt.Sprintf("%d", port),
	}
	// register a module to an RPC server
	client := rpc.NewRegisterClient(s.conn.cliconn)
	if _, err := client.DoRegisterModule(context.Background(), req); err != nil {
		return nil, fmt.Errorf("client DoRegisterModule failed: %v", err)
	}
	// register commands to an RPC server
	s.rpcRegisterCommand(cmdSpec)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	// register a server and an RPC server to OpenConfigd
	rpc.RegisterShowServer(s.rpcServer, s)

	go s.rpcServer.Serve(lis)

	return s, nil
}

// rpcRegisterCommand registers commands to an RPC server.
func (s *Server) rpcRegisterCommand(cmdSpec string) error {
	client := rpc.NewRegisterClient(s.conn.cliconn)

	var showCommands []rpc.RegisterRequest
	json.Unmarshal([]byte(cmdSpec), &showCommands)

	for _, cmd := range showCommands {

		cmd.Module = serverName
		cmd.Privilege = 1
		cmd.Code = rpc.ExecCode_REDIRECT_SHOW

		if _, err := client.DoRegister(context.Background(), &cmd); err != nil {
			return fmt.Errorf("client DoRegister failed: %v", err)
		}

	}
	return nil
}

// Show is called first when OpenConfigd do show command. Show sends the request
// to the show handler, and returns the result to OpenConfigd.
func (s *Server) Show(req *rpc.ShowRequest, stream rpc.Show_ShowServer) error {
	reply := &rpc.ShowReply{}
	s.C <- req.Line
	reply.Str = <-s.RC

	if err := stream.Send(reply); err != nil {
		return fmt.Errorf("Couldn't send a show result to OpenConfigd.: %v", err)
	}

	return nil
}

// UnregisterServer stops a server. Don't use the server after stopping.
func (s *Server) UnregisterServer() {
	s.rpcServer.Stop()
	s.conn.free()
}
