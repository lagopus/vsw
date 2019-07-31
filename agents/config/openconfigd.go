//
// Copyright 2018-2019 Nippon Telegraph and Telephone Corporation.
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

package config

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"

	pb "github.com/coreswitch/openconfigd/proto"
	"google.golang.org/grpc"
)

type connect struct {
	cliconn *grpc.ClientConn
	stream  pb.Config_DoConfigClient
}

// getConnection gets a connection to OpenConfigd.
func getConnection(server string) (*connect, error) {
	log.Debug(0, "Connect to \"%s\"\n", server)
	cliconn, err := grpc.Dial(server, grpc.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("Crerating a client connection failed: %v", err)
	}
	client := pb.NewConfigClient(cliconn)
	stream, err := client.DoConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("Creating a client stream failed: %v", err)
	}

	return &connect{
		cliconn: cliconn,
		stream:  stream,
	}, nil
}

// send sends a configuration request to OpenConfigd.
func (c *connect) send(ct pb.ConfigType, path []string) {
	cr := &pb.ConfigRequest{
		Type:   ct,
		Module: configAgentStr,
		Path:   path,
	}

	for {
		if err := c.stream.Send(cr); err == nil {
			break
		}
	}
}

// free frees a connection to OpenConfigd.
// Don't use the connection after free.
func (c *connect) free() {
	c.stream.CloseSend()
	c.cliconn.Close()
}

//
// show server
//
const serverName = "showServer"

type Server struct {
	rpcServer *grpc.Server
	conn      *connect
	p         *parser
}

// TODO: Create Help from description in yang.
func getShowCommandSpecs(parserSyntax []*parserSyntax) []pb.RegisterRequest {
	var specs []pb.RegisterRequest
	spec := pb.RegisterRequest{
		Name:      "show-vsw",
		Module:    serverName,
		Mode:      "exec",
		Privilege: 1,
		Helps:     []string{},
		Code:      pb.ExecCode_REDIRECT_SHOW,
	}

	rep := regexp.MustCompile(TOKEN_INTEGER + "|" + TOKEN_STRING + "|" + TOKEN_MACADDR + "|" + TOKEN_IPV4ADDR)
	for _, ps := range parserSyntax {
		for _, s := range ps.syntax {
			line := ps.prefix
			if s.pattern != "" {
				line += " " + s.pattern
			}
			spec.Line = rep.ReplaceAllString(line, "WORD")
			specs = append(specs, spec)
		}
	}
	return specs
}

// rpcRegisterCommand registers commands to an RPC server.
func (s *Server) rpcRegisterCommand() error {
	client := pb.NewRegisterClient(s.conn.cliconn)

	specs := getShowCommandSpecs(ocdcShowSyntax)

	for _, spec := range specs {
		if _, err := client.DoRegister(context.Background(), &spec); err != nil {
			return fmt.Errorf("client DoRegister failed: %v", err)
		}
	}
	return nil
}

// registerServer registers the config agent as show server to an RPC server and OpenConfigd,
// and starts to serve.
func registerServer(port uint16, conn *connect) (*Server, error) {
	s := &Server{
		rpcServer: grpc.NewServer(),
		conn:      conn,
		p:         newOpenConfigParser(nil, ocdcShowSyntax),
	}
	req := &pb.RegisterModuleRequest{
		Module: serverName,
		Port:   fmt.Sprintf("%d", port),
	}

	// register a module to an RPC server
	client := pb.NewRegisterClient(s.conn.cliconn)
	if _, err := client.DoRegisterModule(context.Background(), req); err != nil {
		return nil, fmt.Errorf("client DoRegisterModule failed: %v", err)
	}

	// register commands to an RPC server
	if err := s.rpcRegisterCommand(); err != nil {
		return nil, err
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	// register a server and an RPC server to OpenConfigd
	pb.RegisterShowServer(s.rpcServer, s)

	go s.rpcServer.Serve(lis)

	return s, nil
}

// unregisterServer stops a server.
// Don't use the server after stopping.
func (s *Server) unregisterServer() {
	s.rpcServer.Stop()
}

func sendReply(reply *pb.ShowReply, stream pb.Show_ShowServer) {
	if err := stream.Send(reply); err != nil {
		log.Err("Couldn't send a show result to OpenConfigd.: %v", err)
	}
}

// Show is called first when show command is executed from OpenConfigd.
// If a ShowRequest is complete, it will be parsed and get the reply,
// then the reply is sent OpenConfigd.
func (s *Server) Show(req *pb.ShowRequest, stream pb.Show_ShowServer) error {
	reply := &pb.ShowReply{}

	line := strings.Fields(req.Line)
	if len(line) <= 1 {
		reply.Str = outputErr("Incomplete command: %v", req.Line)
		sendReply(reply, stream)
		return nil
	}

	if rep, err := s.p.parse(line); err != nil {
		log.Err("Error while parsing '%v': %v", req.Line, err)
		reply.Str = outputErr("%v': %v", err, req.Line)
	} else {
		reply.Str = rep.(string)
	}

	sendReply(reply, stream)
	return nil
}
