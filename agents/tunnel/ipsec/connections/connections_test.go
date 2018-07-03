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

package connections

import (
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ConnectionsTestSuit struct {
	suite.Suite
}

func Test_ConnectionsTestSuite(t *testing.T) {
	suite.Run(t, new(ConnectionsTestSuit))
}

const sock = "./test.sock."

var (
	sockName = sock + strconv.Itoa(os.Getpid())
	sockType = "unixpacket"
	//sockType = "unix"
)

func (s *ConnectionsTestSuit) SetupTest() {
}

func (s *ConnectionsTestSuit) TearDownTest() {
}

func (s *ConnectionsTestSuit) TestNewConnection() {
	os.Remove(sockName)
	listener, err := net.ListenUnix(sockType, &net.UnixAddr{sockName, sockType})
	s.Assert().NoError(err)
	defer func() {
		listener.Close()
		os.Remove(sockName)
	}()
	tc, err := net.DialUnix(sockType, nil, &net.UnixAddr{sockName, sockType})
	s.Assert().NoError(err)
	defer tc.Close()
	conn, err := listener.Accept()
	defer conn.Close()
	s.Assert().NoError(err)
	nc := NewConnection(tc)
	s.Assert().NotEqual(nil, nc)
	nc.Close()
}

func (s *ConnectionsTestSuit) TestWriteAll() {
	os.Remove(sockName)
	listener, err := net.ListenUnix(sockType, &net.UnixAddr{sockName, sockType})
	s.Assert().NoError(err)
	defer func() {
		listener.Close()
		os.Remove(sockName)
	}()
	tc, err := net.DialUnix(sockType, nil, &net.UnixAddr{sockName, sockType})
	s.Assert().NoError(err)
	defer tc.Close()
	conn, err := listener.Accept()
	defer conn.Close()
	s.Assert().NoError(err)
	nc := NewConnection(tc)
	defer nc.Close()
	s.Assert().NotEqual(nil, nc)
	var c Connections
	b := []byte{0, 1, 2, 3, 4, 5}
	l, err := c.Write(b)
	s.Assert().NoError(err)
	s.Assert().Equal(len(b), l)
	rb := make([]byte, len(b))
	l, err = io.ReadFull(conn, rb)
	s.Assert().NoError(err)
	s.Assert().Equal(len(rb), l)
}

func (s *ConnectionsTestSuit) TestWriteAllMulti() {
	os.Remove(sockName)
	listener, err := net.ListenUnix(sockType, &net.UnixAddr{sockName, sockType})
	s.Assert().NoError(err)
	defer func() {
		listener.Close()
		os.Remove(sockName)
	}()
	tc, err := net.DialUnix(sockType, nil, &net.UnixAddr{sockName, sockType})
	s.Assert().NoError(err)
	defer tc.Close()
	conn, err := listener.Accept()
	defer conn.Close()
	s.Assert().NoError(err)
	nc := NewConnection(tc)
	s.Assert().NotEqual(nil, nc)
	defer nc.Close()

	var wg sync.WaitGroup
	nLoop := 100
	b := []byte{0, 1, 2, 3, 4, 5}
	for i := 0; i < nLoop; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := nc.Write(b)
			s.Assert().NoError(err)
			s.Assert().Equal(len(b), l)
		}()
	}
	for i := 0; i < nLoop; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var c Connections
			l, err := c.Write(b)
			s.Assert().NoError(err)
			s.Assert().Equal(len(b), l)
		}()
	}
	rb := make([]byte, 100)
	for i := 0; i < nLoop*2; i++ {
		l, err := io.ReadAtLeast(conn, rb, len(b))
		s.Assert().NoError(err)
		s.Assert().Equal(len(b), l)
	}
	wg.Wait()
}
