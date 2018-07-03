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
	"net"
	"sync"
)

type connections map[*Connection]bool

var (
	conns = make(connections)
	mu    sync.Mutex
)

// Connection represents exclusive accessed net.Conn.
type Connection struct {
	sync.Mutex
	net.Conn
}

// NewConnection sets Connection to map and returns it.
func NewConnection(c net.Conn) *Connection {
	conn := Connection{Conn: c}
	mu.Lock()
	conns[&conn] = true
	mu.Unlock()
	return &conn
}

// Write is locked writing for net.Conn.
func (c *Connection) Write(p []byte) (int, error) {
	c.Lock()
	wlen, err := c.Conn.Write(p)
	c.Unlock()
	return wlen, err
}

// Close is locked closing and deleting Connection from map.
func (c *Connection) Close() {
	mu.Lock()
	conns[c] = false
	c.Lock()
	c.Conn.Close()
	c.Unlock()
	delete(conns, c)
	mu.Unlock()
}

// Connections represent set of connection.
type Connections struct {
}

// Write writes all Connections in map.
func (c *Connections) Write(p []byte) (int, error) {
	var (
		wlen int
		err  error
	)
	mu.Lock()
	for c, ok := range conns {
		if ok {
			l, e := c.Write(p)
			wlen += l
			if e != nil {
				err = e
			}
		}
	}
	mu.Unlock()
	return wlen, err
}
