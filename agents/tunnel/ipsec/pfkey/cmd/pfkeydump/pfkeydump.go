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

package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/lagopus/vsw/agents/tunnel/ipsec/pfkey"
)

const sock = "/var/tmp/lagopus.sock"

type sadbMsg struct {
	pfkey.SadbBaseMsg
}

type sadbDumpMsg struct {
	pfkey.SadbBaseMsg
}

func (s *sadbDumpMsg) Parse(r io.Reader) error {
	err := s.ParseSadbMsg(r)
	if err != nil {
		return err
	}
	return nil
}

func (s *sadbDumpMsg) Handle(w io.Writer, smsg *pfkey.SadbMsg) error {
	spew.Dump(*s)
	return nil
}

func (s *sadbMsg) Parse(r io.Reader) error {
	err := s.ParseSadbMsg(r)
	if err != nil {
		return err
	}
	return nil
}

func (s *sadbMsg) Handle(w io.Writer, smsg *pfkey.SadbMsg) error {
	mtype := pfkey.SadbMsgTypes[smsg.Sadb_msg_type]
	fmt.Printf("type: %s errno: %d seq: %d pid: %d\n", mtype, smsg.Sadb_msg_errno,
		smsg.Sadb_msg_seq, smsg.Sadb_msg_pid)
	if s.Sa != nil {
		fmt.Printf("  spi: %x\n", s.Sa.Sadb_sa_spi)
	}
	if s.Policy != nil {
		fmt.Printf("  policy id: %x\n", s.Policy.Policy.Sadb_x_policy_id)
	}
	return nil
}

var seq uint32 = 1

var d = flag.Bool("d", false, "Dump SAD entris.")
var x = flag.Bool("x", false, "Loop forever and dump all the messages transmitted to PF_KEY socket.")

var msgMux = pfkey.MsgMux{
	pfkey.SADB_GETSPI:      &sadbMsg{},
	pfkey.SADB_UPDATE:      &sadbMsg{},
	pfkey.SADB_ADD:         &sadbMsg{},
	pfkey.SADB_DELETE:      &sadbMsg{},
	pfkey.SADB_GET:         &sadbMsg{},
	pfkey.SADB_REGISTER:    &sadbMsg{},
	pfkey.SADB_EXPIRE:      &sadbMsg{},
	pfkey.SADB_DUMP:        &sadbMsg{},
	pfkey.SADB_X_SPDADD:    &sadbMsg{},
	pfkey.SADB_X_SPDUPDATE: &sadbMsg{},
	pfkey.SADB_X_SPDGET:    &sadbMsg{},
	pfkey.SADB_X_SPDDELETE: &sadbMsg{},
}

func main() {
	flag.Parse()
	c, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{sock, "unixpacket"})
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	defer c.Close()

	if *d {
		dump := pfkey.NewSadbMsg(pfkey.SADB_DUMP,
			pfkey.SADB_SATYPE_ESP, seq, uint32(os.Getuid()))
		smsg := pfkey.SadbMsgTransport{
			SadbMsg: dump,
		}
		err = smsg.Serialize(c)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
		for {
			s, err := pfkey.HandlePfkey(c, c, msgMux)
			if err != nil {
				fmt.Println(err)
				os.Exit(-1)
			}
			if s.Sadb_msg_seq == 0 {
				break
			}
		}
	}
	for *x {
		_, err := pfkey.HandlePfkey(c, c, msgMux)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
	}
}
