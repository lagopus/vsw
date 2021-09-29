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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"syscall"

	"github.com/lagopus/vsw/modules/tunnel/log"
)

type msgMap map[uint16]interface{}

// ParseSadbMsg parses a sadb message to SadbBaseMsg structure.
func (s *SadbBaseMsg) ParseSadbMsg(r io.Reader) error {
	msg := s.getMsgMap()
	for {
		sadbExt := SadbExt{}
		err := sadbExt.Deserialize(r)
		if err == io.EOF {
			err = nil
			break
		}
		switch sadbExt.SadbExtType {
		case SADB_EXT_SA:
			s, _ := msg[sadbExt.SadbExtType].(**SadbSa)
			*s = &SadbSa{}
			err = (*s).Deserialize(r)
		case SADB_EXT_LIFETIME_CURRENT, SADB_EXT_LIFETIME_HARD, SADB_EXT_LIFETIME_SOFT:
			s, _ := msg[sadbExt.SadbExtType].(**SadbLifetime)
			*s = &SadbLifetime{}
			err = (*s).Deserialize(r)
		case SADB_EXT_ADDRESS_SRC, SADB_EXT_ADDRESS_DST, SADB_EXT_ADDRESS_PROXY:
			s, _ := msg[sadbExt.SadbExtType].(**AddrPair)
			*s = &AddrPair{SadbAddrLen: sadbExt.SadbExtLen}
			err = (*s).Deserialize(r)
		case SADB_EXT_KEY_AUTH, SADB_EXT_KEY_ENCRYPT:
			s, _ := msg[sadbExt.SadbExtType].(**KeyPair)
			*s = &KeyPair{SadbKeyLen: sadbExt.SadbExtLen}
			err = (*s).Deserialize(r)
		case SADB_EXT_IDENTITY_SRC, SADB_EXT_IDENTITY_DST, SADB_EXT_SENSITIVITY:
			err = syscall.EINVAL
		case SADB_EXT_SPIRANGE:
			s, _ := msg[sadbExt.SadbExtType].(**SadbSPIRange)
			*s = &SadbSPIRange{}
			err = (*s).Deserialize(r)
		case SADB_X_EXT_SA2:
			s, _ := msg[sadbExt.SadbExtType].(**SadbXSa2)
			*s = &SadbXSa2{}
			err = (*s).Deserialize(r)
		case SADB_X_EXT_POLICY:
			s, _ := msg[sadbExt.SadbExtType].(**Policy)
			*s = &Policy{SadbXPolicyLen: sadbExt.SadbExtLen}
			err = (*s).Deserialize(r)
		case SADB_X_EXT_NAT_T_TYPE:
			s, _ := msg[sadbExt.SadbExtType].(**SadbXNatTType)
			*s = &SadbXNatTType{}
			err = (*s).Deserialize(r)
		case SADB_X_EXT_NAT_T_SPORT:
			s, _ := msg[sadbExt.SadbExtType].(**SadbXNatTPort)
			*s = &SadbXNatTPort{}
			err = (*s).Deserialize(r)
		case SADB_X_EXT_NAT_T_DPORT:
			s, _ := msg[sadbExt.SadbExtType].(**SadbXNatTPort)
			*s = &SadbXNatTPort{}
			err = (*s).Deserialize(r)
		default:
			log.Logger.Err("unknown type: %v", sadbExt.SadbExtType)
			err = syscall.EINVAL
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// SadbBaseMsg represents pfkey message structure.
type SadbBaseMsg struct {
	Sa              *SadbSa
	CurrentLifetime *SadbLifetime /* optional */
	HardLifetime    *SadbLifetime /* optional */
	SoftLifetime    *SadbLifetime /* optional */
	SrcAddress      *AddrPair
	DstAddress      *AddrPair
	ProxyAddress    *AddrPair /* optional */
	AuthKey         *KeyPair
	EncKey          *KeyPair
	SrcSadbIdent    *SadbIdent /* optional */
	DstSadbIdent    *SadbIdent /* optional */
	SadbSens        *SadbSens  /* optional */
	SadbSPIRange    *SadbSPIRange
	SadbXSa2        *SadbXSa2 /* optional */
	Policy          *Policy
	NatTType        *SadbXNatTType
	NatTSrcPort     *SadbXNatTPort
	NatTDstPort     *SadbXNatTPort
}

func (s *SadbBaseMsg) getMsgMap() msgMap {
	*s = SadbBaseMsg{} // clear pointers
	return msgMap{
		SADB_EXT_SA:               &s.Sa,
		SADB_EXT_LIFETIME_CURRENT: &s.CurrentLifetime,
		SADB_EXT_LIFETIME_HARD:    &s.HardLifetime,
		SADB_EXT_LIFETIME_SOFT:    &s.SoftLifetime,
		SADB_EXT_ADDRESS_SRC:      &s.SrcAddress,
		SADB_EXT_ADDRESS_DST:      &s.DstAddress,
		SADB_EXT_ADDRESS_PROXY:    &s.ProxyAddress,
		SADB_EXT_KEY_AUTH:         &s.AuthKey,
		SADB_EXT_KEY_ENCRYPT:      &s.EncKey,
		SADB_EXT_IDENTITY_SRC:     &s.SrcSadbIdent,
		SADB_EXT_IDENTITY_DST:     &s.DstSadbIdent,
		SADB_EXT_SENSITIVITY:      &s.SadbSens,
		SADB_EXT_SPIRANGE:         &s.SadbSPIRange,
		SADB_X_EXT_SA2:            &s.SadbXSa2,
		SADB_X_EXT_POLICY:         &s.Policy,
		SADB_X_EXT_NAT_T_TYPE:     &s.NatTType,
		SADB_X_EXT_NAT_T_SPORT:    &s.NatTSrcPort,
		SADB_X_EXT_NAT_T_DPORT:    &s.NatTDstPort,
	}
}

// ParseHandler parses and handle pfkey messages.
type ParseHandler interface {
	Parse(r io.Reader) error
	Handle(w io.Writer, sadbMsg *SadbMsg) error
}

// MsgMux represents a table of ParseHandler for pfkey messages.
type MsgMux map[uint8]ParseHandler

// MsgMuxNew returns a new MsgMux.
func MsgMuxNew() MsgMux {
	return MsgMux{}
}

// ParseHandle sets ParseHandler to MsgMux.
func (m MsgMux) ParseHandle(t uint8, p ParseHandler) {
	m[t] = p
}

func (s *SadbMsg) sendError(w io.Writer, errno uint8) {
	s.SadbMsgErrno = errno
	smsg := SadbMsgTransport{
		SadbMsg: s,
	}
	_ = smsg.Serialize(w)
}

// HandlePfkey handles pfkey messages with MsgMux.
func HandlePfkey(r io.Reader, w io.Writer, msgMux MsgMux) (*SadbMsg, error) {
	if msgMux == nil {
		return nil, syscall.EINVAL
	}
	// assume to keep message boundary, on each pfkey messages.
	br := bufio.NewReader(r)
	// read SadbMsg head
	sb := make([]byte, SadbMsgLen)
	n, err := br.Read(sb) // one read, one pfkey message.
	if n != len(sb) || err != nil {
		// error log only.
		log.Logger.Err("err %#v", err)
		if err == nil {
			return nil, fmt.Errorf("message length err: %d", n)
		}
		return nil, err
	}
	s := SadbMsg{}
	err = s.Deserialize(bytes.NewBuffer(sb))
	if err != nil {
		// error log only.
		log.Logger.Err("err %#v", err)
		return nil, err
	}
	if s.SadbMsgVersion != PF_KEY_V2 {
		s.sendError(w, uint8(syscall.EINVAL))
		log.Logger.Err("invalid pfkey version: %d != %d", PF_KEY_V2, s.SadbMsgVersion)
		return nil, syscall.EINVAL
	}
	log.Logger.Info("base header: len: %d %#v", toByteLen(s.SadbMsgLen), sb)

	// read SadbMsg body
	eb := make([]byte, toByteLen(s.SadbMsgLen)-SadbMsgLen)
	n, err = br.Read(eb)
	if n != len(eb) || err != nil {
		log.Logger.Err("invalid packet length: %d", n)
		s.sendError(w, uint8(syscall.EINVAL))
		return nil, fmt.Errorf("message length err: %d", n)
	}

	log.Logger.Info("extensions:")
	log.Logger.Info("%#v", eb)

	smsg, ok := msgMux[s.SadbMsgType]
	if !ok {
		log.Logger.Err("don't support type %d", s.SadbMsgType)
		return nil, fmt.Errorf("don't support type %d", s.SadbMsgType)
	}

	log.Logger.Info("received sadb msg: %s len: %d seq: %d pid: %d",
		SadbMsgTypes[s.SadbMsgType], toByteLen(s.SadbMsgLen), s.SadbMsgSeq, s.SadbMsgPid)

	buf := bytes.NewBuffer(eb)
	err = smsg.Parse(buf)
	if err != nil {
		log.Logger.Err("parse err: %v", err)
		return nil, fmt.Errorf("parse err: %v", err)
	}
	err = smsg.Handle(w, &s)
	if err != nil {
		log.Logger.Err("handle err: %v", err)
		return nil, fmt.Errorf("handle err: %v", err)
	}
	return &s, err
}
