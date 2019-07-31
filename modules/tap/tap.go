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

package tap

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/notifier"
	"github.com/lagopus/vsw/vswitch"
	vlog "github.com/lagopus/vsw/vswitch/log"
)

const (
	moduleName       = "tap"
	queueLength      = 64
	tapMaxRetryCount = 100
	tapRetryInterval = 100 * time.Millisecond
	vrfRetryCount    = 100
	vrfRetryInterval = 100 * time.Millisecond
)

var log = vswitch.Logger

type vifInfo struct {
	vif *vswitch.VIF
	ch  chan *dpdk.Mbuf
}

type TapInstance struct {
	pool    *dpdk.MemPool
	base    *vswitch.BaseInstance
	noti    *notifier.Notifier
	notiCh  chan notifier.Notification
	txCh    chan vifInfo
	rxCh    chan struct{}
	enabled bool
	wg      sync.WaitGroup
	rs      int
	vrf     string
}

func newTapInstance(base *vswitch.BaseInstance, i interface{}) (vswitch.Instance, error) {
	vrf, ok := i.(string)
	if !ok {
		return nil, errors.New("VRF not specified")
	}

	t := &TapInstance{
		base: base,
		pool: vswitch.GetDpdkResource().Mempool,
		noti: base.Rules().Notifier(),
		txCh: make(chan vifInfo, 1),
		rxCh: make(chan struct{}, 1),
		vrf:  vrf,
	}
	t.notiCh = t.noti.Listen()
	go t.listener()
	go t.txTask()
	return t, nil
}

func (t *TapInstance) Free() {
	t.noti.Close(t.notiCh)
	close(t.txCh)
}

func (t *TapInstance) listener() {
	for n := range t.notiCh {
		rule, ok := n.Value.(vswitch.Rule)
		if !ok || rule.Match != vswitch.MatchOutVIF {
			continue
		}

		vif, ok := rule.Param.(*vswitch.VIF)
		if !ok {
			continue
		}

		switch n.Type {
		case notifier.Add:
			ch := make(chan *dpdk.Mbuf)
			t.txCh <- vifInfo{vif, ch}
			go t.readFromTap(vif, ch)

		case notifier.Delete:
			// Deletion comes for free. If the netlink closes the tap,
			// Read in readFromTap fails which causes channel to be closed.
			// txTask then stops reading from the channel.
		}
	}
}

func newCase(v interface{}) reflect.SelectCase {
	return reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(v)}
}

func (t *TapInstance) txTask() {
	cases := []reflect.SelectCase{newCase(t.txCh)}
	vifs := make(map[int]*vswitch.VIF)

	for {
		chosen, value, ok := reflect.Select(cases)

		if !ok {
			// Need to quit
			if chosen == 0 {
				return
			}

			// Delete closed channel
			l := len(cases) - 1
			cases[chosen] = cases[l]
			cases = cases[:l]

			vifs[chosen] = vifs[l]
			delete(vifs, l)

			continue
		}

		switch v := value.Interface().(type) {
		case vifInfo:
			cases = append(cases, newCase(v.ch))
			vifs[len(cases)-1] = v.vif

		case *dpdk.Mbuf:
			vif := vifs[chosen]
			vif.Input().EnqueueMbuf(v)
		}
	}
}

func (t *TapInstance) readFromTap(vif *vswitch.VIF, ch chan *dpdk.Mbuf) {
	// MAC Header (14 Bytes) + MTU
	buf := make([]byte, vif.MTU()+14)

	index := vif.Index()
	vid := uint16(vif.VID())

	retry := 0
	tap := vif.TAP()
	for tap == nil {
		if retry < tapMaxRetryCount {
			retry++
		} else {
			// XXX: error
			return
		}

		time.Sleep(tapRetryInterval)
		tap = vif.TAP()
	}

	for {
		// XXX: We may want to imporove this by passing the pointer to
		// data directly. We then will need to update data_len of the
		// Mbuf.
		n, err := tap.Read(buf)
		if err != nil {
			log.Printf("%v: Read from Tap failed: %v", t, err)
			// If TAP is closed by the agent, we can glacefully quit.
			close(ch)
			return
		}

		// If the module is not enabled, just skip.
		if !t.enabled {
			continue
		}

		if mbuf := t.pool.AllocMbuf(); mbuf != nil {
			mbuf.SetData(buf[:n])
			mbuf.SetVlanTCI(vid)
			md := (*vswitch.Metadata)(mbuf.Metadata())
			md.Reset()
			md.SetOutVIF(index)
			md.SetInVIF(index)
			ch <- mbuf
		} else {
			log.Printf("%v: %d bytes packet from tap of VIF %d dropped. No Mbuf.", t, n, index)
		}
	}
}

func (t *TapInstance) rxTask() {
	input := t.base.Input()
	mbufs := make([]*dpdk.Mbuf, queueLength)
	for t.enabled {
		n := input.DequeueBurstMbufs(&mbufs)
		for _, mbuf := range mbufs[:n] {
			md := (*vswitch.Metadata)(mbuf.Metadata())

			if md.Local() {
				// Concatenate scattered Mbuf
				p := mbuf.Data()[14:]
				nxt := mbuf.Next()
				for nxt != nil {
					p = append(p, nxt.Data()...)
					nxt = nxt.Next()
				}

				// Copy Dst IP
				var dst [4]byte
				copy(dst[:], p[16:20])
				addr := syscall.SockaddrInet4{
					Port: 0,
					Addr: dst,
				}
				if err := syscall.Sendto(t.rs, p, 0, &addr); err != nil {
					log.Printf("%v: Can't Write to Rawsocket: %v", t, err)
				}
			} else {
				if vif := vswitch.GetVIFByIndex(md.InVIF()); vif != nil {
					tap := vif.TAP()
					frame := mbuf.Data()
					nxt := mbuf.Next()
					for nxt != nil {
						frame = append(frame, nxt.Data()...)
						nxt = nxt.Next()
					}

					_, err := tap.Write(frame)
					if err != nil {
						log.Printf("%v: Write to Tap failed: %v", t, err)
					}
				} else {
					log.Printf("%v: can't find VIF Index = %d", t, md.InVIF())
				}
			}

			mbuf.Free()
		}
		runtime.Gosched()
	}
	t.rxCh <- struct{}{}
}

func (t *TapInstance) Enable() error {
	rs, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("Can't open raw socket: %v", err)
	}

	if err := syscall.SetsockoptInt(rs, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(rs)
		return fmt.Errorf("Can't set IP_HDRINCL: %v", err)
	}

	vpath := "/sys/class/net/" + t.vrf
	for i := 0; i < vrfRetryCount; i++ {
		if _, err := os.Stat(vpath); err == nil {
			break
		}
		time.Sleep(vrfRetryInterval)
	}

	if err := syscall.SetsockoptString(rs, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, t.vrf); err != nil {
		syscall.Close(rs)
		return fmt.Errorf("Can't set SO_BINDTODEVICE: %v", err)
	}

	t.rs = rs

	// launch
	t.enabled = true
	go t.rxTask()

	return nil
}

func (t *TapInstance) Disable() {
	t.enabled = false
	<-t.rxCh
	syscall.Close(t.rs)
}

func (t *TapInstance) String() string {
	return t.base.Name()
}

func init() {
	if l, err := vlog.New(moduleName); err == nil {
		log = l
	} else {
		log.Fatalf("Can't create logger: %s", moduleName)
	}

	rp := &vswitch.RingParam{
		Count:    queueLength,
		SocketId: dpdk.SOCKET_ID_ANY,
	}

	if err := vswitch.RegisterModule("tap", newTapInstance, rp, vswitch.TypeOther); err != nil {
		log.Fatalf("Failed to register Tap class: %v", err)
	}
}
