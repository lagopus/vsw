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

package dumb

import (
	"errors"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/vswitch"
	vlog "github.com/lagopus/vsw/vswitch/log"
)

const (
	moduleName = "dumb"
)

var log = vswitch.Logger

type DumbModule struct {
	base    *vswitch.BaseInstance
	running bool
	done    chan int
}

func newDumbInstance(base *vswitch.BaseInstance, i interface{}) (vswitch.Instance, error) {
	return &DumbModule{
		base:    base,
		running: true,
		done:    make(chan int),
	}, nil
}

func (dm *DumbModule) Free() {}

func (dm *DumbModule) Enable() error {
	log.Printf("%s: Enable()", dm.base.Name())

	if !dm.running {
		return errors.New("Terminated before start")
	}

	oring := dm.base.Rules().Output(vswitch.MatchOutVIF)
	if oring == nil {
		return errors.New("Output ring is not specified.")
	}

	mbufs := make([]*dpdk.Mbuf, 512)
	iring := dm.base.Input()

	go func() {
		for dm.running {
			rxc := iring.DequeueBurstMbufs(&mbufs)
			if rxc > 0 {
				if oring != nil {
					txc := oring.EnqueueBurstMbufs(mbufs[:rxc])
					log.Printf("%s: in=%d, out=%d\n", dm.base.Name(), rxc, txc)
				}
			}
		}
		close(dm.done)
	}()

	return nil
}

func (dm *DumbModule) Disable() {
	log.Printf("%s: Disable()", dm.base.Name())
	dm.running = false
	<-dm.done
}

/*
 * Do module registration here.
 */
func init() {
	if l, err := vlog.New(moduleName); err == nil {
		log = l
	} else {
		log.Fatalf("Can't create logger: %s", moduleName)
	}

	if err := vswitch.RegisterModule("dumb", newDumbInstance, nil, vswitch.TypeOther); err != nil {
		log.Fatalf("Failed to register the class: %v", err)
	}
}
