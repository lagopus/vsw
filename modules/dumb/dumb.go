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

package dumb

import (
	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/vswitch"
)

var log = vswitch.Logger

type DumbModule struct {
	vswitch.ModuleService
	running bool
	done    chan int
}

/*
 * If you want to expose arbitrary struct to be used with Control(), define.
 */
type DumbConfig struct {
	Number int
	String string
	Array  []string
}

//
func createDumbModule(p *vswitch.ModuleParam) (vswitch.Module, error) {
	return &DumbModule{
		ModuleService: vswitch.NewModuleService(p),
		running:       true,
		done:          make(chan int),
	}, nil
}

func (dm *DumbModule) Control(c string, v interface{}) interface{} {
	log.Printf("%s: Control(%v): Value=%v\n", dm.Name(), c, v)
	return true
}

func (dm *DumbModule) Start() bool {
	log.Printf("%s: Start()", dm.Name())

	if !dm.running {
		log.Printf("%s: Terminated before start", dm.Name())
		return false
	}

	oring := dm.Rules().Output(vswitch.MATCH_ANY)
	if oring == nil {
		log.Printf("%s: Output ring is not specified.", dm.Name())
	}

	var irings []*dpdk.Ring

	if dm.Input() != nil {
		irings = append(irings, dm.Input())
	} else {
		log.Printf("%s: Input ring is not specified.", dm.Name())
	}

	if dm.VifInput() != nil {
		irings = append(irings, dm.VifInput())
	} else {
		log.Printf("%s: VIF Input ring is not specified.", dm.Name())
	}
	mbufs := make([]*dpdk.Mbuf, 512)

	go func() {
		for dm.running {
			for _, iring := range irings {
				rxc := iring.DequeueBurstMbufs(&mbufs)
				if rxc > 0 {
					if oring != nil {
						txc := oring.EnqueueBurstMbufs(mbufs[:rxc])
						log.Printf("%s: in=%d, out=%d\n", dm.Name(), rxc, txc)
					}
				}
			}
		}
		close(dm.done)
	}()

	return true
}

func (dm *DumbModule) Stop() {
	log.Printf("%s: Stop()", dm.Name())
	dm.running = false
}

func (dm *DumbModule) Wait() {
	log.Printf("%s: Wait()", dm.Name())
	<-dm.done
}

/*
 * Do module registration here.
 */
func init() {
	if !vswitch.RegisterModule("dumb", createDumbModule, nil, vswitch.TypeOther) {
		log.Fatalf("Failed to register the class.")
	}
}
