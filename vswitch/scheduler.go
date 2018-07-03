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

package vswitch

/*
#cgo CFLAGS: -I${SRCDIR}/../../include -I/usr/local/include/dpdk -m64 -pthread -O3 -msse4.2
#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all -L/usr/local/lib -ldpdk

#include "runtime.h"
#include "scheduler.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/lagopus/vsw/dpdk"
	"github.com/lagopus/vsw/utils/ringpair"
)

const MaxRuntimePerScheduler = C.SCHED_MAX_RUNTIMES

type scheduler struct {
	core     uint
	runtimes []*Runtime
	reqRp    *ringpair.RingPair
	resRp    *ringpair.RingPair
	reqCh    chan *request
	seqno    uint64
	results  map[uint64]chan bool
	mutex    sync.Mutex
	resMutex sync.Mutex
}

type request struct {
	cmd     C.sched_cmd_t
	rid     int
	name    *C.char
	ops     *C.struct_lagopus_runtime_ops
	ins     *C.struct_lagopus_instance
	param   unsafe.Pointer
	enabled bool
	rc      chan bool
}

const (
	RING_USED = 0
	RING_FREE = 1
)

var schedulers = make(map[uint]*scheduler)
var schedulerMutex sync.Mutex

func createRingPair(name string, sockid int) *ringpair.RingPair {
	return ringpair.Create(&ringpair.Config{
		Prefix: name,
		Counts: [2]uint{
			C.SCHED_MAX_REQUESTS,     // Used
			C.SCHED_MAX_REQUESTS * 2, // Free
		},
		SocketID: sockid,
	})
}

// getScheduler initialize the scheduler and returns an instance
// of scheduler for the specified core.
func getScheduler(coreid uint) (*scheduler, error) {
	schedulerMutex.Lock()
	defer schedulerMutex.Unlock()

	var (
		reqRp *ringpair.RingPair
		resRp *ringpair.RingPair
		p     *C.struct_sched_arg
		s     *scheduler
	)
	sockId := int(dpdk.LcoreToSocketId(coreid))

	if s, ok := schedulers[coreid]; ok {
		return s, nil
	}

	// Reserve the slave core
	if !GetDpdkResource().reserveLcore("scheduler", coreid) {
		return nil, fmt.Errorf("Can't reserve lcore for scheduler on %d", coreid)
	}

	// Create ring pairs
	var err error
	reqRp = createRingPair(fmt.Sprintf("sched_req%d", coreid), sockId)
	if reqRp == nil {
		err = errors.New("Can't create ringpair for requests")
		goto Error
	}

	resRp = createRingPair(fmt.Sprintf("sched_res%d", coreid), sockId)
	if resRp == nil {
		err = errors.New("Can't create ringpair for results")
		goto Error
	}

	p = (*C.struct_sched_arg)(C.malloc(C.sizeof_struct_sched_arg))
	p.request = (*C.struct_rte_ring)(unsafe.Pointer(reqRp.Rings[RING_USED]))
	p.request_free = (*C.struct_rte_ring)(unsafe.Pointer(reqRp.Rings[RING_FREE]))
	p.result = (*C.struct_rte_ring)(unsafe.Pointer(resRp.Rings[RING_USED]))
	p.result_free = (*C.struct_rte_ring)(unsafe.Pointer(resRp.Rings[RING_FREE]))

	// EAL Remote Launch
	if dpdk.EalRemoteLaunch((dpdk.LcoreFunc)(C.sched_main), unsafe.Pointer(p), coreid) != 0 {
		err = fmt.Errorf("Can't start scheduler on %d", coreid)
		goto Error
	}

	s = &scheduler{
		core:     coreid,
		runtimes: make([]*Runtime, MaxRuntimePerScheduler),
		reqRp:    reqRp,
		resRp:    resRp,
		reqCh:    make(chan *request),
		results:  make(map[uint64]chan bool),
	}

	go s.sender()
	go s.receiver()

	schedulers[coreid] = s
	return s, nil

Error:
	GetDpdkResource().FreeLcore(coreid)
	if reqRp != nil {
		reqRp.Free()
	}
	if resRp != nil {
		resRp.Free()
	}
	if p != nil {
		C.free(unsafe.Pointer(p))
	}
	return nil, err
}

// Sender sends requests to the scheduler.
// TODO: We may need to do bulk transfer for performance.
func (s *scheduler) sender() {
	freeRing := s.reqRp.Rings[RING_FREE]
	usedRing := s.reqRp.Rings[RING_USED]

	for r := range s.reqCh {
		var req *C.struct_sched_request

		// If we cannot get a free request buffer at the first attempt,
		// we try until we get one with a timeout of 3 seconds.
		if freeRing.Dequeue((*unsafe.Pointer)(unsafe.Pointer(&req))) != 0 {
			t := time.NewTimer(3 * time.Second)
		Loop:
			for {
				select {
				case <-t.C:
					Logger.Fatalf("Can't get free request buffer. Scheduler maybe dead.")
				default:
					if freeRing.Dequeue((*unsafe.Pointer)(unsafe.Pointer(&req))) == 0 {
						if !t.Stop() {
							<-t.C
						}
						break Loop
					}
					runtime.Gosched()
				}
			}
		}

		// Fill details
		req.cmd = r.cmd
		req.seqno = C.uint64_t(s.seqno)
		req.rid = C.int(r.rid)
		req.name = r.name
		req.ops = r.ops
		req.ins = r.ins
		req.param = r.param
		req.enabled = C.bool(r.enabled)

		if usedRing.Enqueue(unsafe.Pointer(req)) != 0 {
			Logger.Printf("Can't send request buffer.")
			continue
		}

		s.resMutex.Lock()
		s.results[s.seqno] = r.rc
		s.resMutex.Unlock()

		// increment sequence number now
		s.seqno++
	}
}

// Receiver receives results from the scheduler.
func (s *scheduler) receiver() {
	req := make([]*C.struct_sched_result, C.SCHED_MAX_REQUESTS)

	freeRing := s.resRp.Rings[RING_FREE]
	usedRing := s.resRp.Rings[RING_USED]

	for {
		count := usedRing.DequeueBurst((*unsafe.Pointer)(unsafe.Pointer(&req[0])), uint(len(req)))
		for i := 0; i < int(count); i++ {
			seqno := uint64(req[i].seqno)
			s.resMutex.Lock()
			if rc, ok := s.results[seqno]; ok {
				rc <- bool(req[i].res)
				close(rc)
				delete(s.results, seqno)
			}
			s.resMutex.Unlock()
		}
		if !freeRing.EnqueueBulk((*unsafe.Pointer)(unsafe.Pointer(&req[0])), count) {
			Logger.Printf("Can't free result buffers.")
		}
		runtime.Gosched()
	}
}

func (s *scheduler) request(req *request) bool {
	req.rc = make(chan bool)
	s.reqCh <- req
	return <-req.rc
}

func (s *scheduler) addRuntime(r *Runtime, ops LagopusRuntimeOps, param unsafe.Pointer) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Find a vacant slot for new runtime
	rid := -1
	for i, slot := range s.runtimes {
		if slot == nil {
			rid = i + 1
			break
		}
	}
	if rid == -1 {
		return fmt.Errorf("No available slot for new runtime on core %v", s.core)
	}

	// Create and send a request to add a runtime
	name := C.CString(r.name)
	defer C.free(unsafe.Pointer(name))
	if !s.request(&request{
		cmd:   C.SCHED_CMD_ADD_RUNTIME,
		rid:   rid,
		name:  name,
		ops:   (*C.struct_lagopus_runtime_ops)(ops),
		param: param,
	}) {
		return fmt.Errorf("Adding new runtime failed in the scheduler.")
	}

	// The runtime created
	r.rid = rid
	r.sched = s
	r.ins = make(map[uint64]*RuntimeInstance)
	s.runtimes[rid-1] = r

	return nil
}

func (s *scheduler) deleteRuntime(r *Runtime) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Create and send a request to delete a runtime
	s.request(&request{
		cmd: C.SCHED_CMD_DELETE_RUNTIME,
		rid: r.rid,
	})

	// Delete a reference to the runtime
	s.runtimes[r.rid-1] = nil
}

func (s *scheduler) enableRuntime(r *Runtime, e bool) bool {
	return s.request(&request{
		cmd:     C.SCHED_CMD_ENABLE_RUNTIME,
		rid:     r.rid,
		enabled: e,
	})
}

func (s *scheduler) addRuntimeInstance(r *Runtime, i *RuntimeInstance) bool {
	return s.request(&request{
		cmd: C.SCHED_CMD_ADD_INSTANCE,
		rid: r.rid,
		ins: i.entity,
	})
}

func (s *scheduler) deleteRuntimeInstance(r *Runtime, i *RuntimeInstance) bool {
	return s.request(&request{
		cmd: C.SCHED_CMD_DELETE_INSTANCE,
		rid: r.rid,
		ins: i.entity,
	})
}

func (s *scheduler) enableRuntimeInstance(r *Runtime, i *RuntimeInstance, e bool) bool {
	return s.request(&request{
		cmd:     C.SCHED_CMD_ENABLE_INSTANCE,
		rid:     r.rid,
		ins:     i.entity,
		enabled: e,
	})
}

func (s *scheduler) controlRuntimeInstance(r *Runtime, i *RuntimeInstance, p unsafe.Pointer) bool {
	return s.request(&request{
		cmd:   C.SCHED_CMD_CONTROL_INSTANCE,
		rid:   r.rid,
		ins:   i.entity,
		param: p,
	})
}

func (s *scheduler) terminate() {
	s.request(&request{cmd: C.SCHED_CMD_TERMINATE})
	// TODO: Delete all runtime
}

// Runtime represents an execution environment on DPDK
// slave lcore to be used by modules.
type Runtime struct {
	rid     int
	name    string
	sched   *scheduler
	ins     map[uint64]*RuntimeInstance
	enabled bool
	mutex   sync.Mutex
}

type LagopusRuntimeOps *C.struct_lagopus_runtime_ops

// NewRuntime creates a runtime on the specified lcore for a module.
// Name is a unique name that describes runtime. The name shall be unique
// per core, i.e. scheduler.
// Ops is a pointer to an instance of struct lagopus_runtime_ops.
// Param is an argument passed to init() function of the runtime
// during the startup of the runtime.
func NewRuntime(coreid uint, name string, ops LagopusRuntimeOps, param unsafe.Pointer) (*Runtime, error) {
	s, err := getScheduler(coreid)
	if err != nil {
		return nil, fmt.Errorf("Get a scheduler on core %d failed: %s", coreid, err)
	}

	r := &Runtime{name: name, enabled: false}
	if err := s.addRuntime(r, ops, param); err != nil {
		return nil, fmt.Errorf("Can't register runtime on core %d: %s", coreid, err)
	}

	return r, nil
}

// Register registers RuntimeInstance to the runtime.
func (r *Runtime) Register(i *RuntimeInstance) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.sched == nil {
		return errors.New("Runtime not associated with scheduler")
	}

	if err := i.setRuntime(r); err != nil {
		return err
	}

	// Request to register instance to the runtime
	if !r.sched.addRuntimeInstance(r, i) {
		return errors.New("Adding instance to the runtime failed")
	}
	r.ins[i.id] = i
	return nil
}

func (r *Runtime) unregister(i *RuntimeInstance) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.sched == nil {
		return errors.New("Runtime not associated with scheduler")
	}

	if i.Runtime() != r {
		return errors.New("Instance not associated with this runtime")
	}

	if !r.sched.deleteRuntimeInstance(r, i) {
		return errors.New("Deleting istance from the runtime failed")
	}

	delete(r.ins, uint64(i.id))
	return nil
}

// Instances returns a slice of registered Instance.
func (r *Runtime) RuntimeInstances() []*RuntimeInstance {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.sched == nil {
		return nil
	}

	ins := make([]*RuntimeInstance, 0, len(r.ins))
	for _, v := range r.ins {
		ins = append(ins, v)
	}

	return ins
}

// IsEnabled returns true if the runtime is enabled. False otherwise.
func (r *Runtime) IsEnabled() bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.enabled
}

// Enable enables or disables the runtime.
func (r *Runtime) Enable() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.sched == nil {
		return errors.New("Runtime not associated with scheduler")
	}
	r.sched.enableRuntime(r, true)
	return nil
}

// Enable enables or disables the runtime.
func (r *Runtime) Disable() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.sched == nil {
		return errors.New("Runtime not associated with scheduler")
	}
	r.sched.enableRuntime(r, false)
	return nil
}

// Terminate terminates the runtime. Runtime cannot be used after termination.
func (r *Runtime) Terminate() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.sched == nil {
		return
	}
	r.sched.deleteRuntime(r)
	r.sched = nil
	r.ins = nil
}

func (r *Runtime) enableRuntimeInstance(i *RuntimeInstance, e bool) (bool, error) {
	if r.sched == nil {
		return false, errors.New("Runtime not associated with scheduler")
	}
	return r.sched.enableRuntimeInstance(r, i, e), nil
}

func (r *Runtime) controlRuntimeInstance(i *RuntimeInstance, p unsafe.Pointer) (bool, error) {
	if r.sched == nil {
		return false, errors.New("Runtime not associated with scheduler")
	}
	return r.sched.controlRuntimeInstance(r, i, p), nil
}

type RuntimeInstance struct {
	id      uint64
	runtime *Runtime
	entity  *C.struct_lagopus_instance
	enabled bool
	mutex   sync.Mutex
}

var instanceMutex sync.Mutex
var instanceID uint64

type LagopusInstance *C.struct_lagopus_instance

// NewRuntimeInstance creates an RuntimeInstance.
// Instance is a pointer to an instance of struct lagopus_instnace.
// XXX: Decide whom to free the struct lagopus_instance.
func NewRuntimeInstance(instance LagopusInstance) (*RuntimeInstance, error) {
	if instance == nil {
		return nil, errors.New("Invalid instance passed")
	}

	instanceMutex.Lock()
	defer instanceMutex.Unlock()

	if instanceID == math.MaxUint64 {
		return nil, errors.New("InstanceID exceeded the limit")
	}

	instanceID++
	instance.id = C.uint64_t(instanceID)

	return &RuntimeInstance{id: instanceID, entity: instance, enabled: false}, nil
}

// Runtime returns the runtime this instance belongs to.
func (i *RuntimeInstance) Runtime() *Runtime {
	return i.runtime
}

// setRuntime sets the runtime this instance belongs to.
// Returns false if the instance already belongs to a runtime.
// True if set successively.
func (i *RuntimeInstance) setRuntime(r *Runtime) error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	if i.runtime != nil {
		return errors.New("Runtime already associated")
	}

	i.runtime = r
	return nil
}

// IsEnabled returns true if the instance is enabled. False otherwise.
func (i *RuntimeInstance) IsEnabled() bool {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	return i.enabled
}

// Enable enables the instance.
func (i *RuntimeInstance) Enable() error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	if i.runtime == nil {
		return errors.New("Runtime not associated")
	}

	var err error
	i.enabled, err = i.runtime.enableRuntimeInstance(i, true)
	return err
}

// Disable disables the instance.
func (i *RuntimeInstance) Disable() error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	if i.runtime == nil {
		return errors.New("Runtime not associated")
	}

	var err error
	i.enabled, err = i.runtime.enableRuntimeInstance(i, false)
	return err
}

// Control sends a module defined request to the instance.
func (i *RuntimeInstance) Control(param unsafe.Pointer) (bool, error) {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	if i.runtime == nil {
		return false, errors.New("Runtime not associated")
	}
	return i.runtime.controlRuntimeInstance(i, param)
}

// Unregister removes the instance from the runtime.
func (i *RuntimeInstance) Unregister() error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	if i.runtime == nil {
		return errors.New("Runtime not associated")
	}

	err := i.runtime.unregister(i)
	if err == nil {
		i.enabled = false
	}

	return err
}
