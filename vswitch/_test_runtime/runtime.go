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

package runtime

/*
#cgo CFLAGS: -I${SRCDIR}/../../include -I/usr/local/include/dpdk -m64 -pthread -O3 -msse4.2
#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all

#include <stdlib.h>
#include "runtime.h"
#include "logger.h"

#define MAX_INSTANCE 2

struct test_runtime {
	char *name;
	struct vsw_instance *instances[MAX_INSTANCE];
};

struct test_instance {
	struct vsw_instance base;
	struct rte_ring *o[1];
};

static void*
test_init(void *param) {
	struct test_runtime *r = calloc(1, sizeof(struct test_runtime));
	r->name = param;
	vsw_printf("%s: %s", __func__, r->name);
	return r;
}

static bool
test_process(void *priv) {
	static int x = 0;
	struct test_runtime *r = priv;
	if (x == 0)
		vsw_printf("%s: %s: called", __func__, r->name);
	for (int n = 0; n < MAX_INSTANCE; n++) {
		struct vsw_instance *i =  r->instances[n];
		if (i && i->enabled && x == 0) {
			vsw_printf("%s: %s: %s", __func__, r->name, i->name);
		}
	}
	x = (x + 1) % 100000;
	return true;
}

static void
test_deinit(void *priv) {
	struct test_runtime *r = priv;
	vsw_printf("%s: %s", __func__, r->name);
	free(r);
}

static bool
test_register_instance(void *priv, struct vsw_instance *instance) {
	struct test_runtime *r = priv;
	char *name = priv;
	vsw_printf("%s: %s (%s)", __func__, r->name, instance->name);

	for (int n = 0; n < MAX_INSTANCE; n++) {
		if (r->instances[n] == 0) {
			r->instances[n] = instance;
			return true;
		}
	}

	return false;
}

static bool
test_unregister_instance(void *priv, struct vsw_instance *instance) {
	struct test_runtime *r = priv;
	char *name = priv;
	vsw_printf("%s: %s (%s)", __func__, r->name, instance->name);

	for (int n = 0; n < MAX_INSTANCE; n++) {
		if (r->instances[n] == instance) {
			r->instances[n] = NULL;
			return true;
		}
	}

	return false;
}

static bool
test_control_instance(void *priv, struct vsw_instance *instance, void *param) {
	struct test_runtime *r = priv;
	char *name = priv;
	vsw_printf("%s: %s (%s)", __func__, r->name, instance->name);
	return true;
}

struct vsw_runtime_ops test_ops = {
	.init = test_init,
	.process = test_process,
	.deinit = test_deinit,
	.register_instance = test_register_instance,
	.unregister_instance = test_unregister_instance,
	.control_instance = test_control_instance,
};
*/
import "C"

import (
	"unsafe"

	"github.com/lagopus/vsw/dpdk"
)

func GetRuntimeParams(name string) (unsafe.Pointer, unsafe.Pointer) {
	return unsafe.Pointer(&C.test_ops), unsafe.Pointer(C.CString(name))
}

func NewRuntimeInstance(name string, input, output *dpdk.Ring) unsafe.Pointer {
	p := (*C.struct_test_instance)(C.malloc(C.sizeof_struct_test_instance))
	p.base.name = C.CString(name)
	p.base.input = (*C.struct_rte_ring)(unsafe.Pointer(input))
	p.base.outputs = &p.o[0]
	p.o[0] = (*C.struct_rte_ring)(unsafe.Pointer(output))
	return unsafe.Pointer(p)
}

func FreeRuntimeInstance(p unsafe.Pointer) {
	x := (*C.struct_vsw_instance)(p)
	C.free(unsafe.Pointer(x.name))
	C.free(p)
}
