/*
 * Copyright 2017 Nippon Telegraph and Telephone Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LAGOPUS_SCHEDULER_H_
#define LAGOPUS_SCHEDULER_H_

#include "runtime.h"

#include <stdbool.h>
#include <stdint.h>
#include <rte_ring.h>

struct sched_arg {
	struct rte_ring *request;
	struct rte_ring *request_free;
	struct rte_ring *result;
	struct rte_ring *result_free;
};


typedef enum {
	SCHED_CMD_ADD_RUNTIME,
	SCHED_CMD_DELETE_RUNTIME,
	SCHED_CMD_ENABLE_RUNTIME,

	SCHED_CMD_ADD_INSTANCE,
	SCHED_CMD_DELETE_INSTANCE,
	SCHED_CMD_ENABLE_INSTANCE,
	SCHED_CMD_CONTROL_INSTANCE,

	SCHED_CMD_TERMINATE,

	SCHED_CMD_END
} sched_cmd_t;

struct sched_request {
	sched_cmd_t cmd;
	uint64_t seqno;		// Unique command sequence #
	int rid;		// Unique Runtime ID
	char *name;		// Human readable name of the runtime (used when adding)
	struct lagopus_runtime_ops *ops;
	struct lagopus_instance *ins;
	void *param;
	bool enabled;
};

struct sched_result {
	uint64_t seqno;
	bool res;
};

// Max # of requests that Go can submit to C scheduler at once.
#define SCHED_MAX_REQUESTS 128

// Max # of reuntime instances per lcore
#define SCHED_MAX_RUNTIMES 16

// Scheduler main routine
extern int sched_main(void *arg);

#endif /* LAGOPUS_SCHEDULER_H_ */
