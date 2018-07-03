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

#include <string.h>

#include <rte_malloc.h>
#include <rte_ring.h>

#include "scheduler.h"
#include "logger.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))


struct sched_rings {
	struct rte_ring *used;
	struct rte_ring *free;
};

struct sched_runtime {
	int id;
	char *name;
	struct lagopus_runtime_ops *ops;
	void *priv;
	bool enabled;
};

struct sched {
	struct sched_rings request;
	struct sched_rings result;
	struct sched_request requests[SCHED_MAX_REQUESTS];
	struct sched_result results[SCHED_MAX_REQUESTS * 2];

	struct sched_runtime runtime[SCHED_MAX_RUNTIMES];
	int runtime_count;
};

static inline struct sched_runtime *
sched_runtime_search(struct sched *s, int rid)
{
	for (int i = 0; i < s->runtime_count; i++) {
		if (s->runtime[i].id == rid)
			return &s->runtime[i];
	}
	return NULL;
}

static inline bool
sched_runtime_add(struct sched *s, struct sched_request *req)
{
	if (s->runtime_count == ARRAY_SIZE(s->runtime))
		return false;

	// sanity check
	struct lagopus_runtime_ops *ops = req->ops;
	if ((!ops->init) || (!ops->process) || (!ops->deinit) ||
	    (!ops->register_instance) || (!ops->unregister_instance) ||
	    (!ops->control_instance))
		return false;

	// init runtime
	void *p;
	if (!(p = ops->init(req->param))) {
		lagopus_printf("%s: Initializing runtime %s failed.", __func__, req->name);
		return false;
	}

	struct sched_runtime *r = &s->runtime[s->runtime_count++];
	r->id = req->rid;
	r->ops = ops;
	r->name = (req->name) ? strdup(req->name) : NULL;
	r->priv = p;

	return true;
}

static inline bool
sched_runtime_delete(struct sched *s, struct sched_runtime *r)
{
	// deinit runtime
	r->ops->deinit(r->priv);
	if (r->name)
		free(r->name);

	s->runtime_count--;
	size_t off = r - s->runtime;
	memmove(r, r + 1, sizeof(struct sched_runtime) * (s->runtime_count - off));
	return true;
}

/*
 * Sched_proc_requests() returns true if the scheduler should continue.
 * Returns false if the scheduler shall terminate.
 */
static inline bool
sched_proc_requests(struct sched *s)
{
	bool retval = true;
	void *reqs[ARRAY_SIZE(s->requests)];
	void *res[ARRAY_SIZE(s->requests)];

	// Dequeue request buffers
	unsigned count = rte_ring_sc_dequeue_burst(s->request.used, reqs, ARRAY_SIZE(reqs), NULL);
	if (count == 0)
		return true;

	// Dequeue result buffers
	if (rte_ring_sc_dequeue_bulk(s->result.free, res, count, NULL) != count) {
		lagopus_fatalf("%s: Couldn't allocate enough result buffers. (%d)", __func__, count);
		return false;
	}

	for (int i = 0; i < count; i++) {
		struct sched_request *req = reqs[i];
		struct sched_result *rc = res[i];
		struct sched_runtime *r = sched_runtime_search(s, req->rid);

		rc->seqno = req->seqno;
		rc->res = false;

		// Pre-check
		switch (req->cmd) {
		// Runtime shall not exist
		case SCHED_CMD_ADD_RUNTIME:
			if (r) continue;
			break;

		// Don't care about runtime
		case SCHED_CMD_TERMINATE:
			break;

		// Runtime shall exist
		default:
			if (!r) continue;
		}

		// Do process
		switch (req->cmd) {
		case SCHED_CMD_ADD_RUNTIME:
			rc->res = sched_runtime_add(s, req);
			break;
		case SCHED_CMD_DELETE_RUNTIME:
			rc->res = sched_runtime_delete(s, r);
			break;
		case SCHED_CMD_ENABLE_RUNTIME:
			r->enabled = req->enabled;
			rc->res = req->enabled;
			break;

		case SCHED_CMD_ADD_INSTANCE:
			rc->res = r->ops->register_instance(r->priv, req->ins);
			break;
		case SCHED_CMD_DELETE_INSTANCE:
			rc->res = r->ops->unregister_instance(r->priv, req->ins);
			break;
		case SCHED_CMD_ENABLE_INSTANCE:
			req->ins->enabled = req->enabled;
			rc->res = req->enabled;
			break;
		case SCHED_CMD_CONTROL_INSTANCE:
			rc->res = r->ops->control_instance(r->priv, req->ins, req->param);
			break;

		case SCHED_CMD_TERMINATE:
			retval = false;
			rc->res = true;
			break;

		default:
			lagopus_fatalf("%s: Unknown command: %d", __func__, req->cmd);
		}
	}

	// Free up requests
	if (rte_ring_sp_enqueue_bulk(s->request.free, reqs, count, NULL) != count) {
		lagopus_fatalf("%s: Couldn't requeue freed request buffers. (%d)", __func__, count);
		return false;
	}

	// Enqueue results
	if (rte_ring_sp_enqueue_bulk(s->result.used, res, count, NULL) != count) {
		lagopus_fatalf("%s: Couldn't enqueue results. (%d)", __func__, count);
		return false;
	}

	return retval;
}

static inline void
sched_exec_runtime(struct sched *s)
{
	for (int i = 0; i < s->runtime_count; i++) {
		struct sched_runtime *r = &s->runtime[i];

		if (!r->enabled)
			continue;

		if (!r->ops->process(r->priv)) {
			lagopus_printf("%s: Runtime %s (%lu) failed. Disabling.", __func__, r->name, r->id);
			r->enabled = false;
		}
	}
}

static inline void
sched_terminate_runtime(struct sched *s)
{
	for (int i = 0; i < s->runtime_count; i++) {
		struct sched_runtime *r = &s->runtime[i];
		r->ops->deinit(r->priv);
		if (r->name)
			free(r->name);
	}
	s->runtime_count = 0;
}


/*
 * sched_main() is launched on each slave lcore.
 */
int
sched_main(void *arg)
{
	struct sched_arg *sa = arg;
	struct sched *sched;
	void *objp[SCHED_MAX_REQUESTS * 2];

	if (!(sched = rte_zmalloc(NULL, sizeof(struct sched), 0))) {
		LAGOPUS_DEBUG("%s: Can't allocate memory for scheduler", __func__);
		return -1;
	}

	sched->request.used = sa->request;
	sched->request.free = sa->request_free;
	sched->result.used = sa->result;
	sched->result.free = sa->result_free;
	free(sa);

	// Queue requets and results to free rings
	struct sched_request *reqs = sched->requests;
	int n = ARRAY_SIZE(sched->requests);
	for (int i = 0; i < n; i++)
		objp[i] = reqs + i;
	rte_ring_sp_enqueue_burst(sched->request.free, objp, n, NULL);

	struct sched_result *res = sched->results;
	n = ARRAY_SIZE(sched->results);
	for (int i = 0; i < n; i++)
		objp[i] = res + i;
	rte_ring_sp_enqueue_burst(sched->result.free, objp, n, NULL);

	// Ready to go
	while (sched_proc_requests(sched)) {
		// Invoke all enabled runtime
		sched_exec_runtime(sched);
	}

	// Terminate the scheduler
	sched_terminate_runtime(sched);
	rte_free(sched);

	return 0;
}
