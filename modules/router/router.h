/*
 * Copyright 2017-2019 Nippon Telegraph and Telephone Corporation.
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

#ifndef VSW_MODULES_ROUTER_H_
#define VSW_MODULES_ROUTER_H_

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "interface.h"
#include "neighbor.h"
#include "route.h"
#include "router_common.h"
#include "router_log.h"

#define MAX_ROUTER_REQUESTS 1024

// check packet header
#define VERSION_IPV4 0x04
#define VERSION_IPV6 0x06

#define ROUTER_RULE_MAX 32

#define MAX_RECORDROUTE_OPTIONS 2

// Router Runtime
struct router_mempools {
	struct rte_mempool *direct_pool;
	struct rte_mempool *indirect_pool;
};

static inline struct router_ring*
get_router_ring(struct router_context *ctx, struct rte_ring *ring) {
	if (!ring)
		return NULL;

	struct router_ring *free_rr = NULL;
	for (int i = 0; i < MAX_ROUTER_VIFS + 1; i++) {
		struct router_ring *rr = &ctx->router_ring[i];

		if (rr->ring == ring) {
			rr->rc++;
			return rr;
		}

		if (free_rr == NULL && rr->ring == NULL)
			free_rr = rr;
	}

	if (!free_rr)
		return NULL;

	free_rr->ring = ring;
	free_rr->rc++;

	ctx->rrp[ctx->rr_count] = free_rr;
	ctx->rr_count++;

	return free_rr;
}

static inline void
put_router_ring(struct router_context *ctx, struct router_ring *rr) {
	if (!rr)
		return;

	rr->rc--;
	if (rr->rc > 0)
		return;

	rr->ring = NULL;

	for (int i = 0; i < ctx->rr_count; i++) {
		if (ctx->rrp[i] == rr) {
			ctx->rr_count--;
			ctx->rrp[i] = ctx->rrp[ctx->rr_count];
			rr->sent = rr->dropped = 0;
		}
	}
}

static inline void
mbuf_flush(struct router_ring *rr) {
	unsigned sent = rte_ring_enqueue_burst(rr->ring, (void * const*)rr->mbufs, rr->count, NULL);
	rr->sent += sent;
	rr->dropped += (rr->count - sent);
	if (sent < rr->count) {
		ROUTER_DEBUG("Enqueued partially: %d/%d (%s)", sent, rr->count, rr->ring->name);
		while (unlikely (sent < rr->count)) {
			rte_pktmbuf_free(rr->mbufs[sent]);
			sent++;
		}
	}
	rr->count = 0;
}

static inline void
mbuf_prepare_enqueue(struct router_ring *rr, struct rte_mbuf *mbuf) {
	rr->mbufs[rr->count] = mbuf;
	rr->count++;

	if (rr->count == MAX_ROUTER_MBUFS)
		mbuf_flush(rr);
}

#endif /* VSW_MODULES_ROUTER_H_ */
