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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include "vif.h"
#include "packet.h"
#include "logger.h"

#define ENTITY_MASK_SLOTS	((VIF_MAX_INDEX + 63) / 64)
#define ENTITY_SLOT(i)		((i) / 64)
#define ENTITY_MASK(i)		((uint64_t)1 << ((i) % 64))
#define ENTITY_INDEX(s, o)	(((s) * 64) + (o))

struct vif_runtime {
	bool running;
	bool started;
	struct vif_entity *entities[VIF_MAX_INDEX];
	int max_entity_slot;
	uint64_t entities_set[ENTITY_MASK_SLOTS];
};

static inline void
vif_entity_add(struct vif_runtime *r, struct vif_entity *e) {
	int idx = e->vif - 1;
	r->entities[idx] = e;

	int slot = ENTITY_SLOT(idx);
	r->entities_set[slot] |= ENTITY_MASK(idx);

	// Fill MAC address of the interface
	rte_eth_macaddr_get(e->port_id, &e->self_addr);

	// expand slots to check if needed
	if (r->max_entity_slot < slot)
		r->max_entity_slot = slot;
}

static inline void
release_entity(struct vif_runtime *r, int idx) {
	struct vif_entity *e = r->entities[idx];
	if (e) {
		free(e->name);
		free(e);
	}
}

static inline void
vif_entity_delete(struct vif_runtime *r, vifindex_t vif) {
	int idx = vif - 1;
	release_entity(r, idx);
	r->entities[idx] = NULL;

	int slot = ENTITY_SLOT(idx);
	r->entities_set[slot] &= ~ENTITY_MASK(idx);

	// shrink slots to check if needed
	while (slot >= 0 && slot == r->max_entity_slot && r->entities_set[slot] == 0) {
		r->max_entity_slot--;
		slot--;
	}
}

#define CMD_DEFS(NAME) [VIF_CMD_ ## NAME] = #NAME

static inline void
process_requests(struct vif_runtime *vr, struct rte_ring *ring)
{
	static struct vif_request *reqs[VIF_MAX_REQUESTS];
	static const char *cmds[] = {
		CMD_DEFS(START),
		CMD_DEFS(STOP),
		CMD_DEFS(QUIT),
		CMD_DEFS(NEW),
		CMD_DEFS(DELETE),
	};

	unsigned req_count = rte_ring_dequeue_burst(ring, (void **)reqs, VIF_MAX_REQUESTS);
	for (int i = 0; i < req_count; i++) {
		struct vif_request *r = reqs[i];

		if (r->entity) {
			LAGOPUS_DEBUG("VIF: BE: %s VIF=%d, VRFID=%llx",
					cmds[r->cmd], r->entity->vif, r->entity->vrf);
		} else {
			LAGOPUS_DEBUG("VIF: BE: %s", cmds[r->cmd]);
		}

		switch (r->cmd) {
			case VIF_CMD_NEW:
				// Add new VIF
				vif_entity_add(vr, r->entity);
				break;
			case VIF_CMD_DELETE:
				// Delete VIF
				vif_entity_delete(vr, r->entity->vif);
				free(r->entity);
				break;
			case VIF_CMD_START:
				// Start tx/rx
				vr->started = true;
				break;
			case VIF_CMD_STOP:
				// Stop tx/rx
				vr->started = false;
				break;
			case VIF_CMD_QUIT:
				// quit
				LAGOPUS_DEBUG("VIF: BE: asked to terminate.");
				vr->started = false;
				vr->running = false;
				break;
		}

		free(r);
	}
}

int
vif_do_task(void *arg)
{
	struct vif_task_param *p = arg;
	struct rte_ring *requests = p->req;
	struct vif_runtime *r;
	struct rte_mbuf *mbufs[VIF_MBUF_LEN];

	LAGOPUS_DEBUG("VIF: BE: Starting bridge backend on slave core %u", rte_lcore_id());

	if (!(r = calloc(1, sizeof(struct vif_runtime)))) {
		LAGOPUS_DEBUG("VIF: BE: calloc() failed. Can't start.");
		return -1;
	}

	r->running = true;
	r->started = false;
	r->max_entity_slot = -1;

#ifdef DEBUG
	unsigned heartbeat;
	unsigned counter;
	unsigned nopackets;
#endif

	while (r->running) {
		for (int slot = 0; r->started && slot <= r->max_entity_slot; slot++) {
			uint64_t sets = r->entities_set[slot];
			while (sets) {
				int index = __builtin_ctzll(sets);
				sets &= ~((uint64_t)1 << index);
				struct vif_entity *e = r->entities[ENTITY_INDEX(slot, index)];

				// RX and process incoming packets
				uint16_t rx_count = rte_eth_rx_burst(e->port_id, e->rx_queue_id, mbufs, VIF_MBUF_LEN);
				e->rx_count += rx_count;
				if (rx_count > 0) {
					LAGOPUS_DEBUG("VIF: BE: Rcv'd %d packets on %d.", rx_count, index);
					for (int i = 0; i < rx_count; i++) {
						struct lagopus_packet_metadata *md = LAGOPUS_MBUF_METADATA(mbufs[i]);

						 // mark my vifindex, VRF and reset out_vif
						 md->md_vif.vrf = e->vrf;
						 md->md_vif.in_vif = e->vif;
						 md->md_vif.out_vif = 0;

						 // check if the packet is sent to me
						 struct ether_hdr *hdr = rte_pktmbuf_mtod(mbufs[i], struct ether_hdr *);

						 if (is_same_ether_addr(&hdr->d_addr, &e->self_addr)) {
							md->md_vif.flags |= LAGOPUS_MD_SELF;
						 } else {
							md->md_vif.flags &= ~LAGOPUS_MD_SELF;
						 }
					}
				}
#ifdef DEBUG
				counter += rx_count;
#endif

				// Queue incoming packets
				if (rx_count > 0) {
					unsigned sent = rte_ring_enqueue_burst(e->out_ring, (void * const*)mbufs, rx_count);
					LAGOPUS_DEBUG("VIF: BE: Fwd %d/%d packets for %d.", sent, rx_count, index);

					e->rx_dropped += rx_count - sent;
					while (unlikely (sent < rx_count)) {
						rte_pktmbuf_free(mbufs[sent]);
						sent++;
					}
				}

				// Dequeue outgoing packets
				unsigned tx_count = rte_ring_dequeue_burst(e->in_ring, (void **)mbufs, VIF_MBUF_LEN);
#ifdef DEBUG
				counter += tx_count;
#endif

				// TX outoing packets
				if (tx_count > 0) {
					unsigned sent = rte_eth_tx_burst(e->port_id, e->tx_queue_id, mbufs, tx_count);
					LAGOPUS_DEBUG("VIF: BE: Sent %d/%d packets for %d.", sent, tx_count, index);

					e->tx_count += sent;
					e->tx_dropped += tx_count - sent;
					while (unlikely (sent < tx_count)) {
						rte_pktmbuf_free(mbufs[sent]);
						sent++;
					}
				}
			}
		}
		// check if there's any control message from the frontend
		process_requests(r, requests);

#ifdef DEBUG
		heartbeat++;
		if (heartbeat == 10000000) {
			if (r->started) {
				if (counter == 0)
					nopackets++;
				else
					nopackets = 0;

				if (nopackets == 2) {
					nopackets = 0;
					struct rte_eth_stats stats;
					for (int i = 0; r->entities[i] != NULL && i < 4; i++) {
						struct vif_entity *e = r->entities[i];
						uint8_t port_id = e->port_id;
						rte_eth_stats_get(port_id, &stats);
						int rs = rte_eth_rx_queue_count(port_id, 0);
						int dd = rte_eth_rx_descriptor_done(port_id, 0, 0);
						LAGOPUS_DEBUG("VIF: BE: stats%d: pkts: %d/%d, bytes: %d/%d, err: %d/%d, nombuf: %d, qc=%d, dd=%d)", i,
							stats.ipackets, stats.opackets, stats.ibytes, stats.obytes, stats.ierrors, stats.oerrors, stats.rx_nombuf, rs, dd);
						rte_eth_stats_reset(port_id);
						LAGOPUS_DEBUG("VIF: BE: vif%d: rx %d (dropped %d), tx %d (dropped %d)", i,
								e->rx_count, e->rx_dropped, e->tx_count, e->tx_dropped);

					}
				}
			}

			LAGOPUS_DEBUG("VIF: BE: PING")
			heartbeat = 0;
			counter = 0;
		}
#endif
	}

	// Free resources
	for (int i = 0; i < VIF_MAX_INDEX; i++)
		release_entity(r, i);
	free(r);

	LAGOPUS_DEBUG("VIF: BE: terminated.");

	return 0;
}
