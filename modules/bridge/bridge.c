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
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_errno.h>

//#define DEBUG
#include "packet.h"
#include "logger.h"

#include "bridge.h"

struct bridge_runtime {
	char			*name;
	struct rte_hash		*bridge_hash;
	struct bridge_learn	*learning;
	bool			running;
};

#define ETHADDR_STRLEN 18

static inline void *
etheraddr2str(char *str, size_t len, struct ether_addr *addr)
{
	snprintf(str, len, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr->addr_bytes[0], addr->addr_bytes[1], addr->addr_bytes[2],
		addr->addr_bytes[3], addr->addr_bytes[4], addr->addr_bytes[5]);
	return str;
}

static inline bool
dispatch_packet(struct bridge_domain *bd, uint32_t domain_id, struct rte_mbuf *mbuf)
{
	struct lagopus_packet_metadata *md = LAGOPUS_MBUF_METADATA(mbuf);
	struct ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	struct ether_addr *saddr = &hdr->s_addr;
	struct ether_addr *daddr = &hdr->d_addr;
	struct rte_ring *ring = NULL;
	vifindex_t out_vif = md->md_vif.out_vif;

	// Mark my domain ID
	md->md_vif.bridge_id = domain_id;

	if ((bd->r.tap) && hdr->ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP)) {
		LAGOPUS_DEBUG("%s: BE: ether type arp", bd->name);
		ring = bd->r.tap;
	} else if (((md->md_vif.flags & LAGOPUS_MD_SELF) || is_multicast_ether_addr(daddr)) && bd->r.output) {
		// If the packet is sent to me, then the packet should be forwarded to
		// the default module, e.g. L3.
		md->md_vif.flags &= ~LAGOPUS_MD_SELF;
		ring = bd->r.output;
	} else if (out_vif != 0 && rte_hash_lookup_data(bd->vif_hash, &out_vif, (void **)&ring) < 0) {
		lagopus_fatalf("%s: BE: Unknown VIF: %d", bd->name, out_vif);
		return false;
	} else if (rte_hash_lookup_data(bd->mac_hash, daddr, (void **)&ring) < 0) {
		// flooding
		uint32_t next = 0;
		vifindex_t *vif;

		while (rte_hash_iterate(bd->vif_hash, (const void**)&vif, (void**)&ring, &next) >= 0) {
			if (rte_ring_enqueue(ring, mbuf) == 0)
				rte_pktmbuf_refcnt_update(mbuf, 1);
		}
		// We have one refcnt too much after iteration.
		rte_pktmbuf_free(mbuf);

		return true;
	}
	// We now should have a ring to queue.
	if (rte_ring_enqueue(ring, mbuf) != 0)
		rte_pktmbuf_free(mbuf);

	return true;
}

uint32_t
bridge_domain_hash_func(const void *key, uint32_t length, uint32_t initval)
{
	const uint32_t *k = key;
	return rte_jhash_1word(k[0], initval);
}

uint32_t
mac_entry_hash_func(const void *key, uint32_t length, uint32_t initval)
{
	const uint16_t *k = key;
	return rte_jhash_2words(k[0] << 16 | k[1], k[2], initval);
}

/* Bridge Domain Related */
static inline void
bridge_free_domain_info(struct bridge_domain *bd) {
	if (bd->mac_hash)
		rte_hash_free(bd->mac_hash);
	if (bd->vif_hash)
		rte_hash_free(bd->vif_hash);
	free(bd->name);
	free(bd);
}

static inline void
bridge_domain_config(struct bridge_runtime *b, struct bridge_domain *bd, struct bridge_request *r) {
	struct rte_hash *mac_hash;
	char hash_name[128];

	if (bd->mac_hash)
		rte_hash_free(bd->mac_hash);

	snprintf(hash_name, sizeof(hash_name), "%s-MAC", bd->name);
	struct rte_hash_parameters mac_hash_params = {
		.name = hash_name,
		.entries = r->config.max_mac_entry,
		.key_len = sizeof(struct ether_addr),
		.hash_func = mac_entry_hash_func,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	if ((bd->mac_hash = rte_hash_create(&mac_hash_params)) == NULL) {
		LAGOPUS_DEBUG("%s: hash param %d, %d\n", b->name, mac_hash_params.key_len, mac_hash_params.entries);
		LAGOPUS_DEBUG("%s: BE: Can't create a MAC hash for domain %s (%s)\n",
				b->name, bd->name, rte_strerror(rte_errno));
		bridge_free_domain_info(bd);
		return;
	}
}

static inline void
bridge_domain_add(struct bridge_runtime *b, struct bridge_request *r) {
	struct bridge_domain *bd = r->domain;
	char hash_name[128];

	// create MAC Hash
	bridge_domain_config(b, bd, r);

	snprintf(hash_name, sizeof(hash_name), "%s-VIF", bd->name);
	struct rte_hash_parameters vif_hash_params = {
		.name = hash_name,
		.entries = MAX_BRIDGE_VIFS,
		.key_len = sizeof(vifindex_t),
		.hash_func = bridge_domain_hash_func,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	if ((bd->vif_hash = rte_hash_create(&vif_hash_params)) == NULL) {
		LAGOPUS_DEBUG("%s: BE: Can't create a VIF hash for domain %s\n", b->name, bd->name);
		bridge_free_domain_info(bd);
		return;
	}

	//if (rte_hash_add_key_with_hash_data(b->bridge_hash, &r->domain_id, r->domain_hsig, bd) < 0) {
	if (rte_hash_add_key_data(b->bridge_hash, &r->domain_id, bd) < 0) {
		LAGOPUS_DEBUG("%s: BE: Can't add domain %s\n", b->name, bd->name);
		bridge_free_domain_info(bd);
	}
}

static inline void
bridge_domain_delete(struct bridge_runtime *b, struct bridge_domain *bd, struct bridge_request *r) {
	//if (rte_hash_del_key_with_hash(b->bridge_hash, &r->domain_id, r->domain_hsig) < 0)
	if (rte_hash_del_key(b->bridge_hash, &r->domain_id) < 0)
		LAGOPUS_DEBUG("%s: BE: Can't delete domain %s\n", b->name, bd->name);
	bridge_free_domain_info(bd);
}

static inline void
bridge_config_ring(struct bridge_runtime *b, struct bridge_domain *bd, struct bridge_request *r) {
	bd->r = r->ring;
}

/* VIF Related */
static inline void
bridge_vif_add(struct bridge_runtime *b, struct bridge_domain *bd, struct bridge_request *r) {
	// add to the hash
	//if (rte_hash_add_key_with_hash_data(bd->vif_hash, &r->vif.index, r->vif.hsig, r->vif.ring) < 0)
	if (rte_hash_add_key_data(bd->vif_hash, &r->vif.index, r->vif.ring) < 0)
		LAGOPUS_DEBUG("%s: BE: Can't add VIF index %u to %s\n", b->name, r->vif.index, bd->name);
}

static inline void
bridge_vif_delete(struct bridge_runtime *b, struct bridge_domain *bd, struct bridge_request *r) {
	// remove from the hash
	//if (rte_hash_del_key_with_hash(bd->vif_hash, &r->vif.index, r->vif.hsig) < 0)
	if (rte_hash_del_key(bd->vif_hash, &r->vif.index) < 0)
		LAGOPUS_DEBUG("%s: BE: Can't delete VIF index %u from %s\n", b->name, r->vif.index, bd->name);
}

/* MAC Related */
static inline void
bridge_mac_add(struct bridge_runtime *b, struct bridge_domain *bd, struct bridge_request *r) {
	//if (rte_hash_add_key_with_hash_data(bd->mac_hash, r->mac.mac, r->mac.hsig, r->mac.ring) < 0)
	if (rte_hash_add_key_data(bd->mac_hash, &r->mac.mac, r->mac.ring) < 0)
		LAGOPUS_DEBUG("%s: BE: Can't add MAC entry to %s\n", b->name, bd->name);
}

static inline void
bridge_mac_delete(struct bridge_runtime *b, struct bridge_domain *bd, struct bridge_request *r) {
	if (rte_hash_del_key(bd->mac_hash, &r->mac.mac) < 0)
		LAGOPUS_DEBUG("%s: BE: Can't delete MAC entry from %s\n", b->name, bd->name);
}

#define CMD_DEFS(NAME)	[BRIDGE_CMD_ ## NAME] = #NAME

static inline void
process_requests(struct bridge_runtime *b, struct rte_ring *ring)
{
	static struct bridge_request *reqs[MAX_BRIDGE_REQUESTS];
	const char *cmds[] = {
		CMD_DEFS(DOMAIN_ADD),
		CMD_DEFS(DOMAIN_DELETE),
		CMD_DEFS(DOMAIN_ENABLE),
		CMD_DEFS(DOMAIN_DISABLE),
		CMD_DEFS(DOMAIN_CONFIG),
		CMD_DEFS(CONFIG_RING),
		CMD_DEFS(VIF_ADD),
		CMD_DEFS(VIF_DELETE),
		CMD_DEFS(MAC_ADD),
		CMD_DEFS(MAC_DELETE),
		CMD_DEFS(QUIT)
	};
	unsigned req_count = rte_ring_dequeue_burst(ring, (void **)reqs, MAX_BRIDGE_REQUESTS);
	for (int i = 0; i < req_count; i++) {
		struct bridge_request *r = reqs[i];
		struct bridge_domain *bd;

		LAGOPUS_DEBUG("%s: BE: %s DOMAINID=%x", b->name, cmds[r->cmd], r->domain_id);

		// pre-check
		switch (r->cmd) {
			case BRIDGE_CMD_DOMAIN_ADD:
			case BRIDGE_CMD_QUIT:
				break;
			default:
				if (rte_hash_lookup_data(b->bridge_hash, &r->domain_id, (void **)&bd) < 0) {
					LAGOPUS_DEBUG("%s: BE: Can't find domain ID %u. Skipping.\n", b->name, r->domain_id);
					continue;
				}
		}

		switch (r->cmd) {
			case BRIDGE_CMD_DOMAIN_ADD:
				bridge_domain_add(b, r);
				break;

			case BRIDGE_CMD_DOMAIN_DELETE:
				bridge_domain_delete(b, bd, r);
				break;

			case BRIDGE_CMD_DOMAIN_ENABLE:
				bd->active = true;
				break;

			case BRIDGE_CMD_DOMAIN_DISABLE:
				bd->active = false;
				break;

			case BRIDGE_CMD_DOMAIN_CONFIG:
				bridge_domain_config(b, bd, r);
				break;

			case BRIDGE_CMD_CONFIG_RING:
				bridge_config_ring(b, bd, r);
				break;

			case BRIDGE_CMD_VIF_ADD:
				bridge_vif_add(b, bd, r);
				break;

			case BRIDGE_CMD_VIF_DELETE:
				bridge_vif_delete(b, bd, r);
				break;

			case BRIDGE_CMD_MAC_ADD:
				bridge_mac_add(b, bd, r);
				break;

			case BRIDGE_CMD_MAC_DELETE:
				bridge_mac_delete(b, bd, r);
				break;

			case BRIDGE_CMD_QUIT:
				LAGOPUS_DEBUG("%s: BE: asked to terminate.", b->name);
				b->running = false;
				break;
		}

		free(r);
	}
}

static int
init_mac_learning(struct bridge_runtime *b, struct rte_ring *used, struct rte_ring *free)
{
	unsigned count = rte_ring_free_count(used);
	if (count == 0 && count != rte_ring_free_count(free)) {
		LAGOPUS_DEBUG("%s: BE: Ring sizes for learning don't match. Must be equal.", b->name)
		return -1;
	}

	size_t size = sizeof(struct bridge_learn) * count;
	if (!(b->learning = rte_zmalloc(NULL, size, 0))) {
		LAGOPUS_DEBUG("%s: BE: rte_zmalloc() failed. Can't alloc memory for learning (%d/%d).", b->name, size, count);
		return -1;
	}

	for (int i = 0; i < count; i++) {
		rte_ring_enqueue(free, &b->learning[i]);
	}

	return 0;
}

void
cleanup(struct bridge_runtime *b)
{
	uint32_t next = 0;
	uint32_t *domain_id;
	struct bridge_domain *domain;

	while (rte_hash_iterate(b->bridge_hash, (const void **)&domain_id, (void **)&domain, &next) >= 0) {
		rte_hash_free(domain->vif_hash);
		rte_hash_free(domain->mac_hash);
	}
	rte_hash_free(b->bridge_hash);

	if (b->learning)
		rte_free(b->learning);

	if (b->name)
		free(b->name);

	rte_free(b);
}

int
bridge_task(void *arg)
{
	struct bridge_launch_param *p = arg;
	struct rte_ring *from_frontend = p->request;
	struct rte_ring *used_macl = p->used; // Mac learning containers sent to the frontend
	struct rte_ring *free_macl = p->free; // Mac learning containers available
	struct rte_mbuf *mbufs[MAX_BRIDGE_MBUFS];
	struct bridge_runtime *b;

	LAGOPUS_DEBUG("%s: BE: Starting bridge backend on slave core %u", p->name, rte_lcore_id());

	if (!(b = rte_zmalloc(NULL, sizeof(struct bridge_runtime), 0))) {
		LAGOPUS_DEBUG("%s: BE: rte_zmalloc() failed. Can't start.", p->name);
		return -1;
	}

	// Create hash table for bridge domain
	struct rte_hash_parameters hash_params = {
		.name = p->name,
		.entries = MAX_BRIDGE_DOMAINS,
		.key_len = sizeof(uint32_t),
		.hash_func = bridge_domain_hash_func,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};
	b->bridge_hash = rte_hash_create(&hash_params);
	b->name = p->name;
	free(p);

	if  (init_mac_learning(b, used_macl, free_macl) != 0) {
		cleanup(b);
		return -1;
	}

	// Start
	b->running = true;
	while (b->running) {
		uint32_t next = 0;
		uint32_t *domain_id;
		struct bridge_domain *domain;

		while (rte_hash_iterate(b->bridge_hash, (const void **)&domain_id, (void **)&domain, &next) >= 0) {
			// Skip if the bridge domain is not ready yet.
			if (!domain->active)
				continue;

			//
			// Packets from VIF first
			//
			unsigned count = rte_ring_dequeue_burst(domain->r.vif_input, (void **)mbufs, MAX_BRIDGE_MBUFS);

			for (int i = 0; i < count; i++) {
				// Extract src mac from the packet
				struct bridge_learn *l;
				if (rte_ring_dequeue(free_macl, (void**)&l) == 0) {
					struct lagopus_packet_metadata *md = LAGOPUS_MBUF_METADATA(mbufs[i]);
					struct ether_hdr *hdr = rte_pktmbuf_mtod(mbufs[i], struct ether_hdr *);

					l->domain_id = *domain_id;
					l->index = md->md_vif.in_vif;
					ether_addr_copy(&hdr->s_addr, &l->mac);

					rte_ring_enqueue(used_macl, (void*)l);
				}

				if (!dispatch_packet(domain, *domain_id, mbufs[i])) {
					LAGOPUS_DEBUG("%s: BE: dispatch failed.", b->name);
				}
			}

			//
			// Packets from non-VIF (no need to learn)
			//
			if (domain->r.input) {
				count = rte_ring_dequeue_burst(domain->r.input, (void **)mbufs, MAX_BRIDGE_MBUFS);
				if (count > 0) {
					LAGOPUS_DEBUG("%s: BE: %d mbuf(s)\n", domain->name, count);
				}
				for (int i = 0; i < count; i++) {
					if (!dispatch_packet(domain, *domain_id, mbufs[i])) {
						LAGOPUS_DEBUG("%s: BE: dispatch failed.", b->name);
					}
				}
			}
		}

		// check if there's any control message from the frontend
		process_requests(b, from_frontend);
	}

	// Clean up
	cleanup(b);
}
