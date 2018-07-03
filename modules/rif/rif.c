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
#include <rte_ether.h>

//#define DEBUG
#include "logger.h"
#include "rif.h"
#include "packet.h"

static void rif_proc_trunk(struct rte_mempool *, struct rif_instance *, struct rte_mbuf **, int);
static void rif_proc_access(struct rte_mempool *, struct rif_instance *, struct rte_mbuf **, int);

#define RIF_DEFAULT_RIFS_CAP 256

struct rif_runtime {
	struct rif_instance **rifs;
	struct rte_mempool *pool;
	int rifs_cap;
	int rifs_len;
};

static bool
rif_register_instance(void *p, struct lagopus_instance *base)
{
	struct rif_runtime *r = p;
	struct rif_instance *i = (struct rif_instance*)base;

	// Reallocate RIFs array safely.
	if (r->rifs_len + 1 > r->rifs_cap) {
		int cap = r->rifs_cap * 2;
		struct rif_instance **rifs = calloc(1, sizeof(struct rif_instance*) * cap);

		if (rifs == NULL) {
			LAGOPUS_DEBUG("RIF: Failed to resize rif_instance place holder");
			return false;
		}

		memcpy(rifs, r->rifs, sizeof(struct rif_instance*) * r->rifs_cap);
		free(r->rifs);
		r->rifs = rifs;
		r->rifs_cap = cap;
	}
	r->rifs[r->rifs_len] = i;
	r->rifs_len++;

	for (int n = 0; n < MAX_VID; n++)
		i->index[n] = VIF_INVALID_INDEX;

	memset(i->fwd, 0, sizeof(i->fwd));
	memset(i->fwd_type, 0, sizeof(i->fwd_type));

	i->proc = rif_proc_access;

	return true;
}

static bool
rif_unregister_instance(void *p, struct lagopus_instance *base)
{
	struct rif_runtime *r = p;
	struct rif_instance *i = (struct rif_instance*)base;

	for (int n = 0; n < r->rifs_len; n++) {
		if (r->rifs[n] == i) {
			r->rifs[n] = r->rifs[r->rifs_len - 1];
			r->rifs_len--;
			return true;
		}
	}

	return false;
}

static inline bool
rif_update_forward_table(struct rif_instance *i, struct rif_control_param *ep, fwd_type_t type) {
	if (ep->output != NULL) {
		// Any matching packets shall be forwarded to the same ring (e.g. router)
		if (!i->fwd[ep->vid]) {
			i->fwd[ep->vid] = ep->output;
		} else if (i->fwd[ep->vid] != ep->output) {
			return false;
		}

		i->fwd_type[ep->vid] |= type;
	} else {
		i->fwd_type[ep->vid] &= ~type;
		if (i->fwd_type[ep->vid] == RIF_FWD_TYPE_DEFAULT)
			i->fwd[ep->vid] = NULL;
	}
	return true;
}

static bool
rif_control_instance(void *p, struct lagopus_instance *base, void *param)
{
	struct rif_runtime *r = p;
	struct rif_control_param *ep = param;
	struct rif_instance *i = (struct rif_instance*)base;

	LAGOPUS_DEBUG("%s: name=%s cmd=%d vid=%d output=%p\n", __func__, base->name, ep->cmd, ep->vid, ep->output);

	switch (ep->cmd) {
	case RIF_CMD_ADD_VID:
		i->base.outputs[ep->vid] = ep->output;
		i->index[ep->vid] = ep->index;
		if (!i->trunk)
			i->vid = ep->vid;
		return true;
	case RIF_CMD_DELETE_VID:
		i->base.outputs[ep->vid] = NULL;
		i->index[ep->vid] = VIF_INVALID_INDEX;
		if (!i->trunk)
			i->vid = 0;
		return true;
	case RIF_CMD_SET_MTU:
		i->mtu = ep->mtu;
		return true;
	case RIF_CMD_SET_MAC:
		ether_addr_copy(ep->mac, &i->self_addr);
		return true;
	case RIF_CMD_SET_TRUNK_MODE:
		i->proc = rif_proc_trunk;
		i->trunk = true;
		return true;
	case RIF_CMD_SET_ACCESS_MODE:
		i->proc = rif_proc_access;
		i->trunk = false;
		return true;
	case RIF_CMD_SET_DST_SELF_FORWARD:
		return rif_update_forward_table(i, ep, RIF_FWD_TYPE_SELF);
	case RIF_CMD_SET_DST_BC_FORWARD:
		return rif_update_forward_table(i, ep, RIF_FWD_TYPE_BC);
	case RIF_CMD_SET_DST_MC_FORWARD:
		return rif_update_forward_table(i, ep, RIF_FWD_TYPE_MC);
	}
	return false;
}

static inline struct rte_mbuf*
dup_mbuf(struct rte_mempool *mp, struct rte_mbuf *mbuf)
{
	struct rte_mbuf *new_mbuf = rte_pktmbuf_alloc(mp);

	// copy common metadata section
	memcpy(LAGOPUS_MBUF_METADATA(new_mbuf), LAGOPUS_MBUF_METADATA(mbuf), sizeof(struct vif_metadata));

	// attach to the original mbuf
	rte_pktmbuf_attach(new_mbuf, mbuf);
	rte_pktmbuf_free(mbuf);

	return new_mbuf;
}

static inline fwd_type_t
rif_mark_and_check_next_module(struct rte_mbuf *mbuf, struct ether_addr *self, vifindex_t index)
{
	struct lagopus_packet_metadata *md = LAGOPUS_MBUF_METADATA(mbuf);
	vifindex_t out_vif = md->md_vif.out_vif;

	md->md_vif.in_vif  = index;
	md->md_vif.out_vif = VIF_INVALID_INDEX;

	if (out_vif == index)
		return RIF_FWD_TYPE_DEFAULT;

	// check if the packet is sent to me
	fwd_type_t fwd = RIF_FWD_TYPE_DROP;
	struct ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

	if (is_same_ether_addr(&hdr->d_addr, self)) {
		md->md_vif.flags |= LAGOPUS_MD_SELF;
		fwd = RIF_FWD_TYPE_SELF;
	} else {
		md->md_vif.flags &= ~LAGOPUS_MD_SELF;

		if (is_multicast_ether_addr(&hdr->d_addr))
			fwd = RIF_FWD_TYPE_MC;
		else if (is_broadcast_ether_addr(&hdr->d_addr))
			fwd = RIF_FWD_TYPE_BC;
	}

	return fwd;
}

static void
rif_proc_trunk(struct rte_mempool *mp, struct rif_instance *e, struct rte_mbuf **mbufs, int count)
{
	uint16_t vid = e->vid;
	vifindex_t *index = e->index;
	struct rte_ring **outputs = e->base.outputs;
	struct rte_ring **fwd = e->fwd;
	fwd_type_t *ft = e->fwd_type;

	struct ether_addr *self_addr = &e->self_addr;

	// TRUNK Mode
	for (int i = 0; i < count; i++) {
		struct rte_mbuf *mbuf = mbufs[i];
		uint16_t vlan_id = mbuf->vlan_tci & 0xfff;
		struct rte_ring *output = outputs[vlan_id];
		bool enqueued = false;

		// XXX: We shall optimize packets forwarding. Queueing packets one-by-one
		// is not optimal.
		if ((mbuf->pkt_len <= e->mtu) && (output)) {
			if (rte_mbuf_refcnt_read(mbuf) > 1)
				mbuf = dup_mbuf(mp, mbuf);

			fwd_type_t t = rif_mark_and_check_next_module(mbuf, self_addr, index[vlan_id]);
			if (t & ft[vlan_id])
				output = fwd[vlan_id];
			if (t != RIF_FWD_TYPE_DROP)
				enqueued = (rte_ring_enqueue(output, mbuf) == 0);
		}

		if (enqueued) {
			e->count++;
		} else {
			rte_pktmbuf_free(mbuf);
			e->dropped++;
		}
	}
}

static inline void
rif_free_mbufs(struct rte_mbuf **mbufs, unsigned count, unsigned sent)
{
	while (unlikely (sent < count)) {
		rte_pktmbuf_free(mbufs[sent]);
		sent++;
	}
}

static void
rif_proc_access(struct rte_mempool *mp, struct rif_instance *e, struct rte_mbuf **mbufs, int count)
{
	struct rte_mbuf *any_mbufs[RIF_MBUF_LEN]; // FIXME
	struct rte_mbuf *fwd_mbufs[RIF_MBUF_LEN]; // FIXME

	uint16_t vid = e->vid;
	vifindex_t index = e->index[vid];
	struct rte_ring *output = e->base.outputs[vid];
	struct rte_ring *fwd_output = e->fwd[vid];
	fwd_type_t ft = e->fwd_type[vid];

	struct ether_addr *self_addr = &e->self_addr;

	unsigned any_count = 0;
	unsigned fwd_count = 0;

	for (int i = 0; i < count; i++) {
		struct rte_mbuf *mbuf = mbufs[i];
		struct ether_hdr *eh = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

		// drop following packets
		// - w/o appropriate VLAN ID
		// - exceeding MTU
		if ((mbuf->pkt_len > e->mtu) ||
		    (mbuf->vlan_tci & 0xfff != vid)) {
			rte_pktmbuf_free(mbuf);
			e->dropped++;
			continue;
		}

		if (rte_mbuf_refcnt_read(mbuf) > 1)
			mbuf = dup_mbuf(mp, mbuf);

		fwd_type_t t = rif_mark_and_check_next_module(mbuf, self_addr, index);
		if (t == RIF_FWD_TYPE_DEFAULT)  {
			// router -> bridge
			any_mbufs[any_count++] = mbuf;
		} else if (t & ft) {
			// bridge -> router
			fwd_mbufs[fwd_count++] = mbuf;
		} else {
			// drop
			rte_pktmbuf_free(mbuf);
			e->dropped++;
		}
	}

	// Queue incoming packets at once for ACCESS Mode
	unsigned any_sent = 0;
	unsigned fwd_sent = 0;

	if ((output) && any_count > 0)
		any_sent = rte_ring_enqueue_burst(output, (void * const*)any_mbufs, any_count, NULL);
	if ((fwd_output) && fwd_count > 0)
		fwd_sent = rte_ring_enqueue_burst(fwd_output, (void * const*)fwd_mbufs, fwd_count, NULL);

	unsigned total_sent = any_sent + fwd_sent;

	LAGOPUS_DEBUG("RIF: Rcv'd %d/%d packets.", total_sent, count);

	e->count += total_sent;
	e->dropped += count - total_sent;

	rif_free_mbufs(any_mbufs, any_count, any_sent);
	rif_free_mbufs(fwd_mbufs, fwd_count, fwd_sent);
}

static void*
rif_init(void *param)
{
	struct rif_runtime *r;
	struct rif_runtime_param *p = param;
	char pool_name[RTE_MEMZONE_NAMESIZE];

	if (!(r = calloc(1, sizeof(struct rif_runtime)))) {
		LAGOPUS_DEBUG("RIF: calloc() failed. Can't start.");
		return NULL;
	}

	r->rifs_cap = RIF_DEFAULT_RIFS_CAP;
	if (!(r->rifs = calloc(1, sizeof(struct rif_instance*) * r->rifs_cap))) {
		LAGOPUS_DEBUG("RIF: calloc() failed. Can't start.");
		goto error;
	}

	snprintf(pool_name, RTE_MEMZONE_NAMESIZE, "rif-md-pool-%d", rte_lcore_id());
	r->pool = rte_pktmbuf_pool_create(pool_name, RIF_MBUF_LEN, 32, PACKET_METADATA_SIZE, 0, rte_socket_id());
	if (r->pool == NULL) {
		LAGOPUS_DEBUG("RIF: rte_pktmbuf_pool_create() failed. Can't start.");
		goto error;
	}

	LAGOPUS_DEBUG("RIF: Starting bridge backend on slave core %u", rte_lcore_id());

	return r;

error:
	if (r->rifs)
		free(r->rifs);
	if (r)
		free(r);
	return NULL;
}

static bool
rif_process(void *p)
{
	struct rif_runtime *r = p;
	struct rte_mbuf *mbufs[RIF_MBUF_LEN]; // XXX: Should be configurable

	for (int n = 0; n < r->rifs_len; n++) {
		struct rif_instance *e = (struct rif_instance*)r->rifs[n];
		if ((!e) || (!e->base.enabled))
			continue;

		// RX and process incoming packets
		uint16_t count = rte_ring_dequeue_burst(e->base.input, (void **)mbufs, RIF_MBUF_LEN, NULL);
		if (count > 0)
			e->proc(r->pool, e, mbufs, count);
	}
	return true;
}

static void
rif_deinit(void *p)
{
	struct rif_runtime *r = p;
	rte_mempool_free(r->pool);
	free(r->rifs);
	free(r);
}

struct lagopus_runtime_ops rif_runtime_ops = {
	.init = rif_init,
	.process = rif_process,
	.deinit = rif_deinit,
	.register_instance = rif_register_instance,
	.unregister_instance = rif_unregister_instance,
	.update_rings = NULL,
	.control_instance = rif_control_instance,
};
