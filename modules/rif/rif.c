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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

#include "logger.h"
#include "rif.h"
#include "packet.h"
#include "ether.h"

static void rif_proc_tx_trunk(struct rte_mempool *, struct rif_instance *, struct rte_mbuf **, int);
static void rif_proc_rx_trunk(struct rte_mempool *, struct rif_instance *, struct rte_mbuf **, int);
static void rif_proc_tx_access(struct rte_mempool *, struct rif_instance *, struct rte_mbuf **, int);
static void rif_proc_rx_access(struct rte_mempool *, struct rif_instance *, struct rte_mbuf **, int);

#define RIF_DEFAULT_RIFS_CAP 256

static uint32_t rif_log_id = 0;

#define RIF_DEBUG(fmt, x...)	vsw_msg_debug(rif_log_id, 0, fmt, ## x)
#define RIF_INFO(fmt, x...)	vsw_msg_info(rif_log_id, fmt, ## x)
#define RIF_WARNING(fmt, x...)	vsw_msg_warning(rif_log_id, fmt, ## x)
#define RIF_ERROR(fmt, x...)	vsw_msg_error(rif_log_id, fmt, ## x)
#define RIF_FATAL(fmt, x...)	vsw_msg_fatal(rif_log_id, fmt, ## x)

struct rif_runtime {
	struct rif_instance **rifs;
	struct rte_mempool *pool;
	int rifs_cap;
	int rifs_len;
};

static bool
rif_register_instance(void *p, struct vsw_instance *base)
{
	struct rif_runtime *r = p;
	struct rif_instance *i = (struct rif_instance*)base;

	// Reallocate RIFs array safely.
	if (r->rifs_len + 1 > r->rifs_cap) {
		int cap = r->rifs_cap * 2;
		struct rif_instance **rifs = calloc(1, sizeof(struct rif_instance*) * cap);

		if (rifs == NULL) {
			RIF_DEBUG("RIF: Failed to resize rif_instance place holder");
			return false;
		}

		memcpy(rifs, r->rifs, sizeof(struct rif_instance*) * r->rifs_cap);
		free(r->rifs);
		r->rifs = rifs;
		r->rifs_cap = cap;
	}
	r->rifs[r->rifs_len] = i;
	r->rifs_len++;

	for (int n = 0; n < MAX_VID; n++) {
		i->index[n] = VIF_INVALID_INDEX;
		i->fwd[n] = NULL;
		i->fwd_type[n] = VSW_ETHER_DST_UNKNOWN;
	}

	i->proc_tx = rif_proc_tx_access;
	i->proc_rx = rif_proc_rx_access;

	return true;
}

static bool
rif_unregister_instance(void *p, struct vsw_instance *base)
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
rif_update_forward_table(struct rif_instance *i, struct rif_control_param *ep, vsw_ether_dst_t type) {
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
		if (i->fwd_type[ep->vid] == VSW_ETHER_DST_UNKNOWN)
			i->fwd[ep->vid] = NULL;
	}
	return true;
}

static bool
rif_control_instance(void *p, struct vsw_instance *base, void *param)
{
	struct rif_control_param *ep = param;
	struct rif_instance *i = (struct rif_instance*)base;

	RIF_DEBUG("%s: name=%s cmd=%d vid=%d output=%p\n", __func__, base->name, ep->cmd, ep->vid, ep->output);

	switch (ep->cmd) {
	case RIF_CMD_ADD_VID:
		i->base.outputs[ep->vid] = ep->output;
		i->counters[ep->vid] = ep->counter;
		i->index[ep->vid] = ep->index;
		if (!i->trunk)
			i->vid = ep->vid;
		return true;
	case RIF_CMD_DELETE_VID:
		i->base.outputs[ep->vid] = NULL;
		i->counters[ep->vid] = NULL;
		i->index[ep->vid] = VIF_INVALID_INDEX;
		if (!i->trunk)
			i->vid = 0;
		return true;
	case RIF_CMD_SET_MTU:
		i->mtu = ep->mtu;
		return true;
	case RIF_CMD_SET_MAC:
		ether_addr_copy(&ep->mac, &i->self_addr);
		return true;
	case RIF_CMD_SET_TRUNK_MODE:
		i->proc_tx = rif_proc_tx_trunk;
		i->proc_rx = rif_proc_rx_trunk;
		i->trunk = true;
		return true;
	case RIF_CMD_SET_ACCESS_MODE:
		i->proc_tx = rif_proc_tx_access;
		i->proc_rx = rif_proc_rx_access;
		i->trunk = false;
		return true;
	case RIF_CMD_SET_DST_SELF_FORWARD:
		return rif_update_forward_table(i, ep, VSW_ETHER_DST_SELF);
	case RIF_CMD_SET_DST_BC_FORWARD:
		return rif_update_forward_table(i, ep, VSW_ETHER_DST_BROADCAST);
	case RIF_CMD_SET_DST_MC_FORWARD:
		return rif_update_forward_table(i, ep, VSW_ETHER_DST_MULTICAST);
	}
	return false;
}

static inline struct rte_mbuf*
dup_mbuf(struct rte_mempool *mp, struct rte_mbuf *mbuf)
{
	struct rte_mbuf *new_mbuf = rte_pktmbuf_alloc(mp);

	// copy common metadata section
	memcpy(VSW_MBUF_METADATA(new_mbuf), VSW_MBUF_METADATA(mbuf), sizeof(struct vsw_common_metadata));

	// attach to the original mbuf
	rte_pktmbuf_attach(new_mbuf, mbuf);
	rte_pktmbuf_free(mbuf);

	return new_mbuf;
}

static void
rif_proc_tx_trunk(struct rte_mempool *mp, struct rif_instance *e, struct rte_mbuf **mbufs, int count)
{
	vifindex_t *index = e->index;
	struct rte_ring **outputs = e->base.outputs;
	struct vsw_counter *c = e->counter;
	struct vsw_counter **counters = e->counters;

	// TRUNK Mode
	for (int i = 0; i < count; i++) {
		struct rte_mbuf *mbuf = mbufs[i];
		uint16_t vlan_id = mbuf->vlan_tci & 0xfff;
		vifindex_t vifidx = index[vlan_id];

		if (vifidx == VIF_INVALID_INDEX) {
			c->out_errors++;
			rte_pktmbuf_free(mbuf);
			continue;
		}

		struct vsw_counter *vc = counters[vlan_id];

		// XXX: We shall optimize packets forwarding. Queueing packets one-by-one
		// is not optimal.
		if (mbuf->pkt_len <= e->mtu) {
			if (rte_mbuf_refcnt_read(mbuf) > 1)
				mbuf = dup_mbuf(mp, mbuf);

			// In_vif is set to VIF index of RIF, so that VSI will not send back
			// the packet during flooding.
			struct vsw_packet_metadata *md = VSW_MBUF_METADATA(mbuf);
			md->common.in_vif  = vifidx;
			md->common.out_vif = VIF_INVALID_INDEX;

			// VRF -> VSI
			if (rte_ring_enqueue(outputs[vlan_id], mbuf) == 0) {
				VSW_ETHER_UPDATE_OUT_COUNTER(c, vc, vsw_check_ether_dst(mbuf), mbuf->pkt_len);
			} else {
				rte_pktmbuf_free(mbuf);
				c->out_discards++;
				vc->out_discards++;
			}
		} else {
			c->out_errors++;
			vc->out_errors++;
			rte_pktmbuf_free(mbuf);
		}
	}
}

static void
rif_proc_rx_trunk(struct rte_mempool *mp, struct rif_instance *e, struct rte_mbuf **mbufs, int count)
{
	vifindex_t *index = e->index;
	struct rte_ring **fwd = e->fwd;
	vsw_ether_dst_t *ft = e->fwd_type;
	struct vsw_counter *c = e->counter;
	struct vsw_counter **counters = e->counters;

	struct ether_addr *self_addr = &e->self_addr;

	// TRUNK Mode
	for (int i = 0; i < count; i++) {
		struct rte_mbuf *mbuf = mbufs[i];
		uint16_t vlan_id = mbuf->vlan_tci & 0xfff;
		vifindex_t vifidx = index[vlan_id];

		if (vifidx == VIF_INVALID_INDEX) {
			c->in_errors++;
			rte_pktmbuf_free(mbuf);
			continue;
		}

		struct vsw_counter *vc = counters[vlan_id];

		// XXX: We shall optimize packets forwarding. Queueing packets one-by-one
		// is not optimal.
		if (mbuf->pkt_len <= e->mtu) {
			if (rte_mbuf_refcnt_read(mbuf) > 1)
				mbuf = dup_mbuf(mp, mbuf);

			struct vsw_packet_metadata *md = VSW_MBUF_METADATA(mbuf);
			md->common.in_vif  = vifidx;
			md->common.out_vif = VIF_INVALID_INDEX;

			// VSI -> VRF
			vsw_ether_dst_t d = vsw_check_ether_dst_and_self(mbuf, self_addr);

			bool sent = false;
			if (d & ft[vlan_id]) {
				if (rte_ring_enqueue(fwd[vlan_id], mbuf) == 0) {
					sent = true;
					VSW_ETHER_UPDATE_IN_COUNTER(c, vc, d, mbuf->pkt_len);
				}
			}

			if (!sent) {
				rte_pktmbuf_free(mbuf);
				c->in_discards++;
				vc->in_discards++;
			}
		} else {
			c->in_errors++;
			vc->in_errors++;
			rte_pktmbuf_free(mbuf);
		}
	}
}

static void
rif_proc_tx_access(struct rte_mempool *mp, struct rif_instance *e, struct rte_mbuf **mbufs, int count)
{
	struct rte_mbuf *outbound_mbufs[RIF_MBUF_LEN]; // FIXME
	uint16_t vid = e->vid;
	vifindex_t index = e->index[vid];
	struct rte_ring *outbound_output = e->base.outputs[vid];
	struct vsw_counter *c = e->counter;
	unsigned outbound_count = 0;

	if (index == VIF_INVALID_INDEX || outbound_output == NULL) {
		for (int i = 0; i < count; i++) {
			c->out_errors++;
			rte_pktmbuf_free(mbufs[i]);
		}
		return;
	}

	struct vsw_counter *vc = e->counters[vid];

	for (int i = 0; i < count; i++) {
		struct rte_mbuf *mbuf = mbufs[i];

		// drop following packets
		// - w/o appropriate VLAN ID
		// - exceeding MTU
		if ((mbuf->pkt_len > e->mtu) ||
		    ((mbuf->vlan_tci & 0xfff) != vid)) {
			c->out_errors++;
			vc->out_errors++;
			rte_pktmbuf_free(mbuf);
			continue;
		}

		if (rte_mbuf_refcnt_read(mbuf) > 1)
			mbuf = dup_mbuf(mp, mbuf);

		// In_vif is set to VIF index of RIF, so that VSI will not send back
		// the packet during flooding.
		struct vsw_packet_metadata *md = VSW_MBUF_METADATA(mbuf);
		md->common.in_vif  = index;
		md->common.out_vif = VIF_INVALID_INDEX;

		// VRF -> VSI
		vsw_ether_dst_t dst = vsw_check_ether_dst(mbuf);
		VSW_ETHER_UPDATE_OUT_COUNTER(c, vc, dst, mbuf->pkt_len);

		outbound_mbufs[outbound_count++] = mbuf;
	}

	unsigned outbound_sent = 0;

	if (outbound_count > 0)
		outbound_sent = rte_ring_enqueue_burst(outbound_output, (void * const*)outbound_mbufs, outbound_count, NULL);

	if (unlikely(outbound_sent < outbound_count)) {
		uint64_t discards = outbound_count - outbound_sent;
		c->out_discards += discards;
		vc->out_discards += discards;

		uint64_t octets = 0;
		while (unlikely(outbound_sent < outbound_count)) {
			struct rte_mbuf *mbuf = mbufs[outbound_sent];

			vsw_ether_dst_t dst = vsw_check_ether_dst(mbuf);
			VSW_ETHER_DEC_OUT_COUNTER(c, vc, dst);
			octets += mbuf->pkt_len;

			rte_pktmbuf_free(mbuf);
			outbound_sent++;
		}
		c->out_octets -= octets;
		vc->out_octets -= octets;
	}
}

static void
rif_proc_rx_access(struct rte_mempool *mp, struct rif_instance *e, struct rte_mbuf **mbufs, int count)
{
	struct rte_mbuf *inbound_mbufs[RIF_MBUF_LEN]; // FIXME
	uint16_t vid = e->vid;
	vifindex_t index = e->index[vid];
	struct rte_ring *inbound_output = e->fwd[vid];
	vsw_ether_dst_t ft = e->fwd_type[vid];
	struct vsw_counter *c = e->counter;
	struct ether_addr *self_addr = &e->self_addr;
	unsigned inbound_count = 0;

	if (index == VIF_INVALID_INDEX) {
		for (int i = 0; i < count; i++) {
			c->in_errors++;
			rte_pktmbuf_free(mbufs[i]);
		}
		return;
	}

	struct vsw_counter *vc = e->counters[vid];

	for (int i = 0; i < count; i++) {
		struct rte_mbuf *mbuf = mbufs[i];

		// drop following packets
		// - w/o appropriate VLAN ID
		// - exceeding MTU
		if ((mbuf->pkt_len > e->mtu) ||
		    ((mbuf->vlan_tci & 0xfff) != vid)) {
			c->in_errors++;
			vc->in_errors++;
			rte_pktmbuf_free(mbuf);
			continue;
		}

		if (rte_mbuf_refcnt_read(mbuf) > 1)
			mbuf = dup_mbuf(mp, mbuf);

		struct vsw_packet_metadata *md = VSW_MBUF_METADATA(mbuf);
		md->common.in_vif  = index;
		md->common.out_vif = VIF_INVALID_INDEX;

		vsw_ether_dst_t dst = vsw_check_ether_dst_and_self(mbuf, self_addr);

		if (dst & ft) {
			inbound_mbufs[inbound_count++] = mbuf;
			VSW_ETHER_UPDATE_IN_COUNTER(c, vc, dst, mbuf->pkt_len);
		} else {
			rte_pktmbuf_free(mbuf);
			c->in_discards++;
			vc->in_discards++;
		}
	}

	// Queue incoming packets at once for ACCESS Mode
	unsigned inbound_sent = 0;

	if ((inbound_output) && inbound_count > 0)
		inbound_sent = rte_ring_enqueue_burst(inbound_output, (void * const*)inbound_mbufs, inbound_count, NULL);

	if (unlikely(inbound_sent < inbound_count)) {
		uint64_t discards = inbound_count - inbound_sent;
		c->in_discards += discards;
		vc->in_discards += discards;

		uint64_t octets = 0;
		while (unlikely(inbound_sent < inbound_count)) {
			struct rte_mbuf *mbuf = mbufs[inbound_sent];

			vsw_ether_dst_t dst = vsw_check_ether_dst(mbuf);
			VSW_ETHER_DEC_IN_COUNTER(c, vc, dst);
			octets += mbuf->pkt_len;

			rte_pktmbuf_free(mbuf);
			inbound_sent++;
		}
		c->in_octets -= octets;
		vc->in_octets -= octets;
	}
}

static void
update_logid()
{
	int id = vsw_log_getid("rif");
	if (id >= 0)
		rif_log_id = (uint32_t)id;
}

static void*
rif_init(void *param)
{
	struct rif_runtime *r;
	char pool_name[RTE_MEMZONE_NAMESIZE];

	update_logid();

	if (!(r = calloc(1, sizeof(struct rif_runtime)))) {
		RIF_DEBUG("RIF: calloc() failed. Can't start.");
		return NULL;
	}

	r->rifs_cap = RIF_DEFAULT_RIFS_CAP;
	if (!(r->rifs = calloc(1, sizeof(struct rif_instance*) * r->rifs_cap))) {
		RIF_DEBUG("RIF: calloc() failed. Can't start.");
		goto error;
	}

	snprintf(pool_name, RTE_MEMZONE_NAMESIZE, "rif-md-pool-%d", rte_lcore_id());
	r->pool = rte_pktmbuf_pool_create(pool_name, RIF_MBUF_LEN, 32, PACKET_METADATA_SIZE, 0, rte_socket_id());
	if (r->pool == NULL) {
		RIF_DEBUG("RIF: rte_pktmbuf_pool_create() failed. Can't start.");
		goto error;
	}

	RIF_DEBUG("RIF: Starting bridge backend on slave core %u", rte_lcore_id());

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
	uint16_t count;

	for (int n = 0; n < r->rifs_len; n++) {
		struct rif_instance *e = (struct rif_instance*)r->rifs[n];
		if ((!e) || (!e->base.enabled))
			continue;

		// VRF -> RIF -> VSI (TX, i.e. outbound)
		count = rte_ring_dequeue_burst(e->base.input, (void **)mbufs, RIF_MBUF_LEN, NULL);
		if (count > 0)
			e->proc_tx(r->pool, e, mbufs, count);

		// VSI -> RIF -> VRF (RX, i.e. inbound)
		count = rte_ring_dequeue_burst(e->base.input2, (void **)mbufs, RIF_MBUF_LEN, NULL);
		if (count > 0)
			e->proc_rx(r->pool, e, mbufs, count);

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

struct vsw_runtime_ops rif_runtime_ops = {
	.init = rif_init,
	.process = rif_process,
	.deinit = rif_deinit,
	.register_instance = rif_register_instance,
	.unregister_instance = rif_unregister_instance,
	.update_rings = NULL,
	.control_instance = rif_control_instance,
};
