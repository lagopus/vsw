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

//#define DEBUG
#include "logger.h"
#include "ethdev.h"
#include "packet.h"

static void ethdev_rx_trunk(struct ethdev_rx_instance *, struct rte_mbuf **, int);
static void ethdev_rx_access(struct ethdev_rx_instance *, struct rte_mbuf **, int);
static void ethdev_tx_trunk(struct ethdev_tx_instance *, struct rte_mbuf **, int);
static void ethdev_tx_access(struct ethdev_tx_instance *, struct rte_mbuf **, int);

struct ethdev_runtime {
	struct ethdev_instance *devs[RTE_MAX_ETHPORTS];
	int max_port_id;
	struct rte_mempool *pool;
	struct rte_mempool *hdr_pool;	// Ether Header mempool (TRUNK only)
	struct rte_mempool *cln_pool;	// Packet clone mempool (TRUNK only)
};

static bool
ethdev_unregister_instance(void *p, struct lagopus_instance *base)
{
	struct ethdev_runtime *r = p;
	struct ethdev_instance *i = (struct ethdev_instance*)base;
	int port_id = i->port_id;

	if ((port_id >= RTE_MAX_ETHPORTS) || (!(r->devs[port_id])))
		return false;

	r->devs[port_id] = NULL;

	if (port_id == r->max_port_id) {
		while (--port_id >= 0) {
			if (r->devs[port_id])
				break;
		}
		r->max_port_id = port_id;
	}

	return true;
}

static bool
ethdev_register_instance(struct ethdev_runtime *r, struct ethdev_instance *i)
{
	int port_id = i->port_id;

	if ((port_id >= RTE_MAX_ETHPORTS) || (r->devs[port_id]))
		return false;

	r->devs[port_id] = i;

	if (port_id > r->max_port_id)
		r->max_port_id = port_id;

	for (int n = 0; n < MAX_VID; n++)
		i->index[n] = VIF_INVALID_INDEX;

	i->tx = ethdev_tx_access;
	i->rx = ethdev_rx_access;

	return true;
}

static bool
ethdev_tx_register_instance(void *p, struct lagopus_instance *base)
{
	struct ethdev_runtime *r = p;
	struct ethdev_tx_instance *i = (struct ethdev_tx_instance*)base;

	LAGOPUS_DEBUG("%s: %s=%p", __func__, i->common.base.name, i->common.base.input);

	if (!ethdev_register_instance(r, (struct ethdev_instance*)i))
		return false;

	if (rte_eth_tx_queue_setup(i->common.port_id, 0, i->nb_tx_desc, rte_socket_id(), NULL) != 0) {
		ethdev_unregister_instance(p, base);
		return false;
	}

	i->r = r;

	return true;
}

static bool
ethdev_rx_register_instance(void *p, struct lagopus_instance *base)
{
	struct ethdev_runtime *r = p;
	struct ethdev_rx_instance *i = (struct ethdev_rx_instance*)base;

	if (!ethdev_register_instance(r, (struct ethdev_instance*)i))
		return false;

	if (rte_eth_rx_queue_setup(i->common.port_id, 0, i->nb_rx_desc, rte_socket_id(), NULL, r->pool) != 0) {
		ethdev_unregister_instance(p, base);
		return false;
	}

	rte_eth_macaddr_get(i->common.port_id, &i->self_addr);
	memset(i->fwd, 0, sizeof(i->fwd));
	memset(i->fwd_type, 0, sizeof(i->fwd_type));

	return true;
}

static bool
ethdev_control_instance(void *p, struct lagopus_instance *base, void *param)
{
	struct ethdev_runtime *r = p;
	struct ethdev_control_param *ep = param;
	struct ethdev_instance *i = (struct ethdev_instance*)base;

	LAGOPUS_DEBUG("%s: name=%s cmd=%d vid=%d output=%p\n", __func__, base->name, ep->cmd, ep->vid, ep->output);

	switch (ep->cmd) {
	case ETHDEV_CMD_ADD_VID:
		i->base.outputs[ep->vid] = ep->output;
		i->index[ep->vid] = ep->index;
		if (!i->trunk)
			i->vid = ep->vid;
		break;
	case ETHDEV_CMD_DELETE_VID:
		i->base.outputs[ep->vid] = NULL;
		i->index[ep->vid] = VIF_INVALID_INDEX;
		if (!i->trunk)
			i->vid = 0;
		break;
	case ETHDEV_CMD_SET_TRUNK_MODE:
		i->tx = ethdev_tx_trunk;
		i->rx = ethdev_rx_trunk;
		i->trunk = true;
		break;
	case ETHDEV_CMD_SET_ACCESS_MODE:
		i->tx = ethdev_tx_access;
		i->rx = ethdev_rx_access;
		i->trunk = false;
		break;
	case ETHDEV_CMD_SET_NATIVE_VID:
		if (i->trunk) {
			if (i->vid != 0) {
				i->base.outputs[i->vid] = NULL;
				i->index[ep->vid] = VIF_INVALID_INDEX;
			}
			i->vid = ep->vid;
			i->base.outputs[ep->vid] = ep->output;
			i->index[ep->vid] = ep->index;
		}
		break;
	default:
		return false;
	}
	return true;
}

static inline bool
ethdev_update_forward_table(struct ethdev_rx_instance *i, struct ethdev_control_param *ep, fwd_type_t type) {
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
		if (i->fwd_type[ep->vid] == ETHDEV_FWD_TYPE_NONE)
			i->fwd[ep->vid] = NULL;
	}
	return true;
}

static bool
ethdev_rx_control_instance(void *p, struct lagopus_instance *base, void *param)
{
	struct ethdev_runtime *r = p;
	struct ethdev_control_param *ep = param;
	struct ethdev_rx_instance *ri = (struct ethdev_rx_instance*)base;
	struct ethdev_instance *i = (struct ethdev_instance*)base;

	switch (ep->cmd) {
	case ETHDEV_CMD_UPDATE_MAC:
		rte_eth_macaddr_get(i->port_id, &ri->self_addr);
		return true;

	case ETHDEV_CMD_SET_TRUNK_MODE:
		i->rx = ethdev_rx_trunk;
		i->trunk = true;
		return true;
	case ETHDEV_CMD_SET_ACCESS_MODE:
		i->rx = ethdev_rx_access;
		i->trunk = false;
		return true;

	case ETHDEV_CMD_SET_DST_SELF_FORWARD:
		return ethdev_update_forward_table(ri, ep, ETHDEV_FWD_TYPE_SELF);
	case ETHDEV_CMD_SET_DST_BC_FORWARD:
		return ethdev_update_forward_table(ri, ep, ETHDEV_FWD_TYPE_BC);
	case ETHDEV_CMD_SET_DST_MC_FORWARD:
		return ethdev_update_forward_table(ri, ep, ETHDEV_FWD_TYPE_MC);
	}
	return ethdev_control_instance(p, base, param);
}

static bool
ethdev_tx_control_instance(void *p, struct lagopus_instance *base, void *param)
{
	struct ethdev_runtime *r = p;
	struct ethdev_control_param *ep = param;
	struct ethdev_tx_instance *ti = (struct ethdev_tx_instance*)base;
	struct ethdev_instance *i = (struct ethdev_instance*)base;

	switch (ep->cmd) {
	case ETHDEV_CMD_UPDATE_MAC:
	case ETHDEV_CMD_SET_DST_SELF_FORWARD:
	case ETHDEV_CMD_SET_DST_BC_FORWARD:
	case ETHDEV_CMD_SET_DST_MC_FORWARD:
		return true;

	case ETHDEV_CMD_SET_TRUNK_MODE:
		i->tx = ethdev_tx_trunk;
		i->trunk = true;
		return true;
	case ETHDEV_CMD_SET_ACCESS_MODE:
		i->tx = ethdev_tx_access;
		i->trunk = false;
		return true;
	}
	return ethdev_control_instance(p, base, param);
}

static struct rte_mempool*
create_mempool(const char *prefix, unsigned n, uint16_t data_room_size)
{
	char pool_name[RTE_MEMZONE_NAMESIZE];
	int socket_id = rte_socket_id();

	snprintf(pool_name, RTE_MEMZONE_NAMESIZE, "%s-%d", prefix, socket_id);
	return rte_pktmbuf_pool_create(pool_name, n, 32, 0, data_room_size, socket_id);
}

static void*
ethdev_rx_init(void *param)
{
	struct ethdev_runtime *r;
	struct ethdev_runtime_param *p = param;

	if (p == NULL || p->pool == NULL) {
		LAGOPUS_DEBUG("ETHDEV: no mempool passed.");
		return NULL;
	}

	if (!(r = calloc(1, sizeof(struct ethdev_runtime)))) {
		LAGOPUS_DEBUG("ETHDEV: calloc() failed. Can't start.");
		return NULL;
	}

	LAGOPUS_DEBUG("ETHDEV: Starting bridge RX backend on slave core %u", rte_lcore_id());
	r->max_port_id = -1;
	r->pool = p->pool;

	return r;
}

static void*
ethdev_tx_init(void *param)
{
	struct ethdev_runtime *r;
	struct ethdev_runtime_param *p = param;

	if (!(r = calloc(1, sizeof(struct ethdev_runtime)))) {
		LAGOPUS_DEBUG("ETHDEV: calloc() failed. Can't start.");
		return NULL;
	}

	r->hdr_pool = create_mempool("ethdev-hdr-pool", ETHDEV_MBUF_LEN, 2 * RTE_PKTMBUF_HEADROOM);
	if (r->hdr_pool == NULL) {
		LAGOPUS_DEBUG("ETHDEV: create_mempol() for header failed.");
		free(r);
		return NULL;
	}

	r->cln_pool = create_mempool("ethdev-cln-pool", ETHDEV_MBUF_LEN, 0);
	if (r->cln_pool == NULL) {
		LAGOPUS_DEBUG("ETHDEV: create_mempol() for clone failed.");
		rte_mempool_free(r->hdr_pool);
		free(r);
		return NULL;
	}

	LAGOPUS_DEBUG("ETHDEV: Starting bridge TX backend on slave core %u", rte_lcore_id());
	r->max_port_id = -1;

	return r;
}

static inline fwd_type_t
ethdev_mark_and_check_next_module(struct rte_mbuf *mbuf, struct ether_addr *self, vifindex_t index)
{
	fwd_type_t fwd = ETHDEV_FWD_TYPE_NONE;
	struct lagopus_packet_metadata *md = LAGOPUS_MBUF_METADATA(mbuf);
	memset((void*)md, 0, sizeof(struct vif_metadata));

	// check if the packet is sent to me
	struct ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

	if (is_same_ether_addr(&hdr->d_addr, self)) {
		md->md_vif.flags |= LAGOPUS_MD_SELF;
		fwd = ETHDEV_FWD_TYPE_SELF;
	} else {
		md->md_vif.flags &= ~LAGOPUS_MD_SELF;

		if (is_multicast_ether_addr(&hdr->d_addr))
			fwd = ETHDEV_FWD_TYPE_MC;
		else if (is_broadcast_ether_addr(&hdr->d_addr))
			fwd = ETHDEV_FWD_TYPE_BC;
	}

	md->md_vif.in_vif = index;
	md->md_vif.out_vif = VIF_INVALID_INDEX;
	md->md_vif.local = false;

	return fwd;
}

static void
ethdev_rx_trunk(struct ethdev_rx_instance *e, struct rte_mbuf **mbufs, int rx_count)
{
	uint16_t vid = e->common.vid;
	vifindex_t *index = e->common.index;
	struct rte_ring **outputs = e->common.base.outputs;
	struct rte_ring **fwd = e->fwd;
	fwd_type_t *ft = e->fwd_type;
	struct ether_addr *self_addr = &e->self_addr;

	// TRUNK Mode
	for (int i = 0; i < rx_count; i++) {
		struct rte_mbuf *mbuf = mbufs[i];

		if (rte_vlan_strip(mbuf) != 0) {
			// NATIVE Mode
			if (vid != 0) {
				mbuf->vlan_tci = vid;
				mbuf->ol_flags |= PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED;
			} else {
				rte_pktmbuf_free(mbuf);
				e->rx_dropped++;
				continue;
			}
		}

		// XXX: We shall optimize packets forwarding. Queueing packets one-by-one
		// is not optimal.
		uint16_t vlan_id = mbuf->vlan_tci & 0xfff;
		struct rte_ring *output = outputs[vlan_id];
		bool enqueued = false;

		if (output) {
			if (ethdev_mark_and_check_next_module(mbuf, self_addr, index[vlan_id]) & ft[vlan_id])
				output = fwd[vlan_id];
			enqueued = (rte_ring_enqueue(output, mbuf) == 0);
		}

		if (enqueued) {
			e->rx_count++;
		} else {
			rte_pktmbuf_free(mbuf);
			e->rx_dropped++;
		}
	}
}

static inline void
ethdev_free_mbufs(struct rte_mbuf **mbufs, unsigned count, unsigned sent)
{
	while (unlikely (sent < count)) {
		rte_pktmbuf_free(mbufs[sent]);
		sent++;
	}
}

static void
ethdev_rx_access(struct ethdev_rx_instance *e, struct rte_mbuf **mbufs, int rx_count)
{
	struct rte_mbuf *in_mbufs[ETHDEV_MBUF_LEN]; // FIXME
	struct rte_mbuf *fwd_mbufs[ETHDEV_MBUF_LEN]; // FIXME

	uint16_t vid = e->common.vid;
	vifindex_t index = e->common.index[vid];
	struct rte_ring *output = e->common.base.outputs[vid];
	struct rte_ring *fwd_output = e->fwd[vid];
	fwd_type_t ft = e->fwd_type[vid];

	struct ether_addr *self_addr = &e->self_addr;

	unsigned count = 0;
	unsigned fwd_count = 0;

	for (int i = 0; i < rx_count; i++) {
		struct rte_mbuf *mbuf = mbufs[i];
		struct ether_hdr *eh = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

		// Drop packets with tags
		if (eh->ether_type == rte_cpu_to_be_16(ETHER_TYPE_VLAN)) {
			rte_pktmbuf_free(mbuf);
			e->rx_dropped++;
			continue;
		}

		if (ethdev_mark_and_check_next_module(mbuf, self_addr, index) & ft)
			fwd_mbufs[fwd_count++] = mbuf;
		else
			in_mbufs[count++] = mbuf;

		mbuf->ol_flags |= PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED;
		mbuf->vlan_tci = vid;
	}

	// Queue incoming packets at once for ACCESS Mode
	unsigned sent = 0;
	unsigned fwd_sent = 0;

	if (output)
		sent = rte_ring_enqueue_burst(output, (void * const*)in_mbufs, count, NULL);
	if (fwd_output)
		fwd_sent = rte_ring_enqueue_burst(fwd_output, (void * const*)fwd_mbufs, fwd_count, NULL);

	unsigned total_sent = sent + fwd_sent;

	LAGOPUS_DEBUG("ETHDEV: Rcv'd %d/%d packets for %d.", total_sent, rx_count, e->common.port_id);

	e->rx_count += total_sent;
	e->rx_dropped += rx_count - total_sent;

	ethdev_free_mbufs(in_mbufs, count, sent);
	ethdev_free_mbufs(fwd_mbufs, fwd_count, fwd_sent);
}

static bool
ethdev_rx_process(void *p)
{
	struct ethdev_runtime *r = p;
	struct rte_mbuf *mbufs[ETHDEV_MBUF_LEN]; // FIXME

	for (int port_id = 0; port_id <= r->max_port_id; port_id++) {
		struct ethdev_rx_instance *e = (struct ethdev_rx_instance*)r->devs[port_id];
		if ((!e) || (!e->common.base.enabled))
			continue;

		// RX and process incoming packets
		uint16_t rx_count = rte_eth_rx_burst(port_id, 0, mbufs, e->nb_rx_desc);
		if (rx_count > 0) {
			LAGOPUS_DEBUG("port_id=%d, rx_count=%d, vid=%d\n", port_id, rx_count, e->common.vid);
			e->common.rx(e, mbufs, rx_count);
		}
	}
	return true;
}

static inline void
ethdev_tx_burst(struct ethdev_tx_instance *e, struct rte_mbuf **mbufs, int count, int tx_count)
{
	unsigned sent = rte_eth_tx_burst(e->common.port_id, 0, mbufs, count);
	e->tx_count += sent;
	e->tx_dropped += tx_count - sent;
	ethdev_free_mbufs(mbufs, count, sent);
}

/*
 * Clone only the first mbuf in the chain.
 *
 * We could use rte_pktmbuf_attach() in DPDK, but we didn't want
 * to change the refcnt of mbuf. We refer via this new indirect
 * mbuf, but not directly, so the refcnt doesn't need to be changed
 * after all.
 *
 * We also don't need to copy all metadata, as this cloned mbuf
 * is not the first one in the chain.
 */
static inline struct rte_mbuf*
clone_mbuf(struct rte_mempool *mp, struct rte_mbuf *m) {
	struct rte_mbuf *mi = rte_pktmbuf_alloc(mp);
	if (unlikely(mi == NULL))
		return NULL;

	mi->priv_size = m->priv_size;
	mi->buf_physaddr = m->buf_physaddr;
	mi->buf_addr = m->buf_addr;
	mi->buf_len = m->buf_len;

	mi->next = m->next;
	mi->data_off = m->data_off;
	mi->data_len = m->data_len;
	mi->pkt_len = m->pkt_len;
	mi->nb_segs = m->nb_segs;

	mi->ol_flags = m->ol_flags | IND_ATTACHED_MBUF;
	mi->packet_type = m->packet_type;

	return mi;
}

/*
 * Insert VLAN tag.
 *
 * If refcnt of the mbuf is 1, then directly manipulate the packet.
 * If refcnt is more than 1, then we have to create a new ether header
 * and concatenate with the original mbuf chain via cloned indirect mbuf.
 * This cloned indirect mbuf points after the original ether header.
 *
 * Returns mbuf that should be sent out when succeeded.
 */
static inline struct rte_mbuf*
ethdev_insert_vlan(struct rte_mbuf *m, struct rte_mempool *hdr_pool, struct rte_mempool *cln_pool)
{
	struct ether_hdr *oh = rte_pktmbuf_mtod(m, struct ether_hdr *);
	struct ether_hdr *nh;

	// If refcnt == 1, we can directly manipulate the mbuf
	if (rte_mbuf_refcnt_read(m) == 1) {
		nh = (struct ether_hdr *)rte_pktmbuf_prepend(m, sizeof(struct vlan_hdr));

		// nothing we can do...
		if (nh == NULL)
			return NULL;

		memmove(nh, oh, 2 * ETHER_ADDR_LEN);
		nh->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);

		struct vlan_hdr *vh = (struct vlan_hdr *)(nh + 1);
		vh->vlan_tci = rte_cpu_to_be_16(m->vlan_tci);

		m->ol_flags &= ~PKT_RX_VLAN_STRIPPED;
		return m;
	}

	/*
	 * Otherwise, we need to allocate mbuf for ether header with 802.1q tag.
	 *
	 * The first mbuf holds new ether header with VLAN tag only.
	 * The second mbuf is indirect, and attached to the original mbuf.
	 * The second mbuf points to after the ether header in the original mbuf.
	 */
	struct rte_mbuf *hdr = rte_pktmbuf_alloc(hdr_pool);
	if (unlikely(hdr == NULL))
		return NULL;

	// Allocate indirect mbuf. We need to clone the first one only.
	struct rte_mbuf *clone = clone_mbuf(cln_pool, m);
	if (unlikely(clone == NULL)) {
		rte_pktmbuf_free(hdr);
		return NULL;
	}

	// Duplicate ether_hdr of original mbuf, and fill VLAN Tag
	nh = (struct ether_hdr*)rte_pktmbuf_prepend(hdr, sizeof(struct ether_hdr) + sizeof(struct vlan_hdr));
	memcpy(nh, oh, 2 * ETHER_ADDR_LEN);
	nh->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);

	struct vlan_hdr *vh = (struct vlan_hdr*)(nh + 1);
	vh->vlan_tci = rte_cpu_to_be_16(m->vlan_tci);
	vh->eth_proto = oh->ether_type;
	hdr->ol_flags = m->ol_flags & ~PKT_RX_VLAN_STRIPPED;

	// Remove the ether header
	rte_pktmbuf_adj(clone, (uint16_t)sizeof(struct ether_hdr));

	// Concainate ether header w/ 802.1q tag, and the reset of the packet.
	hdr->next = clone;

	hdr->pkt_len = (uint16_t)(hdr->data_len + clone->pkt_len);
	hdr->nb_segs = (uint8_t)(clone->nb_segs + 1);

	hdr->port = m->port;
	hdr->vlan_tci = m->vlan_tci;
	hdr->vlan_tci_outer = m->vlan_tci_outer;
	hdr->tx_offload = m->tx_offload;
	hdr->hash = m->hash;

	return hdr;
}

static void
ethdev_tx_trunk(struct ethdev_tx_instance *e, struct rte_mbuf **mbufs, int tx_count)
{
	struct rte_mbuf *out_mbufs[ETHDEV_MBUF_LEN]; // FIXME
	struct rte_ring **outputs = e->common.base.outputs;
	uint16_t vid = e->common.vid;
	int cnt = 0;
	struct rte_mempool *hp = e->r->hdr_pool;
	struct rte_mempool *cp = e->r->cln_pool;

	for (int i = 0; i < tx_count; i++) {
		struct rte_mbuf *mbuf = mbufs[i];

		if (!outputs[mbuf->vlan_tci & 0xfff]) {
			// Invalid VID
			rte_pktmbuf_free(mbuf);
			continue;
		}

		if (mbuf->vlan_tci != vid) {
			// Tag none-Native VID
			struct rte_mbuf *tagged_mbuf = ethdev_insert_vlan(mbuf, hp, cp);
			if (tagged_mbuf != NULL) {
				out_mbufs[cnt++] = tagged_mbuf;
			} else {
				rte_pktmbuf_free(mbuf);
			}
		} else {
			// Native VID
			out_mbufs[cnt++] = mbuf;
		}
	}
	ethdev_tx_burst(e, out_mbufs, cnt, tx_count);
}

static void
ethdev_tx_access(struct ethdev_tx_instance *e, struct rte_mbuf **mbufs, int tx_count)
{
	struct rte_mbuf *out_mbufs[ETHDEV_MBUF_LEN]; // FIXME
	uint16_t vid = e->common.vid;
	int cnt = 0;

	for (int i = 0; i < tx_count; i++) {
		struct rte_mbuf *mbuf = mbufs[i];

		if (unlikely(mbuf->vlan_tci != vid)) {
			rte_pktmbuf_free(mbuf);
			continue;
		}
		out_mbufs[cnt++] = mbuf;
	}
	ethdev_tx_burst(e, out_mbufs, cnt, tx_count);
}

static bool
ethdev_tx_process(void *p)
{
	struct ethdev_runtime *r = p;
	struct rte_mbuf *mbufs[ETHDEV_MBUF_LEN]; // FIXME: Should be same as e->nb_tx_desc

	for (int port_id = 0; port_id <= r->max_port_id; port_id++) {
		struct ethdev_tx_instance *e = (struct ethdev_tx_instance*)r->devs[port_id];
		if ((!e) || (!e->common.base.enabled))
			continue;

		// Dequeue outgoing packets
		unsigned tx_count = rte_ring_dequeue_burst(e->common.base.input, (void **)mbufs, e->nb_tx_desc, NULL);

		// TX outoing packets
		if (tx_count > 0) {
			uint16_t vid = e->common.vid;
			LAGOPUS_DEBUG("port_id=%d, tx_count=%d, vid=%d\n", port_id, tx_count, vid);
			e->common.tx(e, mbufs, tx_count);
		}
	}
	return true;
}

static void
ethdev_deinit(void *p)
{
	struct ethdev_runtime *r = p;

	for (int i = 0; i < RTE_MAX_ETHPORTS; i++) {
		struct ethdev_instance *e = r->devs[i];
		if (e)
			free((void*)e->base.name);
	}

	rte_mempool_free(r->hdr_pool);
	rte_mempool_free(r->cln_pool);

	free(r);
}

struct lagopus_runtime_ops ethdev_rx_runtime_ops = {
	.init = ethdev_rx_init,
	.process = ethdev_rx_process,
	.deinit = ethdev_deinit,
	.register_instance = ethdev_rx_register_instance,
	.unregister_instance = ethdev_unregister_instance,
	.update_rings = NULL,
	.control_instance = ethdev_rx_control_instance,
};

struct lagopus_runtime_ops ethdev_tx_runtime_ops = {
	.init = ethdev_tx_init,
	.process = ethdev_tx_process,
	.deinit = ethdev_deinit,
	.register_instance = ethdev_tx_register_instance,
	.unregister_instance = ethdev_unregister_instance,
	.update_rings = NULL,
	.control_instance = ethdev_tx_control_instance,
};
