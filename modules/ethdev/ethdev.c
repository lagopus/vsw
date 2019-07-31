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
#include <string.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include "logger.h"
#include "ethdev.h"
#include "packet.h"

static void ethdev_rx_trunk(struct ethdev_rx_instance *, struct rte_mbuf **, int);
static void ethdev_rx_access(struct ethdev_rx_instance *, struct rte_mbuf **, int);
static void ethdev_tx_trunk(struct ethdev_tx_instance *, struct rte_mbuf **, int);
static void ethdev_tx_access(struct ethdev_tx_instance *, struct rte_mbuf **, int);

static uint32_t log_id = 0;

#define ETHDEV_DEBUG(fmt, x...)		vsw_msg_debug(log_id, 0, fmt, ## x)
#define ETHDEV_INFO(fmt, x...)		vsw_msg_info(log_id, fmt, ## x)
#define ETHDEV_WARNING(fmt, x...)	vsw_msg_warning(log_id, fmt, ## x)
#define ETHDEV_ERROR(fmt, x...)		vsw_msg_error(log_id, fmt, ## x)
#define ETHDEV_FATAL(fmt, x...)		vsw_msg_fatal(log_id, fmt, ## x)

struct ethdev_runtime {
	struct ethdev_instance *devs[RTE_MAX_ETHPORTS];
	int max_port_id;
	struct rte_mempool *pool;
	struct rte_mempool *hdr_pool;	// Ether Header mempool (TRUNK only)
	struct rte_mempool *cln_pool;	// Packet clone mempool (TRUNK only)
};

static bool
ethdev_unregister_instance(void *p, struct vsw_instance *base)
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
ethdev_tx_register_instance(void *p, struct vsw_instance *base)
{
	struct ethdev_runtime *r = p;
	struct ethdev_tx_instance *i = (struct ethdev_tx_instance*)base;

	ETHDEV_DEBUG("%s: %s=%p", __func__, i->common.base.name, i->common.base.input);

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
ethdev_rx_register_instance(void *p, struct vsw_instance *base)
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
ethdev_control_instance(void *p, struct vsw_instance *base, void *param)
{
	struct ethdev_control_param *ep = param;
	struct ethdev_instance *i = (struct ethdev_instance*)base;

	ETHDEV_DEBUG("%s: name=%s cmd=%d vid=%d output=%p\n", __func__, base->name, ep->cmd, ep->vid, ep->output);

	switch (ep->cmd) {
	case ETHDEV_CMD_ADD_VID:
		i->base.outputs[ep->vid] = ep->output;
		i->index[ep->vid] = ep->index;
		i->counters[ep->vid] = ep->counter;
		if (!i->trunk)
			i->vid = ep->vid;
		break;
	case ETHDEV_CMD_DELETE_VID:
		i->base.outputs[ep->vid] = NULL;
		i->index[ep->vid] = VIF_INVALID_INDEX;
		i->counters[ep->vid] = NULL;
		if (!i->trunk)
			i->vid = 0;
		break;
	case ETHDEV_CMD_SET_NATIVE_VID:
		if (i->trunk) {
			if (i->vid != 0) {
				i->base.outputs[i->vid] = NULL;
				i->index[ep->vid] = VIF_INVALID_INDEX;
				i->counters[ep->vid] = NULL;
			}
			i->vid = ep->vid;
			i->base.outputs[ep->vid] = ep->output;
			i->index[ep->vid] = ep->index;
			i->counters[ep->vid] = ep->counter;
		}
		break;
	default:
		// All other cases should have been processed in
		// ethdev_{tx,rx}_control_instance().
		return false;
	}
	return true;
}

static inline bool
ethdev_update_forward_table(struct ethdev_rx_instance *i, struct ethdev_control_param *ep,
			    vsw_ether_dst_t type) {
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
ethdev_rx_control_instance(void *p, struct vsw_instance *base, void *param)
{
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
		return ethdev_update_forward_table(ri, ep, VSW_ETHER_DST_SELF);
	case ETHDEV_CMD_SET_DST_BC_FORWARD:
		return ethdev_update_forward_table(ri, ep, VSW_ETHER_DST_BROADCAST);
	case ETHDEV_CMD_SET_DST_MC_FORWARD:
		return ethdev_update_forward_table(ri, ep, VSW_ETHER_DST_MULTICAST);

	// The followings are processed in ethdev_control_instance()
	case ETHDEV_CMD_ADD_VID:
	case ETHDEV_CMD_DELETE_VID:
	case ETHDEV_CMD_SET_NATIVE_VID:
		break;
	}
	return ethdev_control_instance(p, base, param);
}

static bool
ethdev_tx_control_instance(void *p, struct vsw_instance *base, void *param)
{
	struct ethdev_control_param *ep = param;
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

	// The followings are processed in ethdev_control_instance()
	case ETHDEV_CMD_ADD_VID:
	case ETHDEV_CMD_DELETE_VID:
	case ETHDEV_CMD_SET_NATIVE_VID:
		break;
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

static void
update_logid()
{
	int id = vsw_log_getid("ethdev");
	if (id >= 0)
		log_id = (uint32_t)id;
}

static void*
ethdev_rx_init(void *param)
{
	struct ethdev_runtime *r;
	struct ethdev_runtime_param *p = param;

	update_logid();

	if (p->iopl_required && rte_eal_iopl_init() != 0) {
		ETHDEV_ERROR("rte_eal_iopl_init() failed");
		return NULL;
	}

	if (p == NULL || p->pool == NULL) {
		ETHDEV_ERROR("no mempool passed.");
		return NULL;
	}

	if (!(r = calloc(1, sizeof(struct ethdev_runtime)))) {
		ETHDEV_ERROR("calloc() failed. Can't start.");
		return NULL;
	}

	ETHDEV_DEBUG("Starting bridge RX backend on slave core %u", rte_lcore_id());
	r->max_port_id = -1;
	r->pool = p->pool;

	return r;
}

static void*
ethdev_tx_init(void *param)
{
	struct ethdev_runtime *r;
	struct ethdev_runtime_param *p = param;

	update_logid();

	if (p->iopl_required && rte_eal_iopl_init() != 0) {
		ETHDEV_ERROR("rte_eal_iopl_init() failed");
		return NULL;
	}

	if (!(r = calloc(1, sizeof(struct ethdev_runtime)))) {
		ETHDEV_ERROR("calloc() failed. Can't start.");
		return NULL;
	}

	r->hdr_pool = create_mempool("ethdev-hdr-pool", ETHDEV_MBUF_LEN, 2 * RTE_PKTMBUF_HEADROOM);
	if (r->hdr_pool == NULL) {
		ETHDEV_ERROR("create_mempol() for header failed.");
		free(r);
		return NULL;
	}

	r->cln_pool = create_mempool("ethdev-cln-pool", ETHDEV_MBUF_LEN, 0);
	if (r->cln_pool == NULL) {
		ETHDEV_ERROR("create_mempol() for clone failed.");
		rte_mempool_free(r->hdr_pool);
		free(r);
		return NULL;
	}

	ETHDEV_DEBUG("Starting bridge TX backend on slave core %u", rte_lcore_id());
	r->max_port_id = -1;

	return r;
}

static inline void
ethdev_set_metadata(struct rte_mbuf *mbuf, vifindex_t index)
{
	struct vsw_packet_metadata *md = VSW_MBUF_METADATA(mbuf);
	struct vsw_common_metadata metadata = {
		.in_vif = index,
		.out_vif = VIF_INVALID_INDEX,
	};
	md->common = metadata;
}

static void
ethdev_rx_trunk(struct ethdev_rx_instance *e, struct rte_mbuf **mbufs, int rx_count)
{
	uint16_t vid = e->common.vid;
	vifindex_t *index = e->common.index;
	struct rte_ring **outputs = e->common.base.outputs;
	struct rte_ring **fwd = e->fwd;
	vsw_ether_dst_t *ft = e->fwd_type;
	struct ether_addr *self_addr = &e->self_addr;
	struct vsw_counter *c = e->common.counter;
	struct vsw_counter **counters = e->common.counters;

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
				c->in_discards++;
				continue;
			}
		}

		// XXX: We shall optimize packets forwarding. Queueing packets one-by-one
		// is not optimal.
		uint16_t vlan_id = mbuf->vlan_tci & 0xfff;
		struct rte_ring *output = outputs[vlan_id];
		if (!output) {
			// Invalid VID
			rte_pktmbuf_free(mbuf);
			c->in_discards++;
			continue;
		}

		struct vsw_counter *vc = counters[vlan_id];
		vsw_ether_dst_t dt = vsw_check_ether_dst_and_self(mbuf, self_addr);
		VSW_ETHER_UPDATE_IN_COUNTER2(c, vc, dt);

		ethdev_set_metadata(mbuf, index[vlan_id]);
		if (dt & ft[vlan_id])
			output = fwd[vlan_id];

		if (rte_ring_enqueue(output, mbuf) == 0) {
			vc->in_octets += mbuf->pkt_len;
		} else {
			rte_pktmbuf_free(mbuf);
			c->in_discards++;
			vc->in_discards++;
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
	vsw_ether_dst_t ft = e->fwd_type[vid];

	struct ether_addr *self_addr = &e->self_addr;

	unsigned count = 0;
	unsigned fwd_count = 0;

	struct vsw_counter *c = e->common.counter;

	for (int i = 0; i < rx_count; i++) {
		struct rte_mbuf *mbuf = mbufs[i];

		struct ether_hdr *eh = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

		// Drop packets with tags
		if (eh->ether_type == rte_cpu_to_be_16(ETHER_TYPE_VLAN)) {
			rte_pktmbuf_free(mbuf);
			c->in_discards++;
			continue;
		}

		ethdev_set_metadata(mbuf, index);

		vsw_ether_dst_t dt = vsw_check_ether_dst_and_self(mbuf, self_addr);

		// For ACCESS mode, the counter will anyway be the same
		// for interface and subinterface.
		VSW_ETHER_UPDATE_IN_COUNTER(c, dt);

		if (dt & ft)
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

	unsigned discarded = rx_count - sent - fwd_sent;
	c->in_discards += discarded;

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
			ETHDEV_DEBUG("port_id=%d, rx_count=%d, vid=%d\n", port_id, rx_count, e->common.vid);
			e->common.rx(e, mbufs, rx_count);
		}
	}
	return true;
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

#define DISCARD_MBUF(m, i, s) {								\
	rte_pktmbuf_free((m)[i]); 							\
	(s)--; 										\
	memmove(&(m)[i], &(m)[i + 1], sizeof(struct rte_mbuf *) * ((s) - (i)));		\
}



static void
ethdev_tx_trunk(struct ethdev_tx_instance *e, struct rte_mbuf **mbufs, int tx_count)
{
	struct rte_ring **outputs = e->common.base.outputs;
	uint16_t vid = e->common.vid;
	int cnt = tx_count;
	struct rte_mempool *hp = e->r->hdr_pool;
	struct rte_mempool *cp = e->r->cln_pool;
	struct vsw_counter *c = e->common.counter;
	struct vsw_counter *nc = e->common.counters[vid];
	struct vsw_counter **counters = e->common.counters;

	for (int i = 0; i < cnt; i++) {
		struct rte_mbuf *mbuf = mbufs[i];

		vsw_ether_dst_t dt = vsw_check_ether_dst(mbuf);

		VSW_ETHER_UPDATE_OUT_COUNTER(c, dt);

		uint16_t vlan_id = mbuf->vlan_tci & 0xfff;

		if (!outputs[vlan_id]) {
			// Invalid VID
			DISCARD_MBUF(mbufs, i, cnt);
			c->out_discards++;
			continue;
		}

		// Some vPMD doesn't support multi-segment mbuf.
		if ((e->force_linearize) && (mbuf->next)) {
			if (rte_pktmbuf_linearize(mbuf) != 0) {
				DISCARD_MBUF(mbufs, i, cnt);
				c->out_discards++;
				continue;
			}
		}

		if (vlan_id != vid) {
			// Tag none-Native VID
			struct rte_mbuf *tagged_mbuf = ethdev_insert_vlan(mbuf, hp, cp);
			if (tagged_mbuf != NULL) {
				mbufs[i] = tagged_mbuf;

				struct vsw_counter *vc = counters[vlan_id];
				VSW_ETHER_UPDATE_OUT_COUNTER(vc, dt);
				vc->out_octets += mbuf->pkt_len;
			} else {
				DISCARD_MBUF(mbufs, i, cnt);
				c->out_discards++;
			}
		} else {
			VSW_ETHER_UPDATE_OUT_COUNTER(nc, dt);
			nc->out_octets += mbuf->pkt_len;
		}
	}

	unsigned sent = rte_eth_tx_burst(e->common.port_id, 0, mbufs, cnt);
	c->out_discards += cnt - sent;

	// Count up discarded packets for each VLAN
	while (unlikely(sent < cnt)) {
		struct rte_mbuf *mbuf = mbufs[sent];
		uint16_t vlan_id = mbuf->vlan_tci & 0xfff;
		struct vsw_counter *vc = (vlan_id == vid) ? nc : counters[vlan_id];

		vc->out_discards++;
		vc->out_octets -= mbuf->pkt_len;

		rte_pktmbuf_free(mbuf);
		sent++;
	}
}

static void
ethdev_tx_access(struct ethdev_tx_instance *e, struct rte_mbuf **mbufs, int tx_count)
{
	uint16_t vid = e->common.vid;
	int cnt = tx_count;
	struct vsw_counter *c = e->common.counter;

	for (int i = 0; i < cnt; i++) {
		struct rte_mbuf *mbuf = mbufs[i];

		vsw_ether_dst_t dt = vsw_check_ether_dst(mbuf);
		VSW_ETHER_UPDATE_OUT_COUNTER(c, dt);

		if (unlikely(mbuf->vlan_tci != vid)) {
			DISCARD_MBUF(mbufs, i, cnt);
			c->out_discards++;
			continue;
		}

		// Some vPMD doesn't support multi-segment mbuf.
		if ((e->force_linearize) && (mbuf->next)) {
			if (rte_pktmbuf_linearize(mbuf) != 0) {
				DISCARD_MBUF(mbufs, i, cnt);
				c->out_discards++;
			}
		}
	}

	unsigned sent = rte_eth_tx_burst(e->common.port_id, 0, mbufs, cnt);
	ethdev_free_mbufs(mbufs, cnt, sent);
	c->out_discards += cnt - sent;
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
			ETHDEV_DEBUG("port_id=%d, tx_count=%d, vid=%d\n", port_id, tx_count, vid);
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

struct vsw_runtime_ops ethdev_rx_runtime_ops = {
	.init = ethdev_rx_init,
	.process = ethdev_rx_process,
	.deinit = ethdev_deinit,
	.register_instance = ethdev_rx_register_instance,
	.unregister_instance = ethdev_unregister_instance,
	.update_rings = NULL,
	.control_instance = ethdev_rx_control_instance,
};

struct vsw_runtime_ops ethdev_tx_runtime_ops = {
	.init = ethdev_tx_init,
	.process = ethdev_tx_process,
	.deinit = ethdev_deinit,
	.register_instance = ethdev_tx_register_instance,
	.unregister_instance = ethdev_unregister_instance,
	.update_rings = NULL,
	.control_instance = ethdev_tx_control_instance,
};
