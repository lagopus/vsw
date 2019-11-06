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

#ifndef VSW_ETHER_H_
#define VSW_ETHER_H_

#include <rte_mbuf.h>
#include <rte_ether.h>

typedef enum {
	VSW_ETHER_DST_UNKNOWN   = 0x0,
	VSW_ETHER_DST_SELF      = 0x1,
	VSW_ETHER_DST_UNICAST   = 0x2,
	VSW_ETHER_DST_BROADCAST = 0x4,
	VSW_ETHER_DST_MULTICAST = 0x8,
} vsw_ether_dst_t;

/**
 * Check the type of destination Ethernet address in rte_mbuf.
 */
static inline vsw_ether_dst_t
vsw_check_ether_dst(struct rte_mbuf *mbuf) {
	struct ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	struct ether_addr *daddr = &hdr->d_addr;

	if (is_broadcast_ether_addr(daddr))
		return VSW_ETHER_DST_BROADCAST;

	if (is_multicast_ether_addr(daddr))
		return VSW_ETHER_DST_MULTICAST;

	return VSW_ETHER_DST_UNICAST;
}

/**
 * Check the type of destination Ethernet address in rte_mbuf.
 *
 * If self is not NULL, then it also checks if the destination ethernet
 * address matches to the ethernet address passed with self.
 */
static inline vsw_ether_dst_t
vsw_check_ether_dst_and_self(struct rte_mbuf *mbuf, struct ether_addr *self) {
	struct ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	struct ether_addr *daddr = &hdr->d_addr;

	if (is_broadcast_ether_addr(daddr))
		return VSW_ETHER_DST_BROADCAST;

	if (is_multicast_ether_addr(daddr))
		return VSW_ETHER_DST_MULTICAST;

	if ((self) && (is_same_ether_addr(&hdr->d_addr, self)))
		return VSW_ETHER_DST_UNICAST | VSW_ETHER_DST_SELF;

	return VSW_ETHER_DST_UNICAST;
}

// The order of members SHALL match to the definition
// of struct vsw_counter in counter.h.
struct vsw_ether_counter {
	uint64_t octets;
	uint64_t unicast_pkts;
	uint64_t broadcast_pkts;
	uint64_t multicast_pkts;
};

static inline void
vsw_ether_counter_inc(struct vsw_ether_counter *c1, struct vsw_ether_counter *c2,
			  vsw_ether_dst_t t, uint64_t pkt_len)
{
	if (t & VSW_ETHER_DST_UNICAST) {
		c1->unicast_pkts++;
		c2->unicast_pkts++;
	} else if (t & VSW_ETHER_DST_BROADCAST) {
		c1->broadcast_pkts++;
		c2->broadcast_pkts++;
	} else if (t & VSW_ETHER_DST_MULTICAST) {
		c1->multicast_pkts++;
		c2->multicast_pkts++;
	}
	c1->octets += pkt_len;
	c2->octets += pkt_len;
}

static inline void
vsw_ether_counter_dec(struct vsw_ether_counter *c1, struct vsw_ether_counter *c2,
			  vsw_ether_dst_t t)
{
	if (t & VSW_ETHER_DST_UNICAST) {
		c1->unicast_pkts--;
		c2->unicast_pkts--;
	} else if (t & VSW_ETHER_DST_BROADCAST) {
		c1->broadcast_pkts--;
		c2->broadcast_pkts--;
	} else if (t & VSW_ETHER_DST_MULTICAST) {
		c1->multicast_pkts--;
		c2->multicast_pkts--;
	}
}

static inline void
vsw_ether_counter_dec_with_octets(struct vsw_ether_counter *c1, struct vsw_ether_counter *c2,
			  vsw_ether_dst_t t, uint64_t pkt_len)
{
	if (t & VSW_ETHER_DST_UNICAST) {
		c1->unicast_pkts--;
		c2->unicast_pkts--;
	} else if (t & VSW_ETHER_DST_BROADCAST) {
		c1->broadcast_pkts--;
		c2->broadcast_pkts--;
	} else if (t & VSW_ETHER_DST_MULTICAST) {
		c1->multicast_pkts--;
		c2->multicast_pkts--;
	}
	c1->octets -= pkt_len;
	c2->octets -= pkt_len;
}

#define _VSW_IN_COUNTER_BASE(c) ((struct vsw_ether_counter*)(c))
#define _VSW_OUT_COUNTER_BASE(c) ((struct vsw_ether_counter*)&((c)->out_octets))

#define VSW_ETHER_INC_IN_COUNTER(c1, c2, d, l) \
	vsw_ether_counter_inc(_VSW_IN_COUNTER_BASE(c1), _VSW_IN_COUNTER_BASE(c2), (d), (l))
#define VSW_ETHER_INC_OUT_COUNTER(c1, c2, d, l) \
	vsw_ether_counter_inc(_VSW_OUT_COUNTER_BASE(c1), _VSW_OUT_COUNTER_BASE(c2), (d), (l))

#define VSW_ETHER_DEC_IN_COUNTER(c1, c2, d) \
	vsw_ether_counter_dec(_VSW_IN_COUNTER_BASE(c1), _VSW_IN_COUNTER_BASE(c2), (d))
#define VSW_ETHER_DEC_IN_COUNTER_WITH_OCTETS(c1, c2, d, l) \
	vsw_ether_counter_dec_with_octets(_VSW_IN_COUNTER_BASE(c1), _VSW_IN_COUNTER_BASE(c2), (d), (l))
#define VSW_ETHER_DEC_OUT_COUNTER(c1, c2, d) \
	vsw_ether_counter_dec(_VSW_OUT_COUNTER_BASE(c1), _VSW_OUT_COUNTER_BASE(c2), (d))
#define VSW_ETHER_DEC_OUT_COUNTER_WITH_OCTETS(c1, c2, d, l) \
	vsw_ether_counter_dec_with_octets(_VSW_OUT_COUNTER_BASE(c1), _VSW_OUT_COUNTER_BASE(c2), (d), (l))

#define VSW_ETHER_UPDATE_IN_COUNTER(c1, c2, d, l) VSW_ETHER_INC_IN_COUNTER(c1, c2, d, l)
#define VSW_ETHER_UPDATE_OUT_COUNTER(c1, c2, d, l) VSW_ETHER_INC_OUT_COUNTER(c1, c2, d, l)

#endif /* VSW_ETHER_H_ */
