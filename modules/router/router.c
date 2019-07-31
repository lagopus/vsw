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

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <linux/rtnetlink.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <rte_ether.h>
#include <rte_malloc.h>

#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_udp.h>

#include "checksum.h"
#include "interface.h"
#include "ipproto.h"
#include "packet.h"
#include "pbr.h"
#include "reassemble.h"
#include "route.h"
#include "router.h"
#include "router_log.h"

// VNI
#define VXLAN_VNI_MASK (0xFFFFFF00)

#define IPV4_HDR_OPT_LEN(h) (((h)->version_ihl & IPV4_HDR_IHL_MASK) * \
				 IPV4_IHL_MULTIPLIER -                \
			     sizeof(struct ipv4_hdr))
#define DONT_RECORD_RR (uint32_t *)(-1)

typedef bool (*parse_options_t)(struct ipv4_hdr *, struct router_mbuf_metadata *,
				struct interface_table *);

static bool parse_options_rr_enable(struct ipv4_hdr *, struct router_mbuf_metadata *,
				    struct interface_table *);
static bool parse_options_rr_disable(struct ipv4_hdr *, struct router_mbuf_metadata *,
				     struct interface_table *);
static bool parse_options_rr_ignore(struct ipv4_hdr *, struct router_mbuf_metadata *,
				    struct interface_table *);

struct router_runtime {
	struct rte_hash *router_hash;
	bool running;

	struct rte_ring *notify; // receive notification from frontend.

	struct router_mempools mempools; // for fragmentation.

	struct rte_mbuf *mbufs[MAX_ROUTER_MBUFS];
};

uint32_t router_log_id = 0;

static bool
init_tables(struct router_context *ctx) {
	struct router_tables *tbls = &ctx->tables;

	// initialize tables.
	if (!(tbls->route = route_init(ctx->name))) {
		ROUTER_ERROR("router: %s: route table initialize failed.", ctx->name);
		return false;
	}
	if (!(tbls->neighbor = neighbor_init(ctx->name))) {
		ROUTER_ERROR("router: %s: neighbor table initialize failed.", ctx->name);
		// route finalize
		route_fini(tbls->route);
		rte_free(tbls->route);
		return false;
	}
	if (!(tbls->interface = interface_init(ctx->name))) {
		ROUTER_ERROR("router: %s: interface table initialize failed.", ctx->name);
		// route finalize
		route_fini(tbls->route);
		rte_free(tbls->route);
		// neighbor finalize
		neighbor_fini(tbls->neighbor);
		rte_free(tbls->neighbor);
		return false;
	}

	return true;
}

static void
update_logid() {
	int id = vsw_log_getid("router");
	if (id >= 0)
		router_log_id = (uint32_t)id;
}

static void
free_context(struct router_context *ctx) {
	struct router_tables *tbls = &ctx->tables;
	// finilize tables.
	route_fini(tbls->route);
	neighbor_fini(tbls->neighbor);
	interface_fini(tbls->interface);
	pbr_fini(tbls->pbr);

	// free tables.
	rte_free(tbls->route);
	rte_free(tbls->neighbor);
	rte_free(tbls->interface);
	rte_free(tbls->pbr);

	// free context
	rte_free(ctx);
}

// manage ribs

//
// packet handling
//

struct opt_base {
	uint8_t type;
	uint8_t len;
	uint8_t ptr;
};

// check_invalid_option checks whether an option is not invalid.
// It can check LSRR, SSRR and RR option.
static bool
check_invalid_option(struct opt_base *opt, int opt_hdr_len) {
	// check length field
	// the minimum value is 3 because the data area is optional.
	// the length should be (3 + 4n).
	if ((opt->len & 0x3) != 0x3 || opt->len > opt_hdr_len) {
		ROUTER_DEBUG("Invalid option length: %d\n", opt->len);
		return false;
	}

	// check pointer field
	// the minimum value is 4 and the pointer should be 4n.
	if (opt->ptr == 0 || opt->ptr & 0x3) {
		ROUTER_DEBUG("Invalid option pointer: %d\n", opt->ptr);
		return false;
	}
	return true;
}

// parse_options parses option header in IPv4 header. router can process the following options.
//   * End of Option List
//   * No Operation
//   * Loose Source and Record Route
//   * Strict Source and Record Route
//   * Record Route
// LSRR, SSRR and RR option require to record a route, and router should be able to select
// processing of them, so parse_options to be called depends on a setting.

// parse_options_rr_enable processes options that require to record a route as per RFC791.
// The route is recorded to RR options after a source ip address decided.
static bool
parse_options_rr_enable(struct ipv4_hdr *hdr, struct router_mbuf_metadata *rmd,
			struct interface_table *iface_table) {

	uint8_t *start_of_opt = (uint8_t *)(&hdr[1]);
	int opt_hdr_len = IPV4_HDR_OPT_LEN(hdr);
	int offset = 0;
	while (offset < opt_hdr_len) {
		struct opt_base *opt = (struct opt_base *)(start_of_opt + offset);

		switch (opt->type) {
		case IPOPT_END:
			return true;
		case IPOPT_NOOP:
			offset++;
			continue;
		case IPOPT_LSRR:
		case IPOPT_SSRR: {
			ROUTER_DEBUG("enable LSRR, SSRR(%u) option\n", opt->type);
			if (rmd->sr_loc) {
				ROUTER_ERROR("packet has multiple source route options.\n");
				return false;
			}
			if (!check_invalid_option(opt, opt_hdr_len - offset)) {
				ROUTER_ERROR("Invalid option header\n");
				return false;
			}

			// check destination address
			uint32_t dst_addr = ntohl(hdr->dst_addr);
			if (!INTERFACE_IS_SELF(iface_table, dst_addr)) {
				// SSRR
				if (opt->type == IPOPT_SSRR) {
					ROUTER_ERROR("SSRR: dst is not self\n");
					return false;
				}
				// LSRR
				ROUTER_DEBUG("LSRR: dst is not self\n");
				rmd->sr_loc = DONT_RECORD_RR;
				break;
			}

			// check whether the source route is empaty or not
			if (opt->ptr > opt->len) {
				ROUTER_DEBUG("LSRR, SSRR: all source routes are used\n");
				rmd->sr_loc = DONT_RECORD_RR;
				break;
			}

			rmd->sr_loc = (uint32_t *)((uint8_t *)opt + opt->ptr - 1);
			opt->ptr += 4;

			// replace destination address by source route
			rmd->cksum_diff += calc_chksum_diff_4byte(hdr->dst_addr, *rmd->sr_loc);
			hdr->dst_addr = *rmd->sr_loc;
			break;
		}
		case IPOPT_RR:
			ROUTER_DEBUG("enable RR(%u) option\n", opt->type);
			if (rmd->rr_loc) {
				ROUTER_ERROR("packet has multiple RR options.\n");
				return false;
			}
			if (!check_invalid_option(opt, opt_hdr_len - offset)) {
				ROUTER_ERROR("Invalid option header\n");
				return false;
			}

			// check whether the room to store route is full or not
			if (opt->ptr > opt->len) {
				ROUTER_DEBUG("RR: all rooms to store route are used\n");
				rmd->rr_loc = DONT_RECORD_RR;
				break;
			}

			rmd->rr_loc = (uint32_t *)((uint8_t *)opt + opt->ptr - 1);
			opt->ptr += 4;
			break;
		default:
			ROUTER_ERROR("Not supported option type(%u)\n", opt->type);
			return false;
		}
		offset += opt->len;
	}
	return true;
}

// parse_options_rr_disable drops packets with options that require to record a route.
static bool
parse_options_rr_disable(struct ipv4_hdr *hdr, struct router_mbuf_metadata *rmd,
			 struct interface_table *iface_table) {

	uint8_t *start_of_opt = (uint8_t *)(&hdr[1]);
	int opt_hdr_len = IPV4_HDR_OPT_LEN(hdr);
	int offset = 0;
	while (offset < opt_hdr_len) {
		struct opt_base *opt =
		    (struct opt_base *)(start_of_opt + offset);
		switch (opt->type) {
		case IPOPT_END:
			return true;
		case IPOPT_NOOP:
			offset++;
			continue;
		case IPOPT_LSRR:
		case IPOPT_SSRR:
		case IPOPT_RR:
			ROUTER_ERROR("RR process mode is disable.\n");
			return false;
		default:
			ROUTER_ERROR("Not supported option type(%u)\n", opt->type);
			return false;
		}
	}
	return true;
}

// parse_options_rr_ignore ignores options that require to record a route without processing
// of the options.
static bool
parse_options_rr_ignore(struct ipv4_hdr *hdr, struct router_mbuf_metadata *rmd,
			struct interface_table *iface_table) {

	uint8_t *start_of_opt = (uint8_t *)(&hdr[1]);
	int opt_hdr_len = IPV4_HDR_OPT_LEN(hdr);
	int offset = 0;
	while (offset < opt_hdr_len) {
		struct opt_base *opt =
		    (struct opt_base *)(start_of_opt + offset);

		switch (opt->type) {
		case IPOPT_END:
			return true;
		case IPOPT_NOOP:
			offset++;
			continue;
		case IPOPT_LSRR:
		case IPOPT_SSRR:
		case IPOPT_RR:
			ROUTER_DEBUG("ignore LSRR, SSRR and RR option(%u)", opt->type);
			break;
		default:
			ROUTER_ERROR("Not supported option type(%u)", opt->type);
			return false;
		}
		offset += opt->len;
	}
	return true;
}

#define MINIMUM_PACKET_LENGTH (sizeof(struct ipv4_hdr) + sizeof(struct ether_hdr))

/**
 * Validation IPv4 header
 */
static bool
check_ipv4_header(struct rte_mbuf *mbuf) {
	struct ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *,
							sizeof(struct ether_hdr));

	// check header length and version
	uint8_t header_len = ipv4->version_ihl & 0x0f;
	uint8_t version = (ipv4->version_ihl & 0xf0) >> 4;
	if (header_len < 5 || header_len > 15 || version != VERSION_IPV4) {
		// invalid data.
		ROUTER_DEBUG("invalid header (length = %d, version = %d)\n",
			     header_len, version);
		return false;
	}

	// Check packet length
	//
	// The length shall be at least IPv4 header (20octets) + Ether Header (14octets),
	// and shall not exceed mbuf->pkt_len.
	uint16_t length = rte_cpu_to_be_16(ipv4->total_length) + sizeof(struct ether_hdr);
	if (unlikely(length < MINIMUM_PACKET_LENGTH || length > mbuf->pkt_len)) {
		ROUTER_DEBUG("invalid packet length(len = %d, pkt_len = %d)\n",
			     length, mbuf->pkt_len);
		return false;
	}

	// Match mbuf->pkt_len to ether header + IPv4 total length.
	if (mbuf->pkt_len > length) {
		if (!mbuf->next) {
			mbuf->pkt_len = length;
			mbuf->data_len = length;
		} else {
			// If the mbuf is multi-segment, we just log an error.
			ROUTER_ERROR("Can't adjust pkt_len of multi-segment mbuf.");
		}
	}

	struct vsw_packet_metadata *md = VSW_MBUF_METADATA(mbuf);
	struct router_mbuf_metadata *rmd = (struct router_mbuf_metadata *)&md->udata;

	// Check fragment offset field in IPv4 header.
	bool df  = (ipv4->fragment_offset & rte_cpu_to_be_16(IPV4_HDR_DF_FLAG));
	bool mf	 = (ipv4->fragment_offset & rte_cpu_to_be_16(IPV4_HDR_MF_FLAG));
	bool off = (ipv4->fragment_offset & rte_cpu_to_be_16(IPV4_HDR_OFFSET_MASK));

	ROUTER_DEBUG("check_frag_field: fragment_offset = %04x, df=%d, mf=%d, offset=%d\n",
		     rte_be_to_cpu_16(ipv4->fragment_offset), df, mf, off);

	// MF and offset can be non-zero only if DF is not set.
	if (df && (mf || off)) {
		ROUTER_DEBUG("MF or offset is non-zero, but DF is set.");
		return false;
	}

	// validation header checksum
	uint16_t cksum = rte_raw_cksum(ipv4, (ipv4->version_ihl & 0x0f) * 4);
	if (cksum != 0xffff) {
		ROUTER_DEBUG("Bad checksum: %04x", cksum);
		return false;
	}

	// check option header
	rmd->has_option = (header_len > 5);

	ROUTER_DEBUG("total len: %u, hdr checksum: %u, version: %d, leader_len: %d\n",
		     length, ipv4->hdr_checksum, version, header_len);

	return true;
}

/**
 * Fragmentation big packet, use DPDK's API.
 */
static int
fragment_packet(struct rte_mbuf *in_mbuf, struct rte_mbuf **out_mbufs,
		uint16_t l3_mtu, struct router_mempools *pools) {
	// backup ether header
	struct ether_hdr orig_ehdr = *(struct ether_hdr *)
				      rte_pktmbuf_mtod((struct rte_mbuf *)in_mbuf, struct ether_hdr *);

	// temporally remove ether header for fragmentation
	if (rte_pktmbuf_adj(in_mbuf, (uint16_t)sizeof(struct ether_hdr)) == NULL) {
		ROUTER_FATAL("Adjusting mbuf for fragmentation failed.\n");
		return 0;
	}

	ROUTER_DEBUG("[FRAG] pkt len: %" PRIu32 "\n", in_mbuf->pkt_len);

	// fragmetation
	int frag_num = rte_ipv4_fragment_packet(in_mbuf, out_mbufs,
						(uint16_t)(RTE_LIBRTE_IP_FRAG_MAX_FRAG),
						l3_mtu, pools->direct_pool, pools->indirect_pool);

	if (frag_num < 0) {
		// fragmentation failed.
		ROUTER_ERROR("[FRAG] fragmetation failed: %s (%d)", rte_strerror(frag_num), frag_num);
		return 0;
	}

	ROUTER_DEBUG("[FRAG] fragmentation success, L3 MTU: %u, fragments: %d",
		     l3_mtu, frag_num);

	struct vsw_packet_metadata *md = VSW_MBUF_METADATA(in_mbuf);
	for (int i = 0; i < frag_num; i++) {
		struct rte_mbuf *out_mbuf = out_mbufs[i];

		// add ether header
		struct ether_hdr *ehdr = (struct ether_hdr *)
					 rte_pktmbuf_prepend(out_mbuf, (uint16_t)sizeof(struct ether_hdr));
		if (unlikely(ehdr == NULL)) {
			ROUTER_FATAL("Prepending mbuf to add ether header failed.\n");
			for (int j = 0; j < i; j++) {
				rte_pktmbuf_free(out_mbufs[j]);
				return 0;
			}
		}
		*ehdr = orig_ehdr;

		// copy VLAN TCI
		out_mbuf->vlan_tci = in_mbuf->vlan_tci;

		// calc ip checksum
		out_mbuf->ol_flags &= ~PKT_TX_IP_CKSUM; // do not offload hw.
		struct ipv4_hdr *ip =
		    rte_pktmbuf_mtod_offset((struct rte_mbuf *)out_mbuf,
					    struct ipv4_hdr *, sizeof(struct ether_hdr));
		ip->hdr_checksum = 0;
		ip->hdr_checksum = rte_ipv4_cksum(ip);
		ROUTER_DEBUG("[FRAG] new checksum = %x\n", ip->hdr_checksum);

		// copy packet metadata
		struct vsw_packet_metadata *outmd = VSW_MBUF_METADATA(out_mbuf);
		*outmd = *md;
	}

	return frag_num;
}

/**
 * Get network address.
 */
static inline uint32_t
get_networkaddr(uint32_t addr, uint8_t plen) {
	if (plen == 0)
		return 0;
	uint32_t mask = IPV4_MASK(plen);
	return addr & mask;
}

static bool
process_self_addressed_mbuf(struct router_instance *ri, struct rte_mbuf *mbuf) {
	struct ipv4_hdr *iphdr =
	    rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *, sizeof(struct ether_hdr));

	// If mbuf is a subsequent fragmented packets, we just
	// pass the mbuf to reassembling routine.
	if ((ntohs(iphdr->fragment_offset) & IPV4_HDR_OFFSET_MASK) > 0) {
		// Reassemble subsequent packets.
		reassemble_packet_process(ri, mbuf);
		return true;
	}

	// check ipip, gre, esp, vxlan.
	// send arp, icmp, ike, self unicast ip packets
	// and mismatched rule packets to send to tap.

	uint16_t dstport = 0;
	uint32_t vni = 0;

	// extract UDP dst port and VNI, if the packet is a UDP packet
	if (iphdr->next_proto_id == IPPROTO_UDP) {
		struct udp_hdr *udp_hdr = (struct udp_hdr *)rte_pktmbuf_mtod_offset(
					    mbuf, struct udp_hdr *,
					    sizeof(struct ether_hdr) +
					    sizeof(struct ipv4_hdr));
		dstport = ntohs(udp_hdr->dst_port);

		struct vxlan_hdr *vxlan_hdr = (struct vxlan_hdr *)rte_pktmbuf_mtod_offset(
						mbuf, struct vxlan_hdr *,
						sizeof(struct ether_hdr) +
						sizeof(struct ipv4_hdr) +
						sizeof(struct udp_hdr));
		vni = (ntohl(vxlan_hdr->vx_vni) & VXLAN_VNI_MASK) >> 8;
	}

	uint32_t srcip = ntohl(iphdr->src_addr);
	uint32_t dstip = ntohl(iphdr->dst_addr);

	// check for all rules.
	struct router_context *ctx = ri->ctx;
	struct router_rule *rules = ctx->rules;
	for (int i = 0; i < ctx->rules_count; i++) {
		struct rule *rule = &rules[i].rule;

		if (rule->proto != IPPROTO_ANY && rule->proto != iphdr->next_proto_id)
			continue;
		if (rule->srcip != 0 && rule->srcip != srcip)
			continue;
		if (rule->dstip != 0 && rule->dstip != dstip)
			continue;
		if (rule->dstport != 0 && rule->dstport != dstport)
			continue;
		if (rule->vni != 0 && rule->vni != vni)
			continue;

		// Fragmented packets shall be reassembled before sending to
		// the next module. If the packet is fragmented, we queue
		// the first fragment here.
		//
		// Note that mbufs with non-zero fragment offset are queued
		// before matching against rules. So they won't get here.
		// Only the first packet may reach here.
		if (ntohs(iphdr->fragment_offset) & IPV4_HDR_MF_FLAG) {
			// set ring information to the first packet metadata,
			// before reassembling.
			struct vsw_packet_metadata *md = VSW_MBUF_METADATA(mbuf);
			struct router_mbuf_metadata *rmd = (struct router_mbuf_metadata *)&md->udata;
			rmd->rr = rules[i].rr;

			if (!reassemble_packet_process_for_first_packet(ri, mbuf)) {
				ROUTER_ERROR("Failed to register first fragment.");
				rte_pktmbuf_free(mbuf);
				return false;
			}
			return true;
		}

		// prepare to enqueue mbuf
		mbuf_prepare_enqueue(rules[i].rr, mbuf);
		return true;
	}

	// send mbufs that didn't match to the rule.
	mbuf_prepare_enqueue(ctx->tap.rr, mbuf);
	return true;
}

/**
 * Lookup the outgoing interface for the packet.
 * It is from header check to header rewriting.
 *
 * Returns NULL if the packet shall be dropped.
 * Otherwise, outgoing interface is returned.
 */
static struct interface *
lookup(struct rte_mbuf *mbuf, struct router_context *ctx) {
	struct ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *,
							sizeof(struct ether_hdr));

	ROUTER_DEBUG("routing packet src addr: %s\n", ip2str(ntohl(ipv4->src_addr)));
	ROUTER_DEBUG("               dst addr: %s\n", ip2str(ntohl(ipv4->dst_addr)));

	// get mbuf metadata and router metadata.
	struct vsw_packet_metadata *md = VSW_MBUF_METADATA(mbuf);
	struct router_mbuf_metadata *rmd = (struct router_mbuf_metadata *)&md->udata;

	// check option header
	rmd->rr_loc = NULL;
	rmd->sr_loc = NULL;
	if (rmd->has_option) {
		if (!ctx->parse_options(ipv4, rmd, ctx->tables.interface))
			return NULL;
	}

	// get dst ip address from input packet.
	uint32_t dstip = ntohl(ipv4->dst_addr);

	// lookup radix trie for PBR.
	nexthop_t *nh = NULL;
	if (ctx->tables.pbr) {
		nh = pbr_entry_get(ctx->tables.pbr, mbuf);

		if (nh) {
			// drop the packet.
			if (nh->action == PBRACTION_DROP)
				return NULL;
			// pass the packet to route_entry_get().
			if (nh->action == PBRACTION_PASS)
				nh = NULL;
		}
	}

	// when nexthop is null,
	// pbr rule is not set or action is pass or can not found a pbr rule.
	if (!nh) {
		// lookup routing table
		nh = route_entry_get(&ctx->tables, dstip);
		if (!nh) {
			ROUTER_DEBUG("%s: route entry not found(dstip: %s).\n", ctx->name, ip2str(dstip));
			// to return unreacheable message by kernel.
			rmd->no_outbound_napt = true;
			return (struct interface *)&ctx->tap;
		}
	}

	uint32_t ip = nh->gw == 0 ? dstip : nh->gw;
	// Lookup the neighbor information.
	// If gw is not 0, the packet send to gw.
	neighbor_t *ne = neighbor_entry_get(ctx->tables.neighbor, ip);
	if (ne) {
		if (!nh->interface) {
			if (nh->ifindex != VIF_INVALID_INDEX) {
				// If ifindex of the nh is not VIF_INVALID_INDEX,
				// search interface information using that as a key.
				nh->interface = interface_entry_get(ctx->tables.interface, nh->ifindex);
				ROUTER_DEBUG("nexthop ifindex: %d", nh->ifindex);
			} else {
				// If ifindex of the nh is VIF_INVALID_INDEX,
				// prioritize neighbor information.
				nh->interface = interface_entry_get(ctx->tables.interface, ne->ifindex);
			}
		}
		ROUTER_DEBUG("[NEIGHBOR] ifindex: %d, ip: %s, mac: %s\n",
			     ne->ifindex, ip2str(ne->ip_addr), mac2str(ne->mac_addr));
	}

	struct interface *ie = nh->interface;
	if (!ie) {
		// drop this packet.
		ROUTER_INFO("interface is not found.\n");
		return NULL;
	}

	// check ttl and set checksum
	if (!(md->common.local)) {
		// A local flag is true, this packet was come from tunnel module,
		// at the time of encapsulation.
		if (likely(ipv4->time_to_live > 0)) {
			uint16_t oldvalue = *(uint16_t *)&ipv4->time_to_live;
			ipv4->time_to_live--;
			uint16_t newvalue = *(uint16_t *)&ipv4->time_to_live;

			rmd->cksum_diff += calc_chksum_diff_2byte(oldvalue, newvalue);
		}

		// if ttl is 0, stop forwarding and send to kernel.
		// expect to reply time exceeded.
		if (ipv4->time_to_live == 0) {
			// recalc cehcksum before send to kernel.
			// modify ip header because decremented ttl.
			rmd->no_outbound_napt = true;
			return (struct interface *)&ctx->tap;
		}
	}

	// If the output device is VRF, no need to process further.
	if (is_iff_type_vrf(&ie->base))
		return ie;

	md->common.out_vif = ie->base.ifindex;

	// Set MTU in the case the packet should sent to
	// tap as a locally originated packet.
	rmd->mtu = ie->base.mtu;

	// ARP resolution is required for for non-Tunnel device.
	if (!ne && !is_iff_type_tunnel(&ie->base)) {
		ROUTER_INFO("%s: no neighbor.\n", ctx->name);
		// to return unreacheable message by kernel.
		return (struct interface *)&ctx->tap;
	}

	// check broadcast
	switch (nh->broadcast_type) {
	case IPV4_NONSTANDARD_BROADCAST:
		ROUTER_INFO("IPV4_NONSTANDARD_BROADCAST\n");
		return NULL;

	case IPV4_LIMITED_BROADCAST:
		ROUTER_DEBUG("IPV4_LIMITED_BROADCAST");
		return (struct interface *)&ctx->tap;

	case IPV4_DIRECTED_BROADCAST:
		if (ie->directed_broadcast) {
			ROUTER_DEBUG("IPV4_DIRECTED_BROADCAST(enable)\n");
			return (struct interface *)&ctx->tap;
		} else {
			ROUTER_INFO("IPV4_DIRECTED_BROADCAST(disable)\n");
			return NULL;
		}

	default:
		break;
	}

	// need fragmentation packet
	if (ie->base.mtu < mbuf->pkt_len) {
		// DF bit is true, send to tap.
		if (ipv4->fragment_offset & rte_cpu_to_be_16(IPV4_HDR_DF_FLAG)) {
			ROUTER_DEBUG("DF bit is true, but fragmentation needed.\n");
			rmd->no_outbound_napt = true;
			return (struct interface *)&ctx->tap;
		}

		// We can't fragment packets with option header for now.
		// Drop the packet.
		if (rmd->has_option) {
			ROUTER_INFO("packet has option header, drop it.\n");
			return NULL;
		}
	}

	// update record route option
	if (rmd->has_option) {
		// get source ip address
		uint32_t src_addr = 0;
		uint32_t addr = ne ? ne->ip_addr : dstip;
		uint32_t nh_netaddr = get_networkaddr(addr, nh->netmask);
		for (int i = 0; i < ie->count; i++) {
			uint32_t plen = ie->addr[i].prefixlen;
			if (nh_netaddr == get_networkaddr(ie->addr[i].addr, plen)) {
				// set srouce interface address.
				src_addr = ie->addr[i].addr;
				break;
			}
		}
		ROUTER_DEBUG("self source address: %s\n", ip2str(src_addr));

		// update record route option
		src_addr = htonl(src_addr);
		if (rmd->rr_loc != NULL && rmd->rr_loc != DONT_RECORD_RR) {
			rmd->cksum_diff += calc_chksum_diff_4byte(*rmd->rr_loc, src_addr);
			*rmd->rr_loc = src_addr;
		}
		if (rmd->sr_loc != NULL && rmd->sr_loc != DONT_RECORD_RR) {
			rmd->cksum_diff += calc_chksum_diff_4byte(*rmd->sr_loc, src_addr);
			*rmd->sr_loc = src_addr;
		}
	}

	if (!is_iff_type_tunnel(&ie->base)) {
		// rewrite ether header
		struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
		ether_addr_copy(&ie->base.mac, &(eth_hdr->s_addr));
		ether_addr_copy(&ne->mac_addr, &(eth_hdr->d_addr));

		// rewrite vlan id.
		if (ie->base.vid != 0)
			mbuf->vlan_tci = ie->base.vid;
	}

	ROUTER_DEBUG("%s: forwarding[in:%d -> out:%d], vid[%d]",
		     ctx->name, md->common.in_vif, ie->base.ifindex, ie->base.vid);
	return ie;
}

static struct napt *
get_napt(struct rte_hash *hash, vifindex_t vif) {
	uint32_t index = (uint32_t)vif;
	struct interface *iface;

	int ret = rte_hash_lookup_data(hash, &index, (void **)&iface);
	if (unlikely(ret < 0)) {
		ROUTER_ERROR("NAPT: Can't find VIF %u", index);
		return NULL;
	}

	return iface->napt;
}

/**
 * Perform packet routing processing for each packet.
 * Lookup route per packet.
 * TODO: Send burst same packets.
 */
static void
routing_packets(struct router_runtime *runtime, struct router_instance *ri, uint32_t count) {
	struct router_context *ctx = ri->ctx;
	if (runtime == NULL || ctx == NULL) {
		ROUTER_ERROR("router: invalid argument. runtime: %p, ctx: %p", runtime, ctx);
		return;
	}

	// For NAPT
	struct rte_hash *ihash = ctx->tables.interface->hashmap;
	vifindex_t vifindex = VIF_INVALID_INDEX;
	struct napt *napt = NULL;

	struct rte_mbuf **mbufs = runtime->mbufs;
	for (int n = 0; n < count; n++) {
		struct rte_mbuf *mbuf = mbufs[n];
		struct vsw_packet_metadata *md = VSW_MBUF_METADATA(mbuf);
		struct router_mbuf_metadata *rmd = (struct router_mbuf_metadata *)&md->udata;

		// reset user data
		memset(rmd, 0, sizeof(struct router_mbuf_metadata));

		// If to_tap flag is true, then send packet to tap(kernel).
		// To_tap is set by tunnel module to forward IKE packets to iked.
		// Validity of packet is guaranteed as it has been checked before
		// the packet is forwarded to tunnel from the router.
		if (md->common.to_tap) {
			mbuf_prepare_enqueue(ctx->tap.rr, mbuf);
			continue;
		}

		// Pass ARP packets to the kernel. We don't bother doing the rest.
		struct ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
		if (hdr->ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP)) {
			ROUTER_DEBUG("Send arp packet to kernel.");
			mbuf_prepare_enqueue(ctx->tap.rr, mbuf);
			continue;
		}

		// We don't care none-IPv4 Packets
		if (hdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
			ROUTER_DEBUG("Ignore none-IPv4 packets.");
			rte_pktmbuf_free(mbuf);
			continue;
		}

		// Check IPv4 Header
		if (!check_ipv4_header(mbuf)) {
			//drop a packet.
			ROUTER_DEBUG("Invalid IPv4 packet.");
			rte_pktmbuf_free(mbuf);
			continue;
		}

		// NAPT: process inbound
		if ((ctx->napt_count > 0) && (!md->common.local)) {
			if (unlikely(md->common.in_vif != vifindex)) {
				vifindex = md->common.in_vif;
				napt = get_napt(ihash, vifindex);
			}

			if (napt) {
				if (napt_inbound(napt, mbuf)) {
					ROUTER_DEBUG("NAPT: processed inbound");
				} else {
					ROUTER_DEBUG("NAPT: ignored inbound");
				}
			}
		}

		struct ipv4_hdr *ipv4 =
		    rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *, sizeof(struct ether_hdr));
		// get dst ip address from input packet.
		uint32_t dstip = ntohl(ipv4->dst_addr);
		// drop a broadcast packet.
		if (dstip == 0xFFFFFFFF) {
			mbuf_prepare_enqueue(ctx->tap.rr, mbuf);
			continue;
		}
		if (dstip == 0) {
			rte_pktmbuf_free(mbuf);
			continue;
		}

		// check all self interfaces.
		if (INTERFACE_IS_SELF(ctx->tables.interface, dstip)) {
			if (!process_self_addressed_mbuf(ri, mbuf)) {
				ROUTER_DEBUG("Failed to process self-addressed packet.");
				// We do not need to free mbuf here.
				// Mbuf is freed in process_self_addressed_mbuf().
			}
			continue;
		}

		// lookup the appropriate route for the mbuf.
		// set interface information to flag_size in lookup().
		struct interface *ie = lookup(mbuf, ctx);
		if (!ie) {
			rte_pktmbuf_free(mbuf);
			continue;
		}

		// If we updated the IPv4 header, update the checksum.
		if (rmd->cksum_diff > 0) {
			struct ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *,
									sizeof(struct ether_hdr));
			update_cksum(&ipv4->hdr_checksum, rmd->cksum_diff);
			rmd->cksum_diff = 0;
		}

		// If we are sending to VRF, no need to process the rest.
		if (is_iff_type_vrf(&ie->base)) {
			mbuf_prepare_enqueue(ie->base.rr, mbuf);
			continue;
		}

		// NAPT: process outbound
		if ((!rmd->no_outbound_napt) &&
		    (ctx->napt_count > 0) &&
		    (md->common.out_vif != VIF_INVALID_INDEX)) {
			if (unlikely(md->common.out_vif != vifindex)) {
				vifindex = md->common.out_vif;
				napt = get_napt(ihash, vifindex);
			}

			if (napt) {
				if (napt_outbound(napt, mbuf)) {
					ROUTER_DEBUG("NAPT: processed outbound");

					// If the destination is not resolved yet, it must be sent out
					// as a local originated packet.
					if (is_iff_type_tap(&ie->base))
						md->common.local = true;
				} else {
					ROUTER_DEBUG("NAPT: ignored outbound");
					rte_pktmbuf_free(mbuf);
					continue;
				}
			}
		}

		bool tap_rx = false;
		size_t mtu;

		if (md->common.local) {
			mtu = rmd->mtu;
		} else {
			mtu = ie->base.mtu;
			tap_rx = is_iff_type_tap(&ie->base);
		}

		//
		// No need to fragment in the following cases:
		// - DF bit is 1.
		// - Packet length is shorter or equal to MTU on the interface.
		// - Sending incoming (RX) packets to TAP (e.g. ICMP Echo Request).
		//
		// All other cases require frgamentation.
		//
		if ((ipv4->fragment_offset & rte_cpu_to_be_16(IPV4_HDR_DF_FLAG) ||
		    (mtu >= mbuf->pkt_len) || (tap_rx))) {
			mbuf_prepare_enqueue(ie->base.rr, mbuf);
		} else {
			struct rte_mbuf *mbufs[RTE_LIBRTE_IP_FRAG_MAX_FRAG];

			uint16_t l3_mtu = mtu - sizeof(struct ether_hdr);
			int count = fragment_packet(mbuf, mbufs, l3_mtu, &runtime->mempools);

			if (count > 0) {
				for (int i = 0; i < count; i++)
					mbuf_prepare_enqueue(ie->base.rr, mbufs[i]);
			} else {
				ROUTER_INFO("router: error: fragmentation failed\n");
			}

			// free original input mbuf.
			rte_pktmbuf_free(mbuf);
		}
	}

	// bulk transfer mbufs if needed
	for (int i = 0; i < ctx->rr_count; i++) {
		struct router_ring *rr = ctx->rrp[i];

		if (rr->count == 0)
			continue;

		mbuf_flush(rr);
	}
}

parse_options_t parse_options[] = {
	[RECORDROUTE_DISABLE] = parse_options_rr_disable,
	[RECORDROUTE_IGNORE] = parse_options_rr_ignore,
	[RECORDROUTE_ENABLE] = parse_options_rr_enable,
};

static bool
router_register_instance(void *p, struct vsw_instance *base) {
	struct router_runtime *r = p;
	struct router_instance *ri = (struct router_instance *)base;

	// set router context
	ri->ctx = rte_zmalloc(NULL, sizeof(struct router_context), 0);
	if (ri->ctx == NULL) {
		ROUTER_ERROR("router: %s: rte_zmalloc() failed.", ri->base.name);
		return false;
	}

	ri->ctx->name = ri->base.name;
	ri->ctx->parse_options = parse_options[ri->rr_mode];

	if (!init_tables(ri->ctx)) {
		ROUTER_ERROR("router: %s: init talbes failed.", base->name);
		return false;
	}

	if (rte_hash_add_key_data(r->router_hash, &ri->base.id, ri) < 0) {
		ROUTER_ERROR("router: Can't add router %s", base->name);
		free_context(ri->ctx);
		return false;
	}

	if (!reassemble_init(ri)) {
		free_context(ri->ctx);
		return false;
	}
	memset(&ri->death_row, 0, sizeof(struct rte_ip_frag_death_row));
	return true;
}

static bool
router_unregister_instance(void *p, struct vsw_instance *base) {
	struct router_runtime *r = p;
	struct router_instance *ri = (struct router_instance *)base;
	ROUTER_DEBUG("%s(%d)", __func__, __LINE__);

	reassemble_fini(ri);

	free_context(ri->ctx);
	if (rte_hash_del_key(r->router_hash, &ri->base.id) < 0)
		return false;

	return true;
}

/**
 * rule_add adds rule from frontend.
 * TODO: use radix trie.
 */
static bool
rule_add(struct router_context *ctx, struct router_rule *r) {
	if (ctx->rules_count == ROUTER_RULE_MAX) {
		ROUTER_INFO("rules table is full.");
		return false;
	}

	r->rr = get_router_ring(ctx, r->ring);
	if (r->rr == NULL) {
		ROUTER_ERROR("rule_add(): can't get router_ring");
		return false;
	}

	// output info(ring, rule, mbuf)
	ctx->rules[ctx->rules_count] = *r;
	ctx->rules_count++;

	return true;
}

/**
 * rule_delete adds rule from frontend.
 * TODO: use radix trie.
 */
static bool
rule_delete(struct router_context *ctx, struct router_rule *r) {

	for (int i = 0; i < ctx->rules_count; i++) {
		struct router_rule *o = &ctx->rules[i];

		if ((o->ring == r->ring) &&
		    (o->rule.dstip == r->rule.dstip) &&
		    (o->rule.srcip == r->rule.srcip) &&
		    (o->rule.proto == r->rule.proto) &&
		    (o->rule.vni == r->rule.vni) &&
		    (o->rule.dstport == r->rule.dstport)) {
			put_router_ring(ctx, o->rr);
			ctx->rules_count--;
			ctx->rules[i] = ctx->rules[ctx->rules_count];
		}
	}

	return false;
}

/**
 * Enable NAPT
 */
bool
napt_enable(struct router_context *ctx, struct napt_config *c) {
	struct interface_table *itbl = ctx->tables.interface;
	struct interface *iface;
	uint32_t index = (uint32_t)c->vif;

	int ret = rte_hash_lookup_data(itbl->hashmap, &index, (void **)&iface);

	if (unlikely(ret < 0)) {
		ROUTER_ERROR("NAPT: Can't find VIF %u (%d)", c->vif, ret);
		return false;
	}

	if (iface->napt != NULL) {
		ROUTER_ERROR("NAPT: Already enabled on VIF %u", c->vif);
		return false;
	}

	if ((iface->napt = napt_create(c)) == NULL) {
		ROUTER_ERROR("NAPT: Can't enable on VIF %u", c->vif);
		return false;
	}

	ctx->napt_count++;

	return true;
}

/**
 * Disable NAPT
 */
bool
napt_disable(struct router_context *ctx, vifindex_t *vif) {
	struct interface_table *itbl = ctx->tables.interface;
	struct interface *iface;
	uint32_t index = (uint32_t)(*vif);

	int ret = rte_hash_lookup_data(itbl->hashmap, &index, (void **)&iface);

	if (unlikely(ret < 0)) {
		ROUTER_ERROR("NAPT: Can't find VIF %u", *vif);
		return false;
	}

	if (iface->napt == NULL) {
		ROUTER_ERROR("NAPT: NAPT not enabled on VIF %u", *vif);
		return false;
	}

	napt_free(iface->napt);
	iface->napt = NULL;

	ctx->napt_count--;

	return true;
}

static bool
router_control_instance(void *p, struct vsw_instance *base, void *param) {
	struct router_instance *ri = (struct router_instance *)base;
	struct router_control_param *rp = param;

	struct router_context *ctx = ri->ctx;
	struct neighbor_table *nt = ctx->tables.neighbor;
	struct interface_table *it = ctx->tables.interface;
	struct pbr_table *pt = ctx->tables.pbr;

	struct router_rule *rule = rp->info;
	struct route_entry *re = rp->info;
	struct neighbor_entry *ne = rp->info;
	struct interface_entry *ie = rp->info;
	struct interface_addr_entry *ia = rp->info;
	struct pbr_entry *pe = rp->info;

	// check if there's any control message from the frontend.
	// pre check
	switch (rp->cmd) {
	case ROUTER_CMD_ENABLE:
		ctx->active = true;
		break;
	case ROUTER_CMD_DISABLE:
		ctx->active = false;
		break;

	case ROUTER_CMD_CONFIG_TAP:
		ctx->tap.ring = (struct rte_ring *)rp->info;
		ctx->tap.rr = get_router_ring(ctx, ctx->tap.ring);
		ctx->tap.flags = IFF_TYPE_TAP;
		break;

	case ROUTER_CMD_RULE_ADD:
		return rule_add(ctx, rule);

	case ROUTER_CMD_RULE_DELETE:
		return rule_delete(ctx, rule);

	case ROUTER_CMD_PBRRULE_ADD:
		if (!pt) {
			if (!(pt = pbr_init(ctx->name)))
				return false;
			ctx->tables.pbr = pt;
		}
		if (!pbr_entry_add(&ctx->tables, pe)) {
			ROUTER_ERROR("%s: Failed to add pbr rule.", ctx->name);
			return false;
		}
		break;

	case ROUTER_CMD_PBRRULE_DELETE:
		if (!pt)
			return false;

		if (!pbr_entry_delete(pt, pe)) {
			ROUTER_ERROR("%s: Failed to delete pbr entry.", ctx->name);
			return false;
		}
		break;
	// manage the rib
	case ROUTER_CMD_ROUTE_ADD:
		if (!route_entry_add(&ctx->tables, re)) {
			ROUTER_ERROR("%s: Failed to add route.", ctx->name);
			return false;
		}
		break;

	case ROUTER_CMD_ROUTE_DELETE:
		if (!route_entry_delete(&ctx->tables, re)) {
			ROUTER_ERROR("%s: Failed to delete route.", ctx->name);
			return false;
		}
		break;

	case ROUTER_CMD_NEIGH_ADD:
		if (!neighbor_entry_update(nt, ne)) {
			ROUTER_ERROR("%s: Failed to add neighbor entry", ctx->name);
			return false;
		}
		break;

	case ROUTER_CMD_NEIGH_DELETE:
		if (!neighbor_entry_delete(nt, ne)) {
			ROUTER_ERROR("%s: Failed to delete neighbor entry", ctx->name);
			return false;
		}
		break;

	case ROUTER_CMD_VIF_ADD:
		if (!interface_entry_add(ctx, ie)) {
			ROUTER_ERROR("%s: Failed to add interface.", ctx->name);
			return false;
		}
		break;

	case ROUTER_CMD_VIF_DELETE:
		if (!interface_entry_delete(ctx, ie)) {
			ROUTER_ERROR("%s: Failed to delete interface.", ctx->name);
			return false;
		}
		break;

	case ROUTER_CMD_VIF_ADD_IP:
		if (!interface_ip_add(it, ia)) {
			ROUTER_ERROR("%s: Failed to add IP address to VIF %u.", ctx->name, ia->ifindex);
			return false;
		}
		break;

	case ROUTER_CMD_VIF_DELETE_IP:
		if (!interface_ip_delete(it, ia)) {
			ROUTER_ERROR("%s: Failed to delete IP address from VIF %u.", ctx->name, ia->ifindex);
			return false;
		}
		break;

	case ROUTER_CMD_VIF_UPDATE_MTU:
		if (!interface_mtu_update(it, ie)) {
			ROUTER_ERROR("%s: Failed to update MTU at VIF %u.", ctx->name, ie->ifindex);
			return false;
		}
		break;

		// When the interface information is deleted,
		// must be clear route informations using the interface.
		// But, deleting an route entry,
		// follow the instructions of the netlink.
		// Therefore, it is not deleted here. arp too.

	case ROUTER_CMD_NAPT_ENABLE:
		if (!napt_enable(ctx, (struct napt_config *)rp->info)) {
			ROUTER_ERROR("%s: Failed to enable NAPT.", ctx->name);
			return false;
		}
		break;

	case ROUTER_CMD_NAPT_DISABLE:
		if (!napt_disable(ctx, (vifindex_t *)rp->info)) {
			ROUTER_ERROR("%s: Failed to disable NAPT.", ctx->name);
			return false;
		}
		break;

	default:
		ROUTER_ERROR("Unsupported command(%d).\n", rp->cmd);
		return false;
	}
	return true;
}

static void *
router_init(void *param) {
	static_assert(sizeof(struct router_mbuf_metadata) <= sizeof(((struct vsw_packet_metadata*)0)->udata),
		      "Size of struct router_mbuf_metadata is too big!");

	struct router_runtime *r;
	struct router_runtime_param *p = param;

	update_logid();

	ROUTER_DEBUG("start router init.");

	if (!(r = rte_zmalloc(NULL, sizeof(struct router_runtime), 0))) {
		ROUTER_ERROR("rte_zmalloc() failed. Can't start.");
		return NULL;
	}

	// Create hash table for router instances
	struct rte_hash_parameters hash_params = {
	    .name = "routers",
	    .entries = MAX_ROUTERS,
	    .key_len = sizeof(uint64_t),
	    .hash_func = rte_jhash,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	if ((r->router_hash = rte_hash_create(&hash_params)) == NULL) {
		rte_free(r);
		return NULL;
	}

	// Set mempools for fragmentation process.
	r->mempools.direct_pool = p->pool;
	r->mempools.indirect_pool =
	    rte_pktmbuf_pool_create("pool_indirect", 4096, 32, 0,
				    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (r->mempools.indirect_pool == NULL) {
		rte_hash_free(r->router_hash);
		rte_free(r);
		ROUTER_ERROR("router: ERROR: Cannot create indirect mempool: %s",
			     rte_strerror(rte_errno));
		return NULL;
	}
	return r;
}

static bool
router_process(void *p) {
	struct router_runtime *r = p;
	uint32_t next = 0;
	uint64_t *id;
	struct router_instance *ri;

	while (rte_hash_iterate(r->router_hash, (const void **)&id, (void **)&ri, &next) >= 0) {
		if (!ri->base.enabled)
			continue;

		unsigned count = rte_ring_dequeue_burst(ri->base.input, (void **)r->mbufs, MAX_ROUTER_MBUFS, NULL);
		if (count > 0) {
			ROUTER_DEBUG("name = %s count = %d ----------", ri->base.name, count);

			//--- packet routing ---//
			routing_packets(r, ri, count);
		}
	}

	return true;
}

static void
router_deinit(void *p) {
	struct router_runtime *r = p;
	uint64_t *id;
	uint32_t next = 0;
	struct router_instance *ri;

	ROUTER_DEBUG("%s(%d)", __func__, __LINE__);

	// free context
	while (rte_hash_iterate(r->router_hash, (const void **)&id, (void **)&ri, &next) >= 0) {
		free_context(ri->ctx);

		// free fragmentation table.
		rte_ip_frag_table_destroy(ri->frag_tbl);
	}

	// free hash table
	rte_hash_free(r->router_hash);
	// free mempool
	rte_mempool_free(r->mempools.indirect_pool);
	// free runtime
	rte_free(r);
	return;
}

struct vsw_runtime_ops router_runtime_ops = {
    .init = router_init,
    .process = router_process,
    .deinit = router_deinit,
    .register_instance = router_register_instance,
    .unregister_instance = router_unregister_instance,
    .update_rings = NULL,
    .control_instance = router_control_instance,
};
