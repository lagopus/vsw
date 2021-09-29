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

#include "lagopus_apis.h"

#include "vxlan_includes.h"
#include "fdb.h"
#include "eventq.h"
#include "udp.h"
#include "vlan.h"
#include "metadata.h"
#include "mbuf.h"

#define CTOR_IDX (LAGOPUS_MODULE_CONSTRUCTOR_INDEX_BASE + 1)

static void ctors(void) __attr_constructor__(CTOR_IDX);
static void dtors(void) __attr_destructor__(CTOR_IDX);
static pthread_once_t once = PTHREAD_ONCE_INIT;

static lagopus_hashmap_t fdbs = NULL;
static lagopus_bbq_t eventq = NULL; /* use inbound only. */

struct vxlan_runtime {
  l2tun_iface_list_t *iface_list;
};

struct traffic_type {
  struct rte_mbuf *pkts[MAX_PKTS_WITH_FLOOD];
  uint32_t num;
};

struct event {
  struct eventq_entry entries[EVENTQ_SIZE];
  uint32_t num;
};

struct vxlan_traffic {
  struct traffic_type out;
  struct traffic_type encap; /* per packet. */
  uint32_t flood_pkts_num;
};

static inline lagopus_result_t
vxlan_put_events(struct eventq_entry *entries,
                 size_t num) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(entries != NULL)) {
    if (unlikely(eventq != NULL)) {
      ret = event_queue_puts(&eventq, entries, num);
    } else {
      ret = LAGOPUS_RESULT_INVALID_OBJECT;
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  if (likely(ret >= 0)) {
    ret = LAGOPUS_RESULT_OK;
  } else {
    TUNNEL_PERROR(ret);
  }

  return ret;
}

/* packets process. */

static inline bool
vxlan_is_ready(struct l2tun_iface *iface) {
  uint16_t output_vid;

  if (likely(iface->enabled && !iface->trunk)) {
    output_vid = iface->access_vid;
    if (iface->vlans[output_vid] != NULL &&
        iface->vlans[output_vid]->output != NULL) {
      return true;
    }
  }

  return false;
}

static inline lagopus_result_t
prepare_one_packet_inbound(struct rte_mbuf **m) {
  struct ether_hdr *eth;

  /* Linearize mbuf. */
  /* NOTE: 'cal UDP checksum' doesn't support segmented mbuf. */
  if (unlikely(rte_pktmbuf_linearize(*m) != 0)) {
    /* not enough tailroom: drop the packet. */
    TUNNEL_ERROR("Not enough tailroom.");
    return LAGOPUS_RESULT_NO_MEMORY;
  }

  if (unlikely((*m)->pkt_len < sizeof(struct ether_hdr))) {
    TUNNEL_ERROR("Bad packet length.");
    return LAGOPUS_RESULT_UNSUPPORTED;
  }

  eth = rte_pktmbuf_mtod(*m, struct ether_hdr *);
  if (unlikely(eth->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4) &&
               eth->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv6))) {
    TUNNEL_ERROR("Unsupported packet type: %d.",
                 rte_be_to_cpu_16(eth->ether_type));
    return LAGOPUS_RESULT_UNKNOWN_PROTO;
  }

  /* Flooding packet. */
  if (unlikely(IS_FLOODING(*m))) {
    /* Flooding packet: drop the packet */
    TUNNEL_ERROR("Flooding packet.");
    return LAGOPUS_RESULT_UNSUPPORTED;
  }

  return LAGOPUS_RESULT_OK;
}

static lagopus_result_t
prepare_one_packet_outbound(struct rte_mbuf **m) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct rte_mbuf *dst_mbuf;

  if (unlikely((*m)->pkt_len < sizeof(struct ether_hdr))) {
    TUNNEL_ERROR("Bad packet length.");
    return LAGOPUS_RESULT_UNSUPPORTED;
  }

  /* Flooding packet. */
  if (unlikely(IS_FLOODING(*m))) {
    ret = mbuf_clone(&dst_mbuf, *m, (*m)->pool);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      return ret;
    }
    /* NOTE: Not free src mbuf.                   */
    /*       Indirect mbuf is automatically free. */
    *m = dst_mbuf;
  }

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
prepare_one_packet(struct l2tun_iface *iface,
                   struct rte_mbuf **m) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct vxlan_iface_metadata *iface_md = VXLAN_IFACE_METADATA(iface);

  ret = iface_md->prepare_one_packet_proc(m);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    return ret;
  }

  rte_prefetch0(rte_pktmbuf_mtod(*m, void *));
  return LAGOPUS_RESULT_OK;
}

static inline void
vxlan_sent_pkts(struct l2tun_iface *iface,
                struct rte_mbuf **out_mbufs,
                size_t out_mbufs_num) {
  uint32_t send = 0;
  size_t i;

  if (out_mbufs_num > 0) {
    send = rte_ring_enqueue_burst(iface->vlans[iface->access_vid]->output,
                                  (void *const *) out_mbufs,
                                  out_mbufs_num,
                                  NULL);
    /* free. */
    if (unlikely(out_mbufs_num != send)) {
      for (i = send; i < out_mbufs_num; i++) {
        /* update dropped stats. */
        l2tun_update_dropped(iface, iface->vlans[iface->access_vid],
                             out_mbufs[i]);
        /* drop packets. */
        rte_pktmbuf_free(out_mbufs[i]);
      }
    }
  }
}

/* inbound. */

static inline lagopus_result_t
vxlan_decap(struct l2tun_iface *iface,
            struct rte_mbuf *m) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct vxlan_mbuf_metadata *metadata = get_priv(m);
  struct ether_hdr *ether_hdr;
  struct vxlan_hdr *vxlan_hdr;
  struct udp_hdr *udp_hdr;
  struct ipv4_hdr *ip_hdr;
  struct ipv6_hdr *ip6_hdr;
  uint8_t proto;

  if (unlikely(iface->trunk)) {
    /* trunk mode.  */
    /* unsupported. */
    ret = LAGOPUS_RESULT_UNSUPPORTED;
    TUNNEL_ERROR("[%s] unsupported trunk mode: %d", iface->base.name, ret);
    return ret;
  }

  /* set keep_ttl metadata. */
  set_meta_keep_ttl(m);

  ret = set_meta_vif(m, iface->vlans[iface->access_vid]->index);
  if (unlikely((ret != LAGOPUS_RESULT_OK))) {
    TUNNEL_PERROR(ret);
    return ret;
  }

  /* Ether. */
  ret = decap_ether(m, &ether_hdr);
  if (unlikely((ret != LAGOPUS_RESULT_OK))) {
    TUNNEL_ERROR("[%s] decap Ether: %d", iface->base.name, ret);
    return ret;
  }

  /* IP. */
  switch (ether_hdr->ether_type) {
    case ETHER_TYPE_IPv4_BE:
      /* IPv4. */
      ret = decap_ip4(m, 0, &ip_hdr);
      if (unlikely((ret != LAGOPUS_RESULT_OK))) {
        TUNNEL_ERROR("[%s] decap IPv4: %d", iface->base.name, ret);
        return ret;
      }
      proto = ip_hdr->next_proto_id;
      break;
    case ETHER_TYPE_IPv6_BE:
      /* IPv6. */
      ret = decap_ip6(m, 0, &ip6_hdr);
      if (unlikely((ret != LAGOPUS_RESULT_OK))) {
        TUNNEL_ERROR("[%s] decap IPv6: %d", iface->base.name, ret);
        return ret;
      }
      proto = ip6_hdr->proto;
      ip_hdr = (struct ipv4_hdr *) ip6_hdr;
      break;
    default:
      TUNNEL_ERROR("[%s] Bad IP version", iface->base.name);
      return LAGOPUS_RESULT_UNKNOWN_PROTO;
  }

  if (unlikely(proto != IPPROTO_UDP)) {
    TUNNEL_ERROR("[%s] Unknown IP next proto: %d", iface->base.name, proto);
    return LAGOPUS_RESULT_UNKNOWN_PROTO;
  }

  metadata->outer_ip = (struct ip *) ip_hdr;

  /* UDP. */
  ret = decap_udp(m, NULL,
                  0 /* ether_type is 0, because disable cal checksum */,
                  false, &udp_hdr);
  if (unlikely((ret != LAGOPUS_RESULT_OK))) {
    TUNNEL_ERROR("[%s] decap UDP: %d", iface->base.name, ret);
    return ret;
  }

  /* Valid checksum. (RFC7348, section 5) */
  if (unlikely(udp_hdr->dgram_cksum != 0)) {
    ret = udp_valid_checksum(ether_hdr->ether_type, (void *) ip_hdr,
                             (void *) udp_hdr);
    if (unlikely((ret != LAGOPUS_RESULT_OK))) {
      TUNNEL_ERROR("[%s] Bad checksum: %d", iface->base.name, ret);
      return ret;
    }
  }

  /* VXLAN. */
  ret = decap_vxlan(m, iface->vni, &vxlan_hdr);
  if (unlikely((ret != LAGOPUS_RESULT_OK))) {
    TUNNEL_ERROR("[%s] decap VXLAN: %d", iface->base.name, ret);
    return ret;
  }

  /* VLAN. */
  /* access mode only. */
  ret = vlan_set_stripped(m, iface->access_vid);

  if (unlikely((ret != LAGOPUS_RESULT_OK))) {
    TUNNEL_ERROR("[%s] Can't pop/set metadata VLAN: %d", iface->base.name, ret);
    return ret;
  }

  /* set inner dst address type(for stats). */
  set_meta_inner_dst_ether_addr_type(m);
  /* set inner packet bytes(for stats). */
  set_meta_inner_pkt_bytes(m);

  metadata->inner_ether_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
vxlan_fdb_learn(struct l2tun_iface *iface,
                struct rte_mbuf *m,
                struct event *event) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct vxlan_mbuf_metadata *metadata;
  struct fdb_entry *entry;
  struct vxlan_iface_metadata *iface_md = VXLAN_IFACE_METADATA(iface);

  metadata = get_priv(m);
  ret = fdb_learn(iface_md->fdb, &metadata->inner_ether_hdr->s_addr,
                  metadata->outer_ip, &entry);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    return ret;
  }

  if (entry != NULL && !fdb_entry_is_referred(entry)) {
    /* new entry. create event. */
    eventq_entry_set(&event->entries[event->num++],
                     L2TUN_CMD_FDB_LEARN, iface->vni,
                     entry);
    TUNNEL_DEBUG("FDB (VNI = %d): Learn: mac = "ETHADDR_FORMAT,
                 iface->vni, ETHADDR_TO_ARRAY(entry->mac));
  }

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
vxlan_inbound_one_packet(struct l2tun_iface *iface,
                         struct rte_mbuf *m,
                         struct vxlan_traffic *t,
                         struct event *event) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  /* prepare. */
  ret = prepare_one_packet(iface, &m);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    goto free;
  }

  /* decap. */
  ret = vxlan_decap(iface, m);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    goto free;
  }

  /* learn. */
  ret = vxlan_fdb_learn(iface, m, event);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    goto free;
  }

free:
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    /* drop packet. */
    if (ret == LAGOPUS_RESULT_UNKNOWN_PROTO) {
      l2tun_update_unknown_protos(iface);
    } else {
      l2tun_update_errors(iface);
    }
    rte_pktmbuf_free(m);
    return ret;
  }

  /* update stats. */
  l2tun_update_stats(iface, iface->vlans[iface->access_vid], m);

  /* add packets for sent. */
  t->out.pkts[t->out.num++] = m;

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
vxlan_inbound(struct l2tun_iface *iface, struct rte_mbuf **mbufs,
              size_t mbufs_num) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct vxlan_iface_metadata *iface_md = VXLAN_IFACE_METADATA(iface);
  struct vxlan_traffic traffic = {0};
  struct event event = {0};
  size_t i;

  if (unlikely(iface_md->fdb == NULL)) {
    ret = LAGOPUS_RESULT_INVALID_OBJECT;
    TUNNEL_PERROR(ret);
    goto done;
  }

  /* process per packet. */
  for (i = 0; i < mbufs_num; i++) {
    ret = vxlan_inbound_one_packet(iface, mbufs[i],
                                   &traffic, &event);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      /* process the next packet. */
      ret = LAGOPUS_RESULT_OK;
      continue;
    }
  }

  /* sent next module. */
  vxlan_sent_pkts(iface, traffic.out.pkts, traffic.out.num);

done:
  if (likely(ret == LAGOPUS_RESULT_OK)) {
    /* put events. */
    ret = vxlan_put_events(event.entries, event.num);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
    }
  } else {
    for (i = 0; i < mbufs_num; i++) {
      /* drop packets. */
      l2tun_update_errors(iface);
      rte_pktmbuf_free(mbufs[i]);
    }
  }

  tunnel_debug_print_stats(iface->base.name, iface->stats,
                           TUNNEL_STATS_TYPE_INBOUND);

  return ret;
}

static bool
vxlan_inbound_process(void *p) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct vxlan_runtime *rt = p;
  struct l2tun_iface_entry *entry = NULL;
  struct rte_mbuf *mbufs[MAX_PKT_BURST];
  uint32_t mbufs_num;

  if (unlikely(rt == NULL)) {
    TUNNEL_ERROR("null runtime");
    return true;
  }

  TAILQ_FOREACH(entry, &(rt->iface_list->head), iface_entries) {
    struct l2tun_iface *iface = entry->iface;
    struct vxlan_iface_metadata *iface_md = VXLAN_IFACE_METADATA(iface);

    if (likely(iface_md->prepare_one_packet_proc != NULL)) {
      if (likely(vxlan_is_ready(iface))) {
        mbufs_num = (uint32_t) rte_ring_dequeue_burst(iface->base.input2,
                    (void **) mbufs,
                    MAX_PKT_BURST,
                    NULL);
        if (mbufs_num > 0) {
          ret = vxlan_inbound(iface, mbufs, mbufs_num);
          if (unlikely(ret != LAGOPUS_RESULT_OK)) {
            TUNNEL_PERROR(ret);
            return false;
          }
        }
      }
    } else {
      ret = LAGOPUS_RESULT_INVALID_OBJECT;
      TUNNEL_PERROR(ret);
      return false;
    }
  }

  return true;
}

/* outbound. */

static inline lagopus_result_t
vxlan_encap(struct l2tun_iface *iface,
            struct rte_mbuf *m) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct ether_hdr *ether_hdr;
  struct vxlan_hdr *vxlan_hdr;
  struct udp_hdr *udp_hdr;
  struct vxlan_mbuf_metadata *metadata;
  uint16_t src_port, ether_type;

  if (unlikely(iface->trunk)) {
    /* trunk mode.  */
    /* unsupported. */
    ret = LAGOPUS_RESULT_UNSUPPORTED;
    TUNNEL_ERROR("[%s] unsupported trunk mode: %d", iface->base.name, ret);
    return ret;
  }

  /* set inner dst address type(for stats). */
  set_meta_inner_dst_ether_addr_type(m);
  /* set inner packet bytes(for stats). */
  set_meta_inner_pkt_bytes(m);

  /* reset metadata(VNI). */
  m->vlan_tci = 0;

  /* set encap, keep_ttl metadata. */
  set_meta_encap(m);
  set_meta_keep_ttl(m);

  /* Inner Ether. */
  if (unlikely(m->pkt_len < sizeof(struct ether_hdr))) {
    TUNNEL_ERROR("[%s] Bad packet length", iface->base.name);
    return LAGOPUS_RESULT_TOO_SHORT;
  }
  ether_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

  /* VXLAN header. */
  ret = encap_vxlan(m, iface->vni, &vxlan_hdr);
  if (unlikely((ret != LAGOPUS_RESULT_OK))) {
    TUNNEL_ERROR("[%s] Can't encap VXLAN: %d", iface->base.name, ret);
    return ret;
  }

  /* UDP header. */
  src_port = udp_gen_src_port(ether_hdr, VXLAN_UDP_PORT_MIN,
                              VXLAN_UDP_PORT_MAX);
  ret = encap_udp(m, src_port, VXLAN_DEFAULT_UDP_DST_PORT, &udp_hdr);
  if (unlikely((ret != LAGOPUS_RESULT_OK))) {
    TUNNEL_ERROR("[%s] Can't generate UDP src port.%d", iface->base.name, ret);
    return ret;
  }
  /* UDP checksum is 0. (RFC7348, section 5)*/
  udp_hdr->dgram_cksum = 0;

  metadata = get_priv(m);
  /* outer IP header. */
  switch (iface->address_type) {
    case ADDRESS_TYPE_IPV4:
      /* IPv4. */
      ether_type = ETHER_TYPE_IPv4;
      ret = encap_ip4(m, 0, IPPROTO_UDP,
                      &iface->local_addr, &metadata->entry.remote_ip,
                      iface->tos, VXLAN_DEFAULT_IP_OFFSET,
                      iface->hop_limit, true);
      break;
    case ADDRESS_TYPE_IPV6:
      /* IPv6. */
      ether_type = ETHER_TYPE_IPv6;
      ret = encap_ip6(m, 0, IPPROTO_UDP,
                      &iface->local_addr, &metadata->entry.remote_ip,
                      iface->tos, iface->hop_limit);
      break;
    default:
      TUNNEL_ERROR("[%s] Bad IP version", iface->base.name);
      return LAGOPUS_RESULT_UNSUPPORTED;
  }

  if (unlikely((ret != LAGOPUS_RESULT_OK))) {
    TUNNEL_ERROR("[%s] encap IP: %d", iface->base.name, ret);
    return ret;
  }

  /* Ether. */
  ret = encap_ether(m, ether_type);
  if (unlikely((ret != LAGOPUS_RESULT_OK))) {
    TUNNEL_ERROR("[%s] encap Ether: %d", iface->base.name, ret);
    return ret;
  }

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
vxlan_encaps(struct l2tun_iface *iface,
             struct vxlan_traffic *t) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  size_t i;

  for (i = 0; i < t->encap.num; i++) {
    ret = vxlan_encap(iface, t->encap.pkts[i]);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      return ret;
    }
  }

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
vxlan_flood(struct l2tun_iface *iface,
            struct vxlan_traffic *t,
            struct rte_mbuf *m,
            size_t *pos) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct vxlan_mbuf_metadata *metadata;
  struct rte_mbuf *new_mbuf;
  size_t i;

  new_mbuf = m;
  for (i = 0; i < iface->remote_addrs.size; i++) {
    if (i > 0) {
      ret = mbuf_clone(&new_mbuf, m, m->pool);
      if (unlikely(ret != LAGOPUS_RESULT_OK)) {
        TUNNEL_PERROR(ret);
        return ret;
      }

      rte_mbuf_refcnt_update(m, 1);
      t->flood_pkts_num++;
    }

    metadata = get_priv(new_mbuf);
    fdb_entry_set_ip(&metadata->entry, iface->address_type,
                     &iface->remote_addrs.addrs[i]);
    t->encap.pkts[(*pos)++] = new_mbuf;
  }

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
vxlan_fdb_find(struct l2tun_iface *iface,
               struct rte_mbuf *m,
               struct vxlan_traffic *t) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct vxlan_mbuf_metadata *metadata;
  struct ether_hdr *ether_hdr;
  struct vxlan_iface_metadata *iface_md = VXLAN_IFACE_METADATA(iface);
  size_t i = 0;

  ether_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

  metadata = get_priv(m);
  ret = fdb_find_copy(iface_md->fdb, &ether_hdr->d_addr,
                      &metadata->entry);

  if (likely(ret == LAGOPUS_RESULT_OK &&
             i < MAX_PKTS_WITH_FLOOD)) {
    t->encap.pkts[i++] = m;

    TUNNEL_DEBUG("FDB (VNI = %d): Find: mac = "ETHADDR_FORMAT,
                 iface->vni, ETHADDR_TO_ARRAY(ether_hdr->d_addr));
  } else if (likely(ret == LAGOPUS_RESULT_NOT_FOUND &&
                    i + iface->remote_addrs.size - 1 < MAX_PKTS_WITH_FLOOD)) {
    /* Flooding. */
    ret = vxlan_flood(iface, t, m, &i);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      return ret;
    }

    TUNNEL_DEBUG("FDB (VNI = %d): Flooding: mac = "ETHADDR_FORMAT,
                 iface->vni, ETHADDR_TO_ARRAY(ether_hdr->d_addr));
  } else {
    if (ret == LAGOPUS_RESULT_OK ||
        ret == LAGOPUS_RESULT_NOT_FOUND) {
      TUNNEL_ERROR("over MAX_PKTS_WITH_FLOOD.");
      ret = LAGOPUS_RESULT_OUT_OF_RANGE;
    } else {
      TUNNEL_PERROR(ret);
    }

    /* drop packet. */
    l2tun_update_errors(iface);
    rte_pktmbuf_free(m);
    return ret;
  }
  t->encap.num = i;

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
vxlan_outbound_one_packet(struct l2tun_iface *iface,
                          struct rte_mbuf *m,
                          struct vxlan_traffic *t) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  size_t i;

  /* reset num of encap pakts. */
  t->encap.num = 0;

  /* prepare. */
  ret = prepare_one_packet(iface, &m);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    goto free_in_mbuf;
  }

  /* find. */
  ret = vxlan_fdb_find(iface, m, t);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    goto free_encap_mbufs;
  }

  /* encaps (include flood packets). */
  ret = vxlan_encaps(iface, t);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    goto free_encap_mbufs;
  }

  /* add packets for sent. */
  if (likely(t->out.num + t->encap.num <
             MAX_PKTS_WITH_FLOOD)) {
    memcpy(&t->out.pkts[t->out.num], t->encap.pkts,
           sizeof(struct rte_mbuf *) * t->encap.num);
    t->out.num += t->encap.num;
  } else {
    TUNNEL_ERROR("over MAX_PKTS_WITH_FLOOD.");
    ret = LAGOPUS_RESULT_OUT_OF_RANGE;
    goto free_encap_mbufs;
  }

free_in_mbuf:
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    /* drop packet. */
    l2tun_update_errors(iface);
    rte_pktmbuf_free(m);
    return ret;
  }

free_encap_mbufs:
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    for (i = 0; i < t->encap.num; i++) {
      /* drop packet. */
      l2tun_update_errors(iface);
      rte_pktmbuf_free(t->encap.pkts[i]);
    }
    return ret;
  }

  /* update stats. */
  l2tun_update_stats(iface, iface->vlans[iface->access_vid], m);

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
vxlan_outbound(struct l2tun_iface *iface, struct rte_mbuf **mbufs,
               size_t mbufs_num) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct vxlan_iface_metadata *iface_md = VXLAN_IFACE_METADATA(iface);
  struct fdb *fdb;
  struct vxlan_traffic traffic = {0};
  size_t i;
  uint64_t vni;

  if (unlikely(iface_md->fdb == NULL)) {
    /* get FDB. */
    vni = (uint64_t) iface->vni;
    ret = lagopus_hashmap_find(&fdbs,
                               (void *) vni,
                               (void **) &fdb);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      goto done;
    }
    fdb_inc_refs(fdb);
    iface_md->fdb = fdb;
  }

  /* process per packet. */
  for (i = 0; i < mbufs_num; i++) {
    ret = vxlan_outbound_one_packet(iface, mbufs[i],
                                    &traffic);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      /* process the next packet. */
      ret = LAGOPUS_RESULT_OK;
      continue;
    }
  }

  /* sent next module. */
  vxlan_sent_pkts(iface, traffic.out.pkts, traffic.out.num);

done:
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    for (i = 0; i < mbufs_num; i++) {
      /* drop packets. */
      l2tun_update_errors(iface);
      rte_pktmbuf_free(mbufs[i]);
    }
  }

  tunnel_debug_print_stats(iface->base.name, iface->stats,
                           TUNNEL_STATS_TYPE_OUTBOUND);

  return ret;
}

static bool
vxlan_outbound_process(void *p) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct vxlan_runtime *rt = p;
  struct l2tun_iface_entry *entry = NULL;
  struct rte_mbuf *mbufs[MAX_PKT_BURST];
  uint32_t mbufs_num;

  if (unlikely(rt == NULL)) {
    TUNNEL_ERROR("null runtime");
    return true;
  }

  TAILQ_FOREACH(entry, &(rt->iface_list->head), iface_entries) {
    struct l2tun_iface *iface = entry->iface;
    struct vxlan_iface_metadata *iface_md = VXLAN_IFACE_METADATA(iface);

    if (likely(iface_md->prepare_one_packet_proc != NULL)) {
      if (likely(vxlan_is_ready(iface))) {
        mbufs_num = (uint32_t)rte_ring_dequeue_burst(iface->base.input,
                    (void **)mbufs,
                    MAX_PKT_BURST,
                    NULL);
        if (mbufs_num > 0) {
          ret = vxlan_outbound(iface, mbufs, mbufs_num);
          if (unlikely(ret != LAGOPUS_RESULT_OK)) {
            TUNNEL_PERROR(ret);
            return false;
          }
        }
      }
    } else {
      ret = LAGOPUS_RESULT_INVALID_OBJECT;
      TUNNEL_PERROR(ret);
      return false;
    }
  }

  return true;
}

/* control process. */

static inline lagopus_result_t
vxlan_fdb_gc(struct l2tun_iface *iface, struct fdb_entry *e) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct fdb_entry *entry = NULL;
  struct event event = {0};
  struct vxlan_iface_metadata *iface_md = VXLAN_IFACE_METADATA(iface);

  if (unlikely(iface_md->fdb == NULL)) {
    ret = LAGOPUS_RESULT_INVALID_OBJECT;
    TUNNEL_PERROR(ret);
    return ret;
  }

  ret = fdb_gc(iface_md->fdb, &e->mac, &entry);
  if (likely(ret == LAGOPUS_RESULT_OK)) {
    if (unlikely(entry == NULL)) {
      /* set delete event. */
      eventq_entry_set(&event.entries[event.num++],
                       L2TUN_CMD_FDB_DEL, iface->vni,
                       e);

      TUNNEL_DEBUG("FDB (VNI = %d): Delete: mac = "ETHADDR_FORMAT,
                   iface->vni, ETHADDR_TO_ARRAY(e->mac));
    } else {
      /* set update (learn) event. */
      eventq_entry_set(&event.entries[event.num++],
                       L2TUN_CMD_FDB_LEARN, iface->vni,
                       entry);

      TUNNEL_DEBUG("FDB (VNI = %d): Learn(update): mac = "ETHADDR_FORMAT,
                   iface->vni, ETHADDR_TO_ARRAY(e->mac));
    }
  } else {
    TUNNEL_PERROR(ret);
    return ret;
  }

  ret = vxlan_put_events(event.entries, event.num);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
  }

  return ret;
}

static inline lagopus_result_t
vxlan_fdb_clear(struct l2tun_iface *iface) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct event event = {0};
  struct vxlan_iface_metadata *iface_md = VXLAN_IFACE_METADATA(iface);

  if (unlikely(iface_md->fdb == NULL)) {
    ret = LAGOPUS_RESULT_INVALID_OBJECT;
    TUNNEL_PERROR(ret);
    return ret;
  }

  ret = fdb_clear(iface_md->fdb);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    return ret;
  }

  eventq_entry_set(&event.entries[event.num++],
                   L2TUN_CMD_FDB_CLEAR, iface->vni,
                   NULL);

  ret = vxlan_put_events(event.entries, event.num);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
    return ret;
  }

  TUNNEL_DEBUG("FDB (VNI = %d): Clear", iface->vni);

  return LAGOPUS_RESULT_OK;
}

static void
vxlan_fdb_free(void *fdb) {
  fdb_free((struct fdb **) &fdb);
}

static inline lagopus_result_t
vxlan_fdbs_add_fdb(struct fdb *fdb, uint64_t vni) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  /* add FDB. */
  ret = lagopus_hashmap_add(&fdbs,
                            (void *) vni,
                            (void **) &fdb, false);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
  }

  return ret;
}

static inline lagopus_result_t
vxlan_fdbs_delete_fdb(uint64_t vni) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  /* delete FDB. */
  /* NOTE: Delete from hashtable. But do not free entry. */
  /*       Free entries at vxlan_unregister_iface().     */
  ret = lagopus_hashmap_delete(&fdbs,
                               (void *) vni,
                               NULL, false);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_PERROR(ret);
  }

  return ret;
}

static inline lagopus_result_t
vxlan_control_reuse_fdb(struct l2tun_iface *iface,
                        struct l2tun_control_param *param) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct vxlan_iface_metadata *iface_md = VXLAN_IFACE_METADATA(iface);

  if (likely(iface_md->fdb != NULL)) {
    /* clear FDB. */
    ret = vxlan_fdb_clear(iface);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      return ret;
    }

    /* delete FDB. */
    /* NOTE: Delete from hashtable. But do not free entry. */
    /*       Free entries at vxlan_unregister_iface().     */
    ret = vxlan_fdbs_delete_fdb((uint64_t) iface->vni);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      return ret;
    }

    /* add FDB. */
    ret = vxlan_fdbs_add_fdb(iface_md->fdb,
                             (uint64_t) param->vni);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      return ret;
    }
  } else {
    TUNNEL_ERROR("FDB is NULL.");
    return LAGOPUS_RESULT_INVALID_OBJECT;
  }

  return ret;
}

static inline lagopus_result_t
vxlan_control_add_fdb(struct l2tun_iface *iface,
                      struct l2tun_control_param *param) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct vxlan_iface_metadata *iface_md = VXLAN_IFACE_METADATA(iface);

  if (likely(iface_md->fdb != NULL)) {
    /* add FDB. */
    ret = vxlan_fdbs_add_fdb(iface_md->fdb,
                             (uint64_t) param->vni);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      return ret;
    }
  } else {
    TUNNEL_ERROR("FDB is NULL.");
    return LAGOPUS_RESULT_INVALID_OBJECT;
  }

  return ret;
}

static inline void
vxlan_control_set_remote_addrs(struct l2tun_iface *iface,
                               struct l2tun_control_param *param) {
  size_t i;

  iface->remote_addrs.size = param->remote_addrs.size;
  for (i = 0; i < param->remote_addrs.size; i++) {
    iface->remote_addrs.addrs[i].ip = param->remote_addrs.addrs[i].ip;
    if (param->address_type == ADDRESS_TYPE_IPV4) {
      iface->remote_addrs.addrs[i].ip.ip4 =
        rte_cpu_to_be_32(iface->remote_addrs.addrs[i].ip.ip4);
    }
  }
}

static inline void
vxlan_control_set_local_addrs(struct l2tun_iface *iface,
                              struct l2tun_control_param *param) {
  iface->local_addr.ip = param->local_addr.ip;
  if (param->address_type == ADDRESS_TYPE_IPV4) {
    iface->local_addr.ip.ip4 =
      rte_cpu_to_be_32(iface->local_addr.ip.ip4);
  }
}

static inline lagopus_result_t
vxlan_control_enable(struct l2tun_iface *iface,
                     struct l2tun_control_param *param) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct l2tun_vlan_entry *vlan_entry = NULL;

  if (iface->inbound) {
    /* inbound. */
    ret = vxlan_control_add_fdb(iface, param);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      return ret;
    }
  }

  if (param->trunk) {
    /* trunk mode.  */
    /* unsupported. */
    ret = LAGOPUS_RESULT_UNSUPPORTED;
    TUNNEL_ERROR("[%s] unsupported trunk mode: %d", iface->base.name, ret);
    return ret;
  }

  iface->address_type = param->address_type;

  vxlan_control_set_local_addrs(iface, param);
  vxlan_control_set_remote_addrs(iface, param);

  iface->hop_limit = param->hop_limit;
  iface->tos = param->tos;
  iface->trunk = param->trunk;
  iface->vni = param->vni;
  iface->enabled = true;
  iface->access_vid = param->vid;

  /* add to VLAN list. */
  vlan_entry = l2tun_add_vlan_entry(iface, param->vid);
  if (unlikely(vlan_entry == NULL)) {
    TUNNEL_ERROR("[%s] no memory", iface->base.name);
    return LAGOPUS_RESULT_NO_MEMORY;
  }

  /* set output, stats. */
  if (iface->inbound) {
    vlan_entry->vlan->output = param->inbound_output;
    vlan_entry->vlan->stats = param->inbound_stats;
  } else {
    vlan_entry->vlan->output = param->outbound_output;
    vlan_entry->vlan->stats = param->outbound_stats;
  }

  /* set VIF index. */
  vlan_entry->vlan->index = param->index;

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
vxlan_control_disable(struct l2tun_iface *iface,
                      struct l2tun_control_param *param) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (iface->inbound) {
    /* inbound. */
    /* clear FDB. */
    ret = vxlan_fdb_clear(iface);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      return ret;
    }

    /* delete FDB. */
    /* NOTE: Delete from hashtable. But do not free entry. */
    /*       Free entries at vxlan_unregister_iface().     */
    ret = vxlan_fdbs_delete_fdb((uint64_t) iface->vni);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      return ret;
    }
  }

  iface->enabled = false;
  iface->access_vid = 0;
  iface->vni = 0;

  /* remove from VLAN list. */
  l2tun_remove_vlan_entry(iface, param->vid);

  return LAGOPUS_RESULT_OK;
}

static bool
vxlan_control_iface(void *priv, struct vsw_instance *base, void *p) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct l2tun_iface *iface = (struct l2tun_iface *)base;
  struct l2tun_control_param *param = p;
  struct vxlan_ctrl_param_metadata *ctrl_md;

  if (unlikely(iface == NULL)) {
    TUNNEL_ERROR("null instance");
    return false;
  }

  if (unlikely(param == NULL)) {
    TUNNEL_ERROR("[%s] null param", iface->base.name);
    return false;
  }

  TUNNEL_DEBUG("[%s] inbound=%d cmd=%d index=%d address_type=%d local=%d remotes=%d "
               "hop_limit=%d tos=%d vid=%d trunk=%d vni=%d "
               "in_output=%p out_output=%p in_stats=%p out_stats=%p",
               iface->base.name, iface->inbound, param->cmd,
               param->index, param->address_type,
               param->local_addr.ip.ip4, param->remote_addrs.addrs[0].ip.ip4,
               param->hop_limit, param->tos, param->vid, param->trunk, param->vni,
               param->inbound_output, param->outbound_output,
               param->inbound_stats, param->outbound_stats);

  ctrl_md = VXLAN_CTRL_PARAM_METADATA(param);

  switch (param->cmd) {
    case L2TUN_CMD_SET_ADDRESS_TYPE:
      iface->address_type = param->address_type;
      break;
    case L2TUN_CMD_SET_LOCAL_ADDR:
      vxlan_control_set_local_addrs(iface, param);
      break;
    case L2TUN_CMD_SET_REMOTE_ADDRS:
      if (iface->inbound) {
        /* inbound. */
        ret = vxlan_fdb_clear(iface);
        if (unlikely(ret != LAGOPUS_RESULT_OK)) {
          TUNNEL_PERROR(ret);
          return false;
        }
      }

      vxlan_control_set_remote_addrs(iface, param);
      break;
    case L2TUN_CMD_SET_HOP_LIMIT:
      iface->hop_limit = param->hop_limit;
      break;
    case L2TUN_CMD_SET_TOS:
      iface->tos = param->tos;
      break;
    case L2TUN_CMD_SET_TRUNK_MODE:
      /* trunk mode.  */
      /* unsupported. */
      TUNNEL_ERROR("[%s] unsupported trunk mode", iface->base.name);
      return false;
    case L2TUN_CMD_SET_ACCESS_MODE:
      iface->trunk = param->trunk;
      break;
    case L2TUN_CMD_SET_VNI:
      if (iface->inbound) {
        /* inbound. */
        ret = vxlan_control_reuse_fdb(iface, param);
        if (unlikely(ret != LAGOPUS_RESULT_OK)) {
          TUNNEL_PERROR(ret);
          return false;
        }
      }

      iface->vni = param->vni;
      break;
    case L2TUN_CMD_SET_ENABLE:
      ret = vxlan_control_enable(iface, param);
      if (unlikely(ret != LAGOPUS_RESULT_OK)) {
        TUNNEL_PERROR(ret);
        return false;
      }
      break;
    case L2TUN_CMD_SET_DISABLE:
      ret = vxlan_control_disable(iface, param);
      if (unlikely(ret != LAGOPUS_RESULT_OK)) {
        TUNNEL_PERROR(ret);
        return false;
      }
      break;
    case L2TUN_CMD_FDB_AGING:
      ret = vxlan_fdb_gc(iface, &ctrl_md->entry);
      if (unlikely(ret != LAGOPUS_RESULT_OK)) {
        TUNNEL_PERROR(ret);
        return false;
      }
      break;
    default:
      return false;
  }

  return true;
}

static void *
vxlan_init(void *param) {
  struct vxlan_runtime *rt = NULL;

  /* create runtime. */
  if (unlikely((rt = (struct vxlan_runtime *) calloc(
                       1, sizeof(struct vxlan_runtime))) == NULL)) {
    TUNNEL_ERROR("vxlan_runtime calloc() failed.");
    return NULL;
  }

  /* create iface list. */
  if ((rt->iface_list = l2tun_create_iface_list()) == NULL) {
    TUNNEL_ERROR("l2tun_create_iface_list() failed");
    free(rt);
    return NULL;
  }

  TUNNEL_DEBUG("slave core=%u", rte_lcore_id());

  return rt;
}

static void
vxlan_deinit(void *p) {
  struct vxlan_runtime *rt = p;

  /* free iface list. */
  l2tun_free_iface_list(rt->iface_list);
  /* free runtime. */
  free(rt);

  TUNNEL_DEBUG("slave core=%u", rte_lcore_id());
}

static bool
vxlan_register_iface(void *priv, struct vsw_instance *base) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct vxlan_runtime *rt = priv;
  struct l2tun_iface *iface = (struct l2tun_iface *)base;
  struct vxlan_iface_metadata *iface_md;
  struct fdb *fdb;
  l2tun_vlan_list_t *vlan_list = NULL;
  bool r = false;
  uint32_t socket_id;

  if (unlikely(rt == NULL)) {
    TUNNEL_ERROR("null runtime");
    goto error;
  }

  if (unlikely(iface == NULL)) {
    TUNNEL_ERROR("null instance");
    goto error;
  }

  TUNNEL_DEBUG("[%s] register instance", iface->base.name);

  /* create VLAN list. */
  if (unlikely((vlan_list = l2tun_create_vlan_list(iface)) == NULL)) {
    TUNNEL_ERROR("[%s] no memory", iface->base.name);
    goto error;
  }

  /* add to iface list. */
  if (unlikely(l2tun_add_iface_entry(rt->iface_list, iface) == NULL)) {
    TUNNEL_ERROR("[%s] no memory", iface->base.name);
    goto error;
  }

  iface_md = VXLAN_IFACE_METADATA(iface);
  if (iface->inbound) {
    /* inbound. */
    /* alloc FDB. */
    socket_id = rte_socket_id();
    if (socket_id == LCORE_ID_ANY) {
      socket_id = 0;
    }
    ret = fdb_alloc(&fdb, socket_id);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      goto error;
    }

    iface_md->fdb = fdb;
    iface_md->prepare_one_packet_proc = prepare_one_packet_inbound;
  } else {
    /* outbound. */
    iface_md->fdb = NULL;
    iface_md->prepare_one_packet_proc = prepare_one_packet_outbound;
  }
  r = true;

error:
  if (unlikely(!r)) {
    free(vlan_list);
  }
  return r;
}

static bool
vxlan_unregister_iface(void *priv, struct vsw_instance *base) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct vxlan_runtime *rt = priv;
  struct l2tun_iface *iface = (struct l2tun_iface *)base;
  struct vxlan_iface_metadata *iface_md;

  if (unlikely(rt == NULL)) {
    TUNNEL_ERROR("null runtime");
    return false;
  }

  if (unlikely(iface == NULL)) {
    TUNNEL_ERROR("null instance");
    return false;
  }

  TUNNEL_DEBUG("[%s] unregister instance", iface->base.name);

  iface_md = VXLAN_IFACE_METADATA(iface);
  if (iface_md->fdb != NULL) {
    /* free FDB. */
    ret = fdb_free(&iface_md->fdb);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
      return false;
    }
    iface_md->fdb = NULL;
  }
  iface_md->prepare_one_packet_proc = NULL;

  /* remove from iface list */
  l2tun_remove_iface_entry(rt->iface_list, iface);

  return true;
}

/* static constructor/destructor. */

static void
init(void) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  /* FDBs. */
  if ((ret = lagopus_hashmap_create(&fdbs,
                                    LAGOPUS_HASHMAP_TYPE_ONE_WORD,
                                    vxlan_fdb_free)) != LAGOPUS_RESULT_OK) {
    rte_panic("Can't create hashmap :%ld\n", ret);
  }

  /* event queue. */
  if ((ret = event_queue_create(&eventq)) != LAGOPUS_RESULT_OK) {
    rte_panic("Can't create event_queue :%ld\n", ret);
  }
}

static void
ctors(void) {
  pthread_once(&once, init);
}

static void
final(void) {
  /* TODO: Call explicitly. */
  if (fdbs != NULL) {
    lagopus_hashmap_shutdown(&fdbs, true);
    lagopus_hashmap_destroy(&fdbs, true);
    fdbs = NULL;
  }
  if (eventq != NULL) {
    event_queue_shutdown(&eventq);
    event_queue_destroy(&eventq);
    eventq = NULL;
  }
}

static void
dtors(void) {
  final();
}

/* Punblic. */

lagopus_result_t
vxlan_get_events(struct eventq_entry *entries,
                 size_t *num) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(entries != NULL && num != NULL)) {
    if (likely(eventq != NULL)) {
      ret = event_queue_gets(&eventq, entries, num);
      if (ret == LAGOPUS_RESULT_TIMEDOUT) {
        /* ignore timeout. */
        *num = 0;
        ret = LAGOPUS_RESULT_OK;
      }
    } else {
      ret = LAGOPUS_RESULT_INVALID_OBJECT;
    }
  }  else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
  }

  if (likely(ret >= 0)) {
    ret = LAGOPUS_RESULT_OK;
  } else {
    TUNNEL_PERROR(ret);
  }

  return ret;
}

struct vsw_runtime_ops vxlan_inbound_runtime_ops = {
  .init = vxlan_init,
  .process = vxlan_inbound_process,
  .deinit = vxlan_deinit,
  .register_instance = vxlan_register_iface,
  .unregister_instance = vxlan_unregister_iface,
  .update_rings = NULL,
  .control_instance = vxlan_control_iface,
};

struct vsw_runtime_ops vxlan_outbound_runtime_ops = {
  .init = vxlan_init,
  .process = vxlan_outbound_process,
  .deinit = vxlan_deinit,
  .register_instance = vxlan_register_iface,
  .unregister_instance = vxlan_unregister_iface,
  .update_rings = NULL,
  .control_instance = vxlan_control_iface,
};
