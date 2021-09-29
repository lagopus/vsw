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
#include <stdbool.h>
#include <sys/queue.h>

#include "logger.h"
#include "gre.h"

struct gre_runtime {
  l3tun_iface_list_t *iface_list;
};

static bool
gre_register_iface(void *priv, struct vsw_instance *base) {
  struct gre_runtime *rt = priv;
  struct l3tun_iface *iface = (struct l3tun_iface *)base;

  if (unlikely(rt == NULL)) {
    TUNNEL_ERROR("null runtime");
    return false;
  }

  if (unlikely(iface == NULL)) {
    TUNNEL_ERROR("null instance");
    return false;
  }

  // add to iface list
  if (unlikely(l3tun_add_iface_entry(rt->iface_list, iface) == NULL)) {
    TUNNEL_ERROR("[%s] no memory", iface->base.name);
    return false;
  }

  return true;
}

static bool
gre_unregister_iface(void *priv, struct vsw_instance *base) {
  struct gre_runtime *rt = priv;
  struct l3tun_iface *iface = (struct l3tun_iface *)base;

  if (unlikely(rt == NULL)) {
    TUNNEL_ERROR("null runtime");
    return false;
  }

  if (unlikely(iface == NULL)) {
    TUNNEL_ERROR("null instance");
    return false;
  }

  // remove from iface list
  l3tun_remove_iface_entry(rt->iface_list, iface);

  return true;
}

static bool
gre_control_iface(__UNUSED void *priv, struct vsw_instance *base, void *p) {
  struct l3tun_iface *iface = (struct l3tun_iface *)base;
  struct l3tun_control_param *param = p;

  if (unlikely(iface == NULL)) {
    TUNNEL_ERROR("null instance");
    return false;
  }

  if (unlikely(param == NULL)) {
    TUNNEL_ERROR("[%s]: null param", iface->base.name);
    return false;
  }

  TUNNEL_DEBUG("[%s]: cmd=%d index=%d address_type=%d local=%d remote=%d "
               "hop_limit=%d tos=%d inbound_output=%p outbound_output=%p",
               iface->base.name, param->cmd, param->index, param->address_type,
               param->local_addr.ip.ip4, param->remote_addr.ip.ip4,
               param->hop_limit, param->tos,
               param->inbound_output, param->outbound_output);

  switch (param->cmd) {
    case L3TUN_CMD_SET_ADDRESS_TYPE:
      iface->address_type = param->address_type;
      break;
    case L3TUN_CMD_SET_LOCAL_ADDR:
      if (iface->address_type == ADDRESS_TYPE_IPV4) {
        iface->local_addr.ip.ip4 = rte_cpu_to_be_32(param->local_addr.ip.ip4);
      } else if (iface->address_type == ADDRESS_TYPE_IPV6) {
        // TODO: IPv6
        TUNNEL_ERROR("[%s] unsupported IPv6 address", iface->base.name);
      } else {
        TUNNEL_ERROR("[%s] invalid address type: %d", iface->base.name,
                     iface->address_type);
      }
      break;
    case L3TUN_CMD_SET_REMOTE_ADDR:
      if (iface->address_type == ADDRESS_TYPE_IPV4) {
        iface->remote_addr.ip.ip4 = rte_cpu_to_be_32(param->remote_addr.ip.ip4);
      } else if (iface->address_type == ADDRESS_TYPE_IPV6) {
        // TODO: IPv6
        TUNNEL_ERROR("[%s] unsupported IPv6 address", iface->base.name);
      } else {
        TUNNEL_ERROR("[%s] invalid address type: %d", iface->base.name,
                     iface->address_type);
      }
      break;
    case L3TUN_CMD_SET_HOP_LIMIT:
      iface->hop_limit = param->hop_limit;
      break;
    case L3TUN_CMD_SET_TOS:
      iface->tos = param->tos;
      break;
    case L3TUN_CMD_SET_ENABLE:
      iface->index = param->index;
      iface->address_type = param->address_type;
      iface->local_addr.ip.ip4 = rte_cpu_to_be_32(param->local_addr.ip.ip4);
      iface->remote_addr.ip.ip4 = rte_cpu_to_be_32(param->remote_addr.ip.ip4);
      iface->hop_limit = param->hop_limit;
      iface->tos = param->tos;
      iface->inbound_output = param->inbound_output;
      iface->outbound_output = param->outbound_output;
      iface->enabled = true;
      break;
    case L3TUN_CMD_SET_DISABLE:
      iface->enabled = false;
      break;
    default:
      return false;
  }

  return true;
}

static bool
gre_is_ready(struct l3tun_iface *iface) {
  if (iface->enabled && iface->inbound_output != NULL &&
      iface->outbound_output != NULL) {
    return true;
  }

  return false;
}

static inline lagopus_result_t
gre_decap(struct l3tun_iface *iface, struct rte_mbuf *mbuf) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct ether_hdr *ether_hdr;
  struct ipv4_hdr *out_ipv4_hdr;
  struct ipv6_hdr *out_ipv6_hdr;
  struct gre_hdr *gre_hdr;
  uint16_t ether_type;
  uint16_t ip_proto;
  uint16_t frag;

  // Linearize mbuf
  if (unlikely(rte_pktmbuf_linearize(mbuf) != 0)) {
    TUNNEL_ERROR("[%s] not enough tailroom", iface->base.name);
    return LAGOPUS_RESULT_NO_MEMORY;
  }

  // decap ethernet frame header
  ret = decap_ether(mbuf, &ether_hdr);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_ERROR("[%s]: decap_eth failed %d", iface->base.name, ret);
    return ret;
  }

  // decap IPv4/6 header
  switch (ether_hdr->ether_type) {
    case ETHER_TYPE_IPv4_BE:
      ret = decap_ip4(mbuf, 0, &out_ipv4_hdr);
      if (unlikely(ret != LAGOPUS_RESULT_OK)) {
        TUNNEL_ERROR("[%s]: decap_ip4 failed %d", iface->base.name, ret);
        return ret;
      }

      frag = ntohs(out_ipv4_hdr->fragment_offset);
      if (unlikely(frag != 0 && frag != IPV4_HDR_DF_FLAG)) {
        TUNNEL_ERROR("[%s]: invalid frag %d", iface->base.name, frag);
        return LAGOPUS_RESULT_UNSUPPORTED;
      }

      ip_proto = out_ipv4_hdr->next_proto_id;

      break;
    case ETHER_TYPE_IPv6_BE:
      ret = decap_ip6(mbuf, 0, &out_ipv6_hdr);
      if (unlikely(ret != LAGOPUS_RESULT_OK)) {
        TUNNEL_ERROR("[%s]: decap_ip6 failed %d", iface->base.name, ret);
        return ret;
      }

      ip_proto = out_ipv6_hdr->proto;

      break;
    default:
      TUNNEL_ERROR("[%s]: unsupported outer IP version", iface->base.name);
      return LAGOPUS_RESULT_UNKNOWN_PROTO;
  }

  // decap GRE header
  if (likely(ip_proto == IPPROTO_GRE)) {
    ret = decap_gre(mbuf, &gre_hdr);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_ERROR("[%s]: decap_gre failed %d", iface->base.name, ret);
      return ret;
    }

    switch (gre_hdr->proto) {
      case ETHER_TYPE_IPv4_BE:
        ether_type = ETHER_TYPE_IPv4;
        break;
      case ETHER_TYPE_IPv6_BE:
        ether_type = ETHER_TYPE_IPv6;
        break;
      default:
        TUNNEL_ERROR("[%s]: unsupported GRE protocol", iface->base.name);
        return LAGOPUS_RESULT_UNKNOWN_PROTO;
    }
  } else {
    TUNNEL_ERROR("[%s]: invalid outer IP protocol %d",
                 iface->base.name, ip_proto);
    return LAGOPUS_RESULT_UNKNOWN_PROTO;
  }

  // set inner packet bytes(for stats)
  set_meta_inner_pkt_bytes(mbuf);

  // encap ethernet frame header
  ret = encap_ether(mbuf, ether_type);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_ERROR("[%s]: encap_eth failed %d", iface->base.name, ret);
    return ret;
  }

  // set keep_ttl metadata
  set_meta_keep_ttl(mbuf);

  // update in_vif
  ret = set_meta_vif(mbuf, iface->index);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_ERROR("[%s] update in_vif failed: %d", iface->base.name, ret);
    return ret;
  }

  return LAGOPUS_RESULT_OK;
}

static inline bool
gre_inbound(struct l3tun_iface *iface) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct rte_mbuf *deq_mbufs[MAX_PKT_BURST];
  struct rte_mbuf *send_mbufs[MAX_PKT_BURST];
  uint32_t deq_num = 0;
  uint32_t send_num = 0;
  uint32_t enq_num = 0;
  uint32_t error_num = 0;
  uint32_t drop_num = 0;

  deq_num = (uint32_t)rte_ring_dequeue_burst(iface->base.input2,
            (void **)deq_mbufs,
            MAX_PKT_BURST,
            NULL);

  if (deq_num == 0) {
    goto done;
  }

  for (uint32_t i = 0; i < deq_num; i++) {
    ret = gre_decap(iface, deq_mbufs[i]);
    if (likely(ret == LAGOPUS_RESULT_OK)) {
      send_mbufs[send_num++] = deq_mbufs[i];

      // update stats
      l3tun_update_stats(iface, deq_mbufs[i]);
    } else if (ret == LAGOPUS_RESULT_UNKNOWN_PROTO) {
      error_num++;
      l3tun_update_unknown_protos(iface);
      rte_pktmbuf_free(deq_mbufs[i]);
    } else {
      error_num++;
      l3tun_update_errors(iface);
      rte_pktmbuf_free(deq_mbufs[i]);
    }
  }

  // send output
  if (send_num > 0) {
    enq_num = rte_ring_enqueue_burst(iface->inbound_output,
                                     (void *const *)send_mbufs,
                                     send_num,
                                     NULL);
    if (unlikely(enq_num != send_num)) {
      TUNNEL_DEBUG("[%s]: enqueue failed", iface->base.name);

      for (uint32_t i = enq_num; i < send_num; i++) {
        // update dropped stats
        l3tun_update_dropped(iface);
        rte_pktmbuf_free(send_mbufs[i]);
      }

      drop_num += (send_num - enq_num);
    }

    TUNNEL_DEBUG("[%s] dequeue=%d, rx_packets=%d, errors=%d, dropped=%d",
                 iface->base.name, deq_num, enq_num, error_num, drop_num);
    tunnel_debug_print_stats(iface->base.name, iface->stats,
                             TUNNEL_STATS_TYPE_INBOUND);
  }

done:
  return true;
}

static bool
gre_inbound_process(void *p) {
  struct gre_runtime *rt = p;
  if (unlikely(rt == NULL)) {
    TUNNEL_ERROR("null runtime");
    return true;
  }

  struct l3tun_iface_entry *entry = NULL;
  TAILQ_FOREACH(entry, &(rt->iface_list->head), iface_entries) {
    struct l3tun_iface *iface = entry->iface;
    if (gre_is_ready(iface)) {
      gre_inbound(iface);
    }
  }

  return true;
}

static inline lagopus_result_t
gre_encap(struct l3tun_iface *iface, struct rte_mbuf *mbuf) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct ether_hdr *ether_hdr;
  struct ip *in_ip;
  uint8_t tos;
  uint16_t off;
  uint8_t ttl;
  uint16_t ether_type;

  // decap ethernet frame header
  ret = decap_ether(mbuf, &ether_hdr);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_ERROR("[%s]: decap_eth failed %d", iface->base.name, ret);
    return ret;
  }

  // set inner packet bytes(for stats)
  set_meta_inner_pkt_bytes(mbuf);

  // encap GRE header
  switch (ether_hdr->ether_type) {
    case ETHER_TYPE_IPv4_BE:
      ret = encap_gre(mbuf, ETHER_TYPE_IPv4);
      break;
    case ETHER_TYPE_IPv6_BE:
      ret = encap_gre(mbuf, ETHER_TYPE_IPv6);
      break;
    default:
      ret = LAGOPUS_RESULT_UNKNOWN_PROTO;
  }
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_ERROR("[%s]: encap_gre failed %d", iface->base.name, ret);
    return ret;
  }

  in_ip = rte_pktmbuf_mtod(mbuf, struct ip *);
  tos = convert_ip_tos(in_ip, iface->tos);
  off = in_ip->ip_off;
  ttl = convert_ip_ttl(in_ip, iface->hop_limit);

  // encap IPv4/6 header
  switch (iface->address_type) {
    case ADDRESS_TYPE_IPV4:
      ret = encap_ip4(mbuf, 0, IPPROTO_GRE,
                      &iface->local_addr, &iface->remote_addr,
                      tos, off, ttl, true);
      if (unlikely(ret != LAGOPUS_RESULT_OK)) {
        TUNNEL_ERROR("[%s]: encap_ip4 failed %d", iface->base.name, ret);
        return ret;
      }

      ether_type = ETHER_TYPE_IPv4;

      break;
    case ADDRESS_TYPE_IPV6:
      ret = encap_ip6(mbuf, 0, IPPROTO_GRE,
                      &iface->local_addr, &iface->remote_addr,
                      tos, ttl);
      if (unlikely(ret != LAGOPUS_RESULT_OK)) {
        TUNNEL_ERROR("[%s]: encap_ip6 failed %d", iface->base.name, ret);
        return ret;
      }

      ether_type = ETHER_TYPE_IPv6;

      break;
    default:
      TUNNEL_ERROR("[%s]: invalid address type %d",
                   iface->base.name, iface->address_type);
      return LAGOPUS_RESULT_UNKNOWN_PROTO;
  }

  // encap ethernet frame header
  ret = encap_ether(mbuf, ether_type);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_ERROR("[%s]: encap_eth failed %d", iface->base.name, ret);
    return ret;
  }

  // set encap, keep_ttl metadata
  set_meta_encap(mbuf);
  set_meta_keep_ttl(mbuf);

  return LAGOPUS_RESULT_OK;
}

static inline bool
gre_outbound(struct l3tun_iface *iface) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct rte_mbuf *deq_mbufs[MAX_PKT_BURST];
  struct rte_mbuf *send_mbufs[MAX_PKT_BURST];
  uint32_t deq_num = 0;
  uint32_t send_num = 0;
  uint32_t enq_num = 0;
  uint32_t error_num = 0;
  uint32_t drop_num = 0;

  deq_num = (uint32_t)rte_ring_dequeue_burst(iface->base.input,
            (void **)deq_mbufs,
            MAX_PKT_BURST,
            NULL);

  if (deq_num == 0) {
    goto done;
  }

  for (uint32_t i = 0; i < deq_num; i++) {
    ret = gre_encap(iface, deq_mbufs[i]);
    if (likely(ret == LAGOPUS_RESULT_OK)) {
      send_mbufs[send_num++] = deq_mbufs[i];

      // update stats
      l3tun_update_stats(iface, deq_mbufs[i]);
    } else {
      error_num++;
      l3tun_update_errors(iface);
      rte_pktmbuf_free(deq_mbufs[i]);
    }
  }

  // send output
  if (send_num > 0) {
    enq_num = rte_ring_enqueue_burst(iface->outbound_output,
                                     (void *const *)send_mbufs,
                                     send_num,
                                     NULL);
    if (unlikely(enq_num != send_num)) {
      TUNNEL_DEBUG("[%s]: enqueue failed", iface->base.name);

      for (uint32_t i = enq_num; i < send_num; i++) {
        // update dropped stats
        l3tun_update_dropped(iface);
        rte_pktmbuf_free(send_mbufs[i]);
      }

      drop_num += (send_num - enq_num);
    }

    TUNNEL_DEBUG("[%s] dequeue=%d, tx_packets=%d, errors=%d, dropped=%d",
                 iface->base.name, deq_num, enq_num, error_num, drop_num);
    tunnel_debug_print_stats(iface->base.name, iface->stats,
                             TUNNEL_STATS_TYPE_OUTBOUND);
  }

done:
  return true;
}

static bool
gre_outbound_process(void *p) {
  struct gre_runtime *rt = p;
  if (unlikely(rt == NULL)) {
    TUNNEL_ERROR("null runtime");
    return true;
  }

  struct l3tun_iface_entry *entry = NULL;
  TAILQ_FOREACH(entry, &(rt->iface_list->head), iface_entries) {
    struct l3tun_iface *iface = entry->iface;
    if (gre_is_ready(iface)) {
      gre_outbound(iface);
    }
  }

  return true;
}

static void *
gre_init(__UNUSED void *param) {
  struct gre_runtime *rt = NULL;

  // create runtime
  if ((rt = (struct gre_runtime *) calloc(1,
                                          sizeof(struct gre_runtime))) == NULL) {
    TUNNEL_ERROR("gre_runtime calloc() failed");
    return NULL;
  }

  // create iface list
  if ((rt->iface_list = l3tun_create_iface_list()) == NULL) {
    TUNNEL_ERROR("l3tun_create_iface_list() failed");
    free(rt);
    return NULL;
  }

  TUNNEL_DEBUG("slave core=%u", rte_lcore_id());

  return rt;
}

static void
gre_deinit(void *p) {
  struct gre_runtime *rt = p;

  // free iface list
  l3tun_free_iface_list(rt->iface_list);

  // free runtime
  free(rt);

  TUNNEL_DEBUG("slave core=%u", rte_lcore_id());
}

struct vsw_runtime_ops gre_inbound_runtime_ops = {
  .init = gre_init,
  .process = gre_inbound_process,
  .deinit = gre_deinit,
  .register_instance = gre_register_iface,
  .unregister_instance = gre_unregister_iface,
  .update_rings = NULL,
  .control_instance = gre_control_iface,
};

struct vsw_runtime_ops gre_outbound_runtime_ops = {
  .init = gre_init,
  .process = gre_outbound_process,
  .deinit = gre_deinit,
  .register_instance = gre_register_iface,
  .unregister_instance = gre_unregister_iface,
  .update_rings = NULL,
  .control_instance = gre_control_iface,
};
