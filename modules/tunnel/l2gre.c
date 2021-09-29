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
#include "mbuf.h"
#include "gre.h"
#include "vlan.h"

struct l2gre_runtime {
  l2tun_iface_list_t *iface_list;
};

static bool
l2gre_register_iface(void *priv, struct vsw_instance *base) {
  struct l2gre_runtime *rt = priv;
  struct l2tun_iface *iface = (struct l2tun_iface *)base;
  l2tun_vlan_list_t *vlan_list = NULL;

  if (unlikely(rt == NULL)) {
    TUNNEL_ERROR("null runtime");
    goto error;
  }

  if (unlikely(iface == NULL)) {
    TUNNEL_ERROR("null instance");
    goto error;
  }

  TUNNEL_DEBUG("[%s] register instance", iface->base.name);

  // create VLAN list
  if ((vlan_list = l2tun_create_vlan_list(iface)) == NULL) {
    TUNNEL_ERROR("[%s] no memory", iface->base.name);
    goto error;
  }

  // add to iface list
  if (l2tun_add_iface_entry(rt->iface_list, iface) == NULL) {
    TUNNEL_ERROR("[%s] no memory", iface->base.name);
    goto error;
  }

  return true;

error:
  free(vlan_list);
  return false;
}

static bool
l2gre_unregister_iface(void *priv, struct vsw_instance *base) {
  struct l2gre_runtime *rt = priv;
  struct l2tun_iface *iface = (struct l2tun_iface *)base;

  if (unlikely(rt == NULL)) {
    TUNNEL_ERROR("null runtime");
    return false;
  }

  if (unlikely(iface == NULL)) {
    TUNNEL_ERROR("null instance");
    return false;
  }

  TUNNEL_DEBUG("[%s] unregister instance", iface->base.name);

  // remove from iface list
  l2tun_remove_iface_entry(rt->iface_list, iface);

  return true;
}

static inline lagopus_result_t
l2gre_control_enable(struct l2tun_iface *iface,
                     struct l2tun_control_param *param) {
  struct l2tun_vlan_entry *vlan_entry = NULL;

  iface->address_type = param->address_type;
  switch (iface->address_type) {
    case ADDRESS_TYPE_IPV4:
      iface->local_addr.ip.ip4 = rte_cpu_to_be_32(param->local_addr.ip.ip4);
      iface->remote_addrs.addrs[0].ip.ip4 = rte_cpu_to_be_32(
                                              param->remote_addrs.addrs[0].ip.ip4);
      iface->remote_addrs.size = 1;

      break;
    case ADDRESS_TYPE_IPV6:
      TUNNEL_ERROR("[%s] unsupported IPv6 address", iface->base.name);
      return LAGOPUS_RESULT_UNSUPPORTED;
    default:
      TUNNEL_ERROR("[%s] invalid address type: %d", iface->base.name,
                   iface->address_type);
      return LAGOPUS_RESULT_UNSUPPORTED;
  }
  iface->hop_limit = param->hop_limit;
  iface->tos = param->tos;
  iface->trunk = param->trunk;
  iface->vni = param->vni;
  iface->enabled = true;
  iface->access_vid = param->vid;

  // add to VLAN list
  vlan_entry = l2tun_add_vlan_entry(iface, param->vid);
  if (unlikely(vlan_entry == NULL)) {
    TUNNEL_ERROR("[%s] no memory", iface->base.name);
    return LAGOPUS_RESULT_NO_MEMORY;
  }

  // set output
  if (iface->inbound) {
    vlan_entry->vlan->output = param->inbound_output;
  } else {
    vlan_entry->vlan->output = param->outbound_output;
  }

  // set VIF index
  vlan_entry->vlan->index = param->index;

  // set stats
  if (iface->inbound) {
    vlan_entry->vlan->stats = param->inbound_stats;
  } else {
    vlan_entry->vlan->stats = param->outbound_stats;
  }

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
l2gre_control_disable(struct l2tun_iface *iface,
                      struct l2tun_control_param *param) {
  if (!iface->trunk) {
    iface->enabled = false;
    iface->access_vid = 0;
  }

  // remove from VLAN list
  l2tun_remove_vlan_entry(iface, param->vid);

  return LAGOPUS_RESULT_OK;
}

static bool
l2gre_control_iface(__UNUSED void *priv, struct vsw_instance *base, void *p) {
  struct l2tun_iface *iface = (struct l2tun_iface *)base;
  struct l2tun_control_param *param = p;

  if (unlikely(iface == NULL)) {
    TUNNEL_ERROR("null instance");
    return false;
  }

  if (unlikely(param == NULL)) {
    TUNNEL_ERROR("[%s] null param", iface->base.name);
    return false;
  }

  TUNNEL_DEBUG("[%s] inbound=%d cmd=%d index=%d address_type=%d local=%d remote=%d "
               "hop_limit=%d tos=%d vid=%d trunk=%d vni=%d "
               "in_output=%p out_output=%p in_stats=%p out_stats=%p",
               iface->base.name, iface->inbound, param->cmd,
               param->index, param->address_type,
               param->local_addr.ip.ip4, param->remote_addrs.addrs[0].ip.ip4,
               param->hop_limit, param->tos, param->vid, param->trunk, param->vni,
               param->inbound_output, param->outbound_output,
               param->inbound_stats, param->outbound_stats);

  switch (param->cmd) {
    case L2TUN_CMD_SET_ADDRESS_TYPE:
      iface->address_type = param->address_type;
      break;
    case L2TUN_CMD_SET_LOCAL_ADDR:
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
    case L2TUN_CMD_SET_REMOTE_ADDRS:
      if (iface->address_type == ADDRESS_TYPE_IPV4) {
        iface->remote_addrs.addrs[0].ip.ip4 = rte_cpu_to_be_32(
                                                param->remote_addrs.addrs[0].ip.ip4);
        iface->remote_addrs.size = 1;
      } else if (iface->address_type == ADDRESS_TYPE_IPV6) {
        // TODO: IPv6
        TUNNEL_ERROR("[%s] unsupported IPv6 address", iface->base.name);
        return false;
      } else {
        TUNNEL_ERROR("[%s] invalid address type: %d", iface->base.name,
                     iface->address_type);
        return false;
      }
      break;
    case L2TUN_CMD_SET_HOP_LIMIT:
      iface->hop_limit = param->hop_limit;
      break;
    case L2TUN_CMD_SET_TOS:
      iface->tos = param->tos;
      break;
    case L2TUN_CMD_SET_TRUNK_MODE:
    case L2TUN_CMD_SET_ACCESS_MODE:
      iface->trunk = param->trunk;
      break;
    case L2TUN_CMD_SET_VNI:
      iface->vni = param->vni;
      break;
    case L2TUN_CMD_SET_ENABLE:
      if (unlikely(l2gre_control_enable(iface, param) != LAGOPUS_RESULT_OK)) {
        return false;
      }
      break;
    case L2TUN_CMD_SET_DISABLE:
      if (unlikely(l2gre_control_disable(iface, param) != LAGOPUS_RESULT_OK)) {
        return false;
      }
      break;
    default:
      TUNNEL_ERROR("[%s] unsupport cmd: %d", iface->base.name, param->cmd);
      return false;
  }

  return true;
}

static bool
l2gre_is_ready(struct l2tun_iface *iface) {
  if (iface->enabled) {
    if (iface->trunk) {
      if (iface->vlan_list->size == 0) {
        return false;
      }

      // TODO: check output

    } else {
      uint16_t output_vid = iface->access_vid;
      if (iface->vlans[output_vid] == NULL ||
          iface->vlans[output_vid]->output == NULL) {
        return false;
      }
    }
  } else {
    return false;
  }

  return true;
}

// inner VLAN
//   TRUNK : decap VLAN header, set VLAN metadata
//   ACCESS: set VLAN metadata
static inline lagopus_result_t
l2gre_inner_vlan_pop(struct l2tun_iface *iface, struct rte_mbuf *mbuf,
                     uint16_t *output_vid) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (iface->trunk) {
    ret = vlan_pop(mbuf, output_vid);

    // native VLAN
    if (ret == LAGOPUS_RESULT_UNSUPPORTED && iface->native_vid != 0) {
      ret = vlan_set_stripped(mbuf, iface->native_vid);
    }
  } else {
    *output_vid = iface->access_vid;
    ret = vlan_set_stripped(mbuf, *output_vid);
  }

  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_ERROR("[%s] can't pop/set metadata VLAN: %d", iface->base.name, ret);
    return ret;
  }

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
l2gre_decap(struct l2tun_iface *iface, struct rte_mbuf *mbuf,
            uint16_t *output_vid) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct ip *out_ip;
  uint16_t out_ip_proto;
  struct ipv4_hdr *out_ipv4_hdr;
  struct ipv6_hdr *out_ipv6_hdr;
  uint16_t out_ip_frag;
  uint16_t in_ether_type;
  struct l2tun_vlan *vlan = NULL;

  // Linearize mbuf
  if (unlikely(rte_pktmbuf_linearize(mbuf) != 0)) {
    TUNNEL_ERROR("[%s] not enough tailroom", iface->base.name);
    return LAGOPUS_RESULT_NO_MEMORY;
  }

  // Flooding packet
  if (unlikely(IS_FLOODING(mbuf) == true)) {
    TUNNEL_ERROR("[%s] invalid flooding packet", iface->base.name);
    return LAGOPUS_RESULT_INVALID_STATE;
  }

  // decap outer ethernet frame header
  ret = decap_ether(mbuf, NULL);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_ERROR("[%s] decap_eth failed: %d", iface->base.name, ret);
    return ret;
  }

  // decap outer IP header
  out_ip = rte_pktmbuf_mtod(mbuf, struct ip *);
  switch (out_ip->ip_v) {
    case IPVERSION:
      ret = decap_ip4(mbuf, 0, &out_ipv4_hdr);
      if (ret != LAGOPUS_RESULT_OK) {
        TUNNEL_ERROR("[%s] decap_ip4 failed: %d", iface->base.name, ret);
        return ret;
      }

      out_ip_frag = ntohs(out_ipv4_hdr->fragment_offset);
      if (unlikely(out_ip_frag != 0 && out_ip_frag != IPV4_HDR_DF_FLAG)) {
        TUNNEL_ERROR("[%s] invalid frag: %d", iface->base.name, out_ip_frag);
        return ret;
      }

      out_ip_proto = out_ipv4_hdr->next_proto_id;

      break;
    case IP6_VERSION:
      ret = decap_ip6(mbuf, 0, &out_ipv6_hdr);
      if (unlikely(ret != LAGOPUS_RESULT_OK)) {
        TUNNEL_ERROR("[%s] decap_ip6 failed: %d", iface->base.name, ret);
        return ret;
      }

      out_ip_proto = out_ipv6_hdr->proto;

      break;
    default:
      TUNNEL_ERROR("[%s] unsupported outer IP version: %d",
                   iface->base.name, out_ip->ip_v);
      return LAGOPUS_RESULT_UNKNOWN_PROTO;
  }

  // decap GRE header
  if (likely(out_ip_proto == IPPROTO_GRE)) {
    struct gre_hdr *gre_hdr;
    ret = decap_gre(mbuf, &gre_hdr);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_ERROR("[%s] decap_gre failed: %d", iface->base.name, ret);
      return ret;
    }

    in_ether_type = ntohs(gre_hdr->proto);
    if (unlikely(in_ether_type != ETHER_TYPE_TEB)) {
      TUNNEL_ERROR("[%s] invalid GRE protocol: %d", iface->base.name, in_ether_type);
      return LAGOPUS_RESULT_UNKNOWN_PROTO;
    }
  } else {
    TUNNEL_ERROR("[%s] invalid outer IP protocol: %d", iface->base.name,
                 out_ip_proto);
    return LAGOPUS_RESULT_UNKNOWN_PROTO;
  }

  // set inner dst address type(for stats)
  set_meta_inner_dst_ether_addr_type(mbuf);

  // set inner vlan tagged packet bytes(for stats)
  set_meta_inner_vlan_tagged_pkt_bytes(mbuf);

  // pop inner vlan
  ret = l2gre_inner_vlan_pop(iface, mbuf, output_vid);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    return ret;
  }

  // set inner packet bytes(for stats)
  set_meta_inner_pkt_bytes(mbuf);

  // set keep_ttl metadata
  set_meta_keep_ttl(mbuf);

  // update in_vif
  vlan = iface->vlans[*output_vid];
  if (vlan != NULL) {
    ret = set_meta_vif(mbuf, vlan->index);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      TUNNEL_ERROR("[%s] update in_vif failed: %d", iface->base.name, ret);
      return ret;
    }
  } else {
    TUNNEL_ERROR("[%s] unsupport vid packet: %d", iface->base.name, *output_vid);
    return LAGOPUS_RESULT_UNSUPPORTED;
  }

  // for debug
  //rte_pktmbuf_dump(stdout, mbuf, sizeof(struct rte_mbuf));

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
l2gre_inbound(struct l2tun_iface *iface) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct rte_mbuf *deq_mbufs[MAX_PKT_BURST];
  struct l2tun_vlan *vlan = NULL;
  struct l2tun_vlan_entry *vlan_entry = NULL;
  struct l2tun_mbuf *decap_mbufs = NULL;
  struct l2tun_mbuf *send_mbufs = NULL;
  uint16_t output_vid = 0;
  uint32_t deq_num = 0;
  uint32_t send_num = 0;
  uint32_t enq_num = 0;
  uint64_t total_num = 0;
  uint32_t error_num = 0;
  uint32_t drop_num = 0;

  deq_num = (uint32_t)rte_ring_dequeue_burst(iface->base.input2,
            (void **)deq_mbufs,
            MAX_PKT_BURST,
            NULL);

  if (deq_num == 0) {
    goto done;
  }

  // decap packet
  for (uint32_t i = 0; i < deq_num; i++) {
    ret = l2gre_decap(iface, deq_mbufs[i], &output_vid);
    if (likely(ret == LAGOPUS_RESULT_OK)) {
      vlan = iface->vlans[output_vid];
      if (likely(vlan != NULL)) {
        decap_mbufs = &(vlan->output_mbufs);
        decap_mbufs->mbufs[decap_mbufs->size] = deq_mbufs[i];
        decap_mbufs->size++;

        // update stats
        l2tun_update_stats(iface, vlan, deq_mbufs[i]);
      } else {
        TUNNEL_ERROR("[%s] unsupport vid packet: %d", iface->base.name, output_vid);
        rte_pktmbuf_free(deq_mbufs[i]);
        error_num++;
        l2tun_update_errors(iface);
      }
    } else if (ret == LAGOPUS_RESULT_UNKNOWN_PROTO) {
      error_num++;
      l2tun_update_unknown_protos(iface);
      rte_pktmbuf_free(deq_mbufs[i]);
    } else {
      error_num++;
      l2tun_update_errors(iface);
      rte_pktmbuf_free(deq_mbufs[i]);
    }
  }

  // send output
  vlan_entry = TAILQ_FIRST(&(iface->vlan_list->head));
  while (vlan_entry != NULL) {
    send_mbufs = &vlan_entry->vlan->output_mbufs;
    send_num = send_mbufs->size;

    if (send_num > 0) {
      enq_num = rte_ring_enqueue_burst(vlan_entry->vlan->output,
                                       (void *const *)send_mbufs->mbufs,
                                       send_num,
                                       NULL);

      if (unlikely(enq_num != send_num)) {
        TUNNEL_DEBUG("[%s] enqueue failed", iface->base.name);

        for (uint32_t i = enq_num; i < send_num; i++) {
          // update dropped stats
          l2tun_update_dropped(iface, vlan, send_mbufs->mbufs[i]);
          rte_pktmbuf_free(send_mbufs->mbufs[i]);
        }

        drop_num += (send_num - enq_num);
      }

      total_num += enq_num;
    }

    // clear
    send_mbufs->size = 0;

    // next
    vlan_entry = TAILQ_NEXT(vlan_entry, vlan_entries);
  }

  if (total_num > 0) {
    TUNNEL_DEBUG("[%s] dequeue=%d, rx_packets=%d, errors=%d, dropped=%d",
                 iface->base.name, deq_num, total_num, error_num, drop_num);
    tunnel_debug_print_stats(iface->base.name, iface->stats,
                             TUNNEL_STATS_TYPE_INBOUND);
  }

done:
  return LAGOPUS_RESULT_OK;
}

static bool
l2gre_inbound_process(void *p) {
  struct l2gre_runtime *rt = p;
  if (unlikely(rt == NULL)) {
    TUNNEL_ERROR("null runtime");
    return true;
  }

  struct l2tun_iface_entry *iface_entry = NULL;
  TAILQ_FOREACH(iface_entry, &(rt->iface_list->head), iface_entries) {
    struct l2tun_iface *iface = iface_entry->iface;
    if (l2gre_is_ready(iface)) {
      l2gre_inbound(iface);
    }
  }

  return true;
}

// inner VLAN
//   TRUNK : insert VLAN header
//   ACCESS: do nothing
static inline lagopus_result_t
l2gre_inner_vlan_push(struct l2tun_iface *iface, struct rte_mbuf *mbuf,
                      uint16_t *output_vid) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (iface->trunk) {
    *output_vid = mbuf->vlan_tci & 0x0fff;

    // native VLAN
    if (output_vid == 0) {
      if (iface->native_vid != 0) {
        *output_vid = iface->native_vid;
      } else {
        TUNNEL_ERROR("[%s] VID is not set", iface->base.name);
        return LAGOPUS_RESULT_INVALID_STATE;
      }
    }

    ret = vlan_push(mbuf);
    if (unlikely((ret != LAGOPUS_RESULT_OK))) {
      TUNNEL_ERROR("[%s] can't push VLAN: %d", iface->base.name, ret);
      return ret;
    }
  } else {
    *output_vid = iface->access_vid;
  }

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
l2gre_flooding(struct rte_mbuf **mbuf) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  // Flooding packet
  struct rte_mbuf *dst_mbuf;
  if (unlikely(IS_FLOODING(*mbuf) == true)) {
    ret = mbuf_clone(&dst_mbuf, *mbuf, (*mbuf)->pool);
    if (unlikely(ret != LAGOPUS_RESULT_OK)) {
      return ret;
    }
    *mbuf = dst_mbuf;
  }

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
l2gre_encap(struct l2tun_iface *iface, struct rte_mbuf **m,
            uint16_t *output_vid) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct rte_mbuf *mbuf = NULL;
  uint16_t out_ether_type = 0;

  // Flooding packet
  ret = l2gre_flooding(m);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_ERROR("[%s] mbuf clone failed: %d", iface->base.name, ret);
    return ret;
  }

  mbuf = *m;

  // set inner dst address type(for stats)
  set_meta_inner_dst_ether_addr_type(mbuf);

  // set inner packet bytes(for stats)
  set_meta_inner_pkt_bytes(mbuf);

  // push inner vlan
  ret = l2gre_inner_vlan_push(iface, mbuf, output_vid);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    return ret;
  }

  // reset metadata
  mbuf->vlan_tci = 0;

  // set inner vlan tagged packet bytes(for stats)
  set_meta_inner_vlan_tagged_pkt_bytes(mbuf);

  // encap GRE header
  ret = encap_gre(mbuf, ETHER_TYPE_TEB);
  if (unlikely(ret != LAGOPUS_RESULT_OK)) {
    TUNNEL_ERROR("[%s] encap_gre failed: %d", iface->base.name, ret);
    return ret;
  }

  // encap outer IP header
  switch (iface->address_type) {
    case ADDRESS_TYPE_IPV4:
      out_ether_type = ETHER_TYPE_IPv4;
      ret = encap_ip4(mbuf, 0, IPPROTO_GRE,
                      &iface->local_addr, &iface->remote_addrs.addrs[0],
                      iface->tos, 0, iface->hop_limit, true);
      break;
    case ADDRESS_TYPE_IPV6:
      out_ether_type = ETHER_TYPE_IPv6;
      ret = encap_ip6(mbuf, 0, IPPROTO_GRE,
                      &iface->local_addr, &iface->remote_addrs.addrs[0],
                      iface->tos, iface->hop_limit);
      break;
    default:
      TUNNEL_ERROR("[%s] unsupported address type: %d",
                   iface->base.name, iface->address_type);
      return LAGOPUS_RESULT_UNKNOWN_PROTO;
  }

  if (unlikely((ret != LAGOPUS_RESULT_OK))) {
    TUNNEL_ERROR("[%s] encap IP failed: %d", iface->base.name, ret);
    return ret;
  }

  // encap outer ethernet frame header
  ret = encap_ether(mbuf, out_ether_type);
  if (ret != LAGOPUS_RESULT_OK) {
    TUNNEL_ERROR("[%s] encap_eth failed: %d", iface->base.name, ret);
    return ret;
  }

  // set encap, keep_ttl metadata
  set_meta_encap(mbuf);
  set_meta_keep_ttl(mbuf);

  // for debug
  //rte_pktmbuf_dump(stdout, mbuf, sizeof(struct rte_mbuf));

  return LAGOPUS_RESULT_OK;
}

static inline lagopus_result_t
l2gre_outbound(struct l2tun_iface *iface) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct rte_mbuf *deq_mbufs[MAX_PKT_BURST];
  struct l2tun_vlan *vlan = NULL;
  struct l2tun_vlan_entry *vlan_entry = NULL;
  struct l2tun_mbuf *encap_mbufs = NULL;
  struct l2tun_mbuf *send_mbufs = NULL;
  uint16_t output_vid = 0;
  uint32_t deq_num = 0;
  uint32_t send_num = 0;
  uint32_t enq_num = 0;
  uint64_t total_num = 0;
  uint32_t error_num = 0;
  uint32_t drop_num = 0;

  deq_num = (uint32_t)rte_ring_dequeue_burst(iface->base.input,
            (void **)deq_mbufs,
            MAX_PKT_BURST,
            NULL);

  if (deq_num == 0) {
    goto done;
  }

  // encap packet
  for (uint32_t i = 0; i < deq_num; i++) {
    ret = l2gre_encap(iface, &deq_mbufs[i], &output_vid);
    if (likely(ret == LAGOPUS_RESULT_OK)) {
      vlan = iface->vlans[output_vid];
      if (likely(vlan != NULL)) {
        encap_mbufs = &(vlan->output_mbufs);
        encap_mbufs->mbufs[encap_mbufs->size] = deq_mbufs[i];
        encap_mbufs->size++;

        // update stats
        l2tun_update_stats(iface, vlan, deq_mbufs[i]);
      } else {
        TUNNEL_ERROR("[%s] unsupport vid packet: %d", iface->base.name, output_vid);
        error_num++;
        l2tun_update_errors(iface);
        rte_pktmbuf_free(deq_mbufs[i]);
      }
    } else {
      error_num++;
      l2tun_update_errors(iface);
      rte_pktmbuf_free(deq_mbufs[i]);
    }
  }

  // send output
  vlan_entry = TAILQ_FIRST(&(iface->vlan_list->head));
  while (vlan_entry != NULL) {
    send_mbufs = &vlan_entry->vlan->output_mbufs;
    send_num = send_mbufs->size;

    if (send_num > 0) {
      enq_num = rte_ring_enqueue_burst(vlan_entry->vlan->output,
                                       (void *const *)send_mbufs->mbufs,
                                       send_num,
                                       NULL);

      if (unlikely(enq_num != send_num)) {
        TUNNEL_DEBUG("[%s] enqueue failed", iface->base.name);

        for (uint32_t i = enq_num; i < send_num; i++) {
          // update dropped stats
          l2tun_update_dropped(iface, vlan, send_mbufs->mbufs[i]);
          rte_pktmbuf_free(send_mbufs->mbufs[i]);
        }

        drop_num += (send_num - enq_num);
      }

      total_num += enq_num;
    }

    // clear
    send_mbufs->size = 0;

    // next
    vlan_entry = TAILQ_NEXT(vlan_entry, vlan_entries);
  }

  if (total_num > 0) {
    TUNNEL_DEBUG("[%s] dequeue=%d, tx_packets=%d, errors=%d, dropped=%d",
                 iface->base.name, deq_num, total_num, error_num, drop_num);
    tunnel_debug_print_stats(iface->base.name, iface->stats,
                             TUNNEL_STATS_TYPE_OUTBOUND);
  }

done:
  return LAGOPUS_RESULT_OK;
}

static bool
l2gre_outbound_process(void *p) {
  struct l2gre_runtime *rt = p;
  if (unlikely(rt == NULL)) {
    TUNNEL_ERROR("null runtime");
    return true;
  }

  struct l2tun_iface_entry *iface_entry = NULL;
  TAILQ_FOREACH(iface_entry, &(rt->iface_list->head), iface_entries) {
    struct l2tun_iface *iface = iface_entry->iface;
    if (l2gre_is_ready(iface)) {
      l2gre_outbound(iface);
    }
  }

  return true;
}

static void *
l2gre_init(__UNUSED void *param) {
  struct l2gre_runtime *rt = NULL;

  // create runtime
  if ((rt = (struct l2gre_runtime *) calloc(1,
            sizeof(struct l2gre_runtime))) == NULL) {
    TUNNEL_ERROR("gre_runtime calloc() failed");
    return NULL;
  }

  // create iface list
  if ((rt->iface_list = l2tun_create_iface_list()) == NULL) {
    TUNNEL_ERROR("l2tun_create_iface_list() failed");
    free(rt);
    return NULL;
  }

  TUNNEL_DEBUG("slave core=%u", rte_lcore_id());

  return rt;
}

static void
l2gre_deinit(void *p) {
  struct l2gre_runtime *rt = p;

  // free iface list
  l2tun_free_iface_list(rt->iface_list);

  // free runtime
  free(rt);

  TUNNEL_DEBUG("slave core=%u", rte_lcore_id());
}

struct vsw_runtime_ops l2gre_inbound_runtime_ops = {
  .init = l2gre_init,
  .process = l2gre_inbound_process,
  .deinit = l2gre_deinit,
  .register_instance = l2gre_register_iface,
  .unregister_instance = l2gre_unregister_iface,
  .update_rings = NULL,
  .control_instance = l2gre_control_iface,
};

struct vsw_runtime_ops l2gre_outbound_runtime_ops = {
  .init = l2gre_init,
  .process = l2gre_outbound_process,
  .deinit = l2gre_deinit,
  .register_instance = l2gre_register_iface,
  .unregister_instance = l2gre_unregister_iface,
  .update_rings = NULL,
  .control_instance = l2gre_control_iface,
};
