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
#include <stdbool.h>
#include <sys/queue.h>

#include "logger.h"
#include "ipip.h"

#define __UNUSED __attribute__((unused))

struct ipip_iface_entry {
  TAILQ_ENTRY(ipip_iface_entry) entries;
  struct ipip_iface *iface;
};

TAILQ_HEAD(ipip_iface_head, ipip_iface_entry);

struct ipip_iface_list {
  size_t size;
  struct ipip_iface_head head;
};

typedef struct ipip_iface_list ipip_iface_list_t;

struct ipip_runtime {
  ipip_iface_list_t *iface_list;
};

static bool
ipip_register_iface(void *priv, struct lagopus_instance *base) {
  struct ipip_runtime *rt = priv;
  struct ipip_iface *iface = (struct ipip_iface *)base;
  struct ipip_iface_entry *entry = NULL;

  if (rt == NULL) {
    lagopus_printf("[%s] %s: null runtime", IPIP_MODULE_NAME, __func__);
    return false;
  }

  if (iface == NULL) {
    lagopus_printf("[%s] %s: null instance", IPIP_MODULE_NAME, __func__);
    return false;
  }

  entry = (struct ipip_iface_entry *) calloc(1, sizeof(struct ipip_iface_entry));
  if (entry == NULL) {
    lagopus_printf("[%s] %s(%s): no memory",
                   IPIP_MODULE_NAME, iface->base.name, __func__);
    return false;
  }

  entry->iface = iface;

  TAILQ_INSERT_TAIL(&(rt->iface_list->head), entry, entries);
  rt->iface_list->size++;

  return true;
}

static bool
ipip_unregister_iface(void *priv, struct lagopus_instance *base) {
  struct ipip_runtime *rt = priv;
  struct ipip_iface *iface = (struct ipip_iface *)base;
  struct ipip_iface_entry *entry = NULL;

  if (rt == NULL) {
    lagopus_printf("[%s] %s: null runtime", IPIP_MODULE_NAME, __func__);
    return false;
  }

  if (iface == NULL) {
    lagopus_printf("[%s] %s: null instance", IPIP_MODULE_NAME, __func__);
    return false;
  }

  entry = TAILQ_FIRST(&(rt->iface_list->head));
  while (entry != NULL) {
    if (entry->iface->index == iface->index) {
      TAILQ_REMOVE(&(rt->iface_list->head), entry, entries);
      free(entry);
      rt->iface_list->size--;
      break;
    }
    entry = TAILQ_NEXT(entry, entries);
  }

  return true;
}

static bool
ipip_control_iface(__UNUSED void *priv, struct lagopus_instance *base,
                   void *p) {
  struct ipip_iface *iface = (struct ipip_iface *)base;
  struct ipip_control_param *param = p;

  if (iface == NULL) {
    lagopus_printf("[%s] %s: null instance", IPIP_MODULE_NAME, __func__);
    return false;
  }

  if (param == NULL) {
    lagopus_printf("[%s] %s(%s): null param",
                   IPIP_MODULE_NAME, iface->base.name, __func__);
    return false;
  }

  LAGOPUS_DEBUG("[%s] %s(%s): index=%d cmd=%d address_type=%d local=%d remote=%d hop_limit=%d tos=%d output=%p",
                IPIP_MODULE_NAME, iface->base.name, __func__,
                iface->index, param->cmd, param->address_type,
                param->local_addr.ip.ip4, param->remote_addr.ip.ip4,
                param->hop_limit, param->tos, param->output);

  switch (param->cmd) {
    case IPIP_CMD_SET_ADDRESS_TYPE:
      iface->address_type = param->address_type;
      break;
    case IPIP_CMD_SET_LOCAL_ADDR:
      iface->local_addr.ip.ip4 = rte_cpu_to_be_32(param->local_addr.ip.ip4);
      break;
    case IPIP_CMD_SET_REMOTE_ADDR:
      iface->remote_addr.ip.ip4 = rte_cpu_to_be_32(param->remote_addr.ip.ip4);
      break;
    case IPIP_CMD_SET_HOP_LIMIT:
      iface->hop_limit = param->hop_limit;
      break;
    case IPIP_CMD_SET_TOS:
      iface->tos = param->tos;
      break;
    case IPIP_CMD_SET_OUTPUT:
      iface->output = param->output;
      break;
    case IPIP_CMD_SET_ENABLE:
      iface->enable = param->enable;
      break;
    case IPIP_CMD_SET_ALL:
      iface->address_type = param->address_type;
      iface->local_addr.ip.ip4 = rte_cpu_to_be_32(param->local_addr.ip.ip4);
      iface->remote_addr.ip.ip4 = rte_cpu_to_be_32(param->remote_addr.ip.ip4);
      iface->hop_limit = param->hop_limit;
      iface->tos = param->tos;
      iface->output = param->output;
      iface->enable = param->enable;
      break;
    default:
      return false;
  }

  return true;
}

static bool
ipip_is_ready(struct ipip_iface *iface) {
  if (iface->enable && iface->output != NULL) {
    return true;
  }

  return false;
}

static inline bool
ipip_inbound(struct ipip_iface *iface) {
  struct rte_mbuf *deq_mbufs[MAX_PKT_BURST];
  struct rte_mbuf *enq_mbufs[MAX_PKT_BURST];
  uint32_t enq_num = 0;
  uint32_t deq_num = (uint32_t)rte_ring_dequeue_burst(iface->base.input2,
                                                      (void **)deq_mbufs,
                                                      MAX_PKT_BURST,
                                                      NULL);
  for (uint32_t i = 0; i < deq_num; i++) {
    lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

    struct rte_mbuf *mbuf = deq_mbufs[i];

    // decap ethernet frame header
    ret = decap_ether(mbuf, NULL);
    if (ret != LAGOPUS_RESULT_OK) {
      lagopus_printf("[%s] %s(%s): decap_eth failed %d",
                     IPIP_MODULE_NAME, iface->base.name, __func__, ret);
      rte_pktmbuf_free(mbuf);
      iface->errors++;
      continue;
    }

    struct ip *outip = rte_pktmbuf_mtod(mbuf, struct ip *);
    if (outip == NULL) {
      lagopus_printf("[%s] %s(%s): no outer IP header",
                     IPIP_MODULE_NAME, iface->base.name, __func__);
      rte_pktmbuf_free(mbuf);
      iface->errors++;
      continue;
    }

    // dencap outer IPv4/6 header
    if (likely(outip->ip_v == IPVERSION)) {
      struct ipv4_hdr *ipv4_hdr;
      ret = decap_ip4(mbuf, 0, &ipv4_hdr);
      if (ret != LAGOPUS_RESULT_OK) {
        lagopus_printf("[%s] %s(%s): decap_ip4 failed %d",
                       IPIP_MODULE_NAME, iface->base.name, __func__, ret);
        rte_pktmbuf_free(mbuf);
        iface->errors++;
        continue;
      }

      uint16_t frag = ntohs(ipv4_hdr->fragment_offset);
      if (frag != 0 && frag != IPV4_HDR_DF_FLAG) {
        lagopus_printf("[%s] %s(%s): invalid frag %d",
                       IPIP_MODULE_NAME, iface->base.name, __func__, frag);
        rte_pktmbuf_free(mbuf);
        iface->errors++;
        continue;
      }
    } else if (outip->ip_v != IP6_VERSION) {
      ret = decap_ip6(mbuf, 0, NULL);
      if (ret != LAGOPUS_RESULT_OK) {
        lagopus_printf("[%s] %s(%s): decap_ip6 failed %d",
                       IPIP_MODULE_NAME, iface->base.name, __func__, ret);
        rte_pktmbuf_free(mbuf);
        iface->errors++;
        continue;
      }
    } else {
      lagopus_printf("[%s] %s(%s): unsupported outer IP version %d",
                     IPIP_MODULE_NAME, iface->base.name, __func__, outip->ip_v);
      rte_pktmbuf_free(mbuf);
      iface->errors++;
      continue;
    }

    struct ip *inip = rte_pktmbuf_mtod(mbuf, struct ip *);
    if (inip == NULL) {
      lagopus_printf("[%s] %s(%s): no inner IP header",
                     IPIP_MODULE_NAME, iface->base.name, __func__);
      rte_pktmbuf_free(mbuf);
      iface->errors++;
      continue;
    }

    uint16_t ether_type;
    if (likely(inip->ip_v == IPVERSION)) {
      ether_type = ETHER_TYPE_IPv4;
    } else if (inip->ip_v != IP6_VERSION) {
      ether_type = ETHER_TYPE_IPv6;
    } else {
      lagopus_printf("[%s] %s(%s): unsupported inner IP version %d",
                     IPIP_MODULE_NAME, iface->base.name, __func__, inip->ip_v);
      rte_pktmbuf_free(mbuf);
      iface->errors++;
      continue;
    }

    // encap ethernet frame header
    ret = encap_ether(mbuf, ether_type);
    if (ret != LAGOPUS_RESULT_OK) {
      lagopus_printf("[%s] %s(%s): encap_eth failed %d",
                     IPIP_MODULE_NAME, iface->base.name, __func__, ret);
      rte_pktmbuf_free(mbuf);
      iface->errors++;
      continue;
    }

    // set local metadata
    ret = set_meta_local(mbuf);
    if (ret != LAGOPUS_RESULT_OK) {
      lagopus_printf("[%s] %s(%s): set_local failed %d",
                     IPIP_MODULE_NAME, iface->base.name, __func__, ret);
      rte_pktmbuf_free(mbuf);
      iface->errors++;
      continue;
    }

    enq_mbufs[enq_num++] = deq_mbufs[i];
  }

  // send output
  if (enq_num > 0) {
    uint32_t sent = rte_ring_enqueue_burst(iface->output,
                                           (void * const*)enq_mbufs,
                                           enq_num,
                                           NULL);
    if (enq_num == sent) {
      iface->rx_packets += enq_num;
    } else {
      lagopus_printf("[%s] %s(%s): enqueue failed",
                     IPIP_MODULE_NAME, iface->base.name, __func__);

      for (uint32_t i = sent; i < enq_num; i++) {
        rte_pktmbuf_free(enq_mbufs[i]);
      }

      iface->rx_packets += sent;
      iface->dropped += (enq_num - sent);
    }

    LAGOPUS_DEBUG("[%s] %s(%s): dequeue=%d, enqueue=%d, rx_packets=%d, errors=%d, dropped=%d",
                  IPIP_MODULE_NAME, iface->base.name, __func__, deq_num, enq_num,
                  iface->rx_packets, iface->errors, iface->dropped);
  }

  return true;
}

static bool
ipip_inbound_process(void *p) {
  struct ipip_runtime *rt = p;
  if (rt == NULL) {
    lagopus_printf("[%s] (%s): null runtime", IPIP_MODULE_NAME, __func__);
    return true;
  }

  struct ipip_iface_entry *entry = NULL;
  TAILQ_FOREACH(entry, &(rt->iface_list->head), entries) {
    struct ipip_iface *iface = entry->iface;
    if (ipip_is_ready(iface)) {
      ipip_inbound(iface);
    }
  }

  return true;
}

static inline bool
ipip_outbound(struct ipip_iface *iface) {
  struct rte_mbuf *deq_mbufs[MAX_PKT_BURST];
  struct rte_mbuf *enq_mbufs[MAX_PKT_BURST];
  uint32_t enq_num = 0;
  uint32_t deq_num = (uint32_t)rte_ring_dequeue_burst(iface->base.input,
                                                      (void **)deq_mbufs,
                                                      MAX_PKT_BURST,
                                                      NULL);
  for (uint32_t i = 0; i < deq_num; i++) {
    lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

    struct rte_mbuf *mbuf = deq_mbufs[i];

    // decap ethernet frame header
    ret = decap_ether(mbuf, NULL);
    if (ret != LAGOPUS_RESULT_OK) {
      lagopus_printf("[%s] %s(%s): decap_eth failed %d",
                     IPIP_MODULE_NAME, iface->base.name, __func__, ret);
      rte_pktmbuf_free(mbuf);
      iface->errors++;
      continue;
    }

    struct ip *inip = rte_pktmbuf_mtod(mbuf, struct ip *);
    if (inip == NULL) {
      lagopus_printf("[%s] %s(%s): no inner IP header",
                     IPIP_MODULE_NAME, iface->base.name, __func__);
      rte_pktmbuf_free(mbuf);
      iface->errors++;
      continue;
    } else if (inip->ip_v != IPVERSION && inip->ip_v != IP6_VERSION) {
      lagopus_printf("[%s] %s(%s): unsupported inner IP version %d",
                     IPIP_MODULE_NAME, iface->base.name, __func__, inip->ip_v);
      rte_pktmbuf_free(mbuf);
      iface->errors++;
      continue;
    }

    uint8_t tos = convert_ip_tos(inip, iface->tos);
    uint16_t off = inip->ip_off;
    uint8_t ttl = convert_ip_ttl(inip, iface->hop_limit);

    // encap IPv4/6 header
    uint16_t ether_type;
    if (likely(iface->address_type == AF_IPV4)) {
      ret = encap_ip4(mbuf, 0, IPPROTO_IPIP,
                &iface->local_addr, &iface->remote_addr,
                tos, off, ttl, true);
      if (ret != LAGOPUS_RESULT_OK) {
        lagopus_printf("[%s] %s(%s): encap_ip4 failed %d",
                       IPIP_MODULE_NAME, iface->base.name, __func__, ret);
        rte_pktmbuf_free(mbuf);
        iface->errors++;
        continue;
      }

      ether_type = ETHER_TYPE_IPv4;
    } else if (iface->address_type == AF_IPV6) {
      ret = encap_ip6(mbuf, 0, IPPROTO_IPIP,
                &iface->local_addr, &iface->remote_addr,
                tos, ttl);
      if (ret != LAGOPUS_RESULT_OK) {
        lagopus_printf("[%s] %s(%s): encap_ip6 failed %d",
                       IPIP_MODULE_NAME, iface->base.name, __func__, ret);
        rte_pktmbuf_free(mbuf);
        iface->errors++;
        continue;
      }

      ether_type = ETHER_TYPE_IPv6;
    } else {
      lagopus_printf("[%s] %s(%s): unsupported address type %d",
                     IPIP_MODULE_NAME, iface->base.name, __func__, iface->address_type);
      rte_pktmbuf_free(mbuf);
      iface->errors++;
      continue;
    }

    // encap ethernet frame header
    ret = encap_ether(mbuf, ether_type);
    if (ret != LAGOPUS_RESULT_OK) {
      lagopus_printf("[%s] %s(%s): encap_eth failed %d",
                     IPIP_MODULE_NAME, iface->base.name, __func__, ret);
      rte_pktmbuf_free(mbuf);
      iface->errors++;
      continue;
    }

    // set local metadata
    ret = set_meta_local(mbuf);
    if (ret != LAGOPUS_RESULT_OK) {
      lagopus_printf("[%s] %s(%s): set_local failed %d",
                     IPIP_MODULE_NAME, iface->base.name, __func__, ret);
      rte_pktmbuf_free(mbuf);
      iface->errors++;
      continue;
    }

    enq_mbufs[enq_num++] = deq_mbufs[i];
  }

  // send output
  if (enq_num > 0) {
    uint32_t sent = rte_ring_enqueue_burst(iface->output,
                                           (void * const*)enq_mbufs,
                                           enq_num,
                                           NULL);
    if (enq_num == sent) {
      iface->tx_packets += enq_num;
    } else {
      lagopus_printf("[%s] %s(%s): enqueue failed",
                     IPIP_MODULE_NAME, iface->base.name, __func__);

      for (uint32_t i = sent; i < enq_num; i++) {
        rte_pktmbuf_free(enq_mbufs[i]);
      }

      iface->tx_packets += sent;
      iface->dropped += (enq_num - sent);
    }

    LAGOPUS_DEBUG("[%s] %s(%s): dequeue=%d, enqueue=%d, tx_packets=%d, errors=%d, dropped=%d",
                  IPIP_MODULE_NAME, iface->base.name, __func__, deq_num, enq_num,
                  iface->tx_packets, iface->errors, iface->dropped);
  }

  return true;
}

static bool
ipip_outbound_process(void *p) {
  struct ipip_runtime *rt = p;
  if (rt == NULL) {
    lagopus_printf("[%s] (%s): null runtime", IPIP_MODULE_NAME, __func__);
    return true;
  }

  struct ipip_iface_entry *entry = NULL;
  TAILQ_FOREACH(entry, &(rt->iface_list->head), entries) {
    struct ipip_iface *iface = entry->iface;
    if (ipip_is_ready(iface)) {
      ipip_outbound(iface);
    }
  }

  return true;
}

static void *
ipip_init(__UNUSED void *param) {
  struct ipip_runtime *rt = NULL;

  if ((rt = (struct ipip_runtime *) calloc(1,
            sizeof(struct ipip_runtime))) == NULL) {
    lagopus_printf("[%s] (%s): ipip_runtime calloc() failed.",
                   IPIP_MODULE_NAME, __func__);
    return NULL;
  }

  if ((rt->iface_list = (ipip_iface_list_t *) calloc(1,
                        sizeof(ipip_iface_list_t))) == NULL) {
    lagopus_printf("[%s] (%s): ipip_iface_list_t calloc() failed.",
                   IPIP_MODULE_NAME, __func__);
    free(rt);
    return NULL;
  }

  TAILQ_INIT(&(rt->iface_list->head));
  rt->iface_list->size = 0;

  LAGOPUS_DEBUG("[%s] (%s): slave core=%u",
                IPIP_MODULE_NAME, __func__, rte_lcore_id());

  return rt;
}

static void
ipip_deinit(void *p) {
  struct ipip_runtime *rt = p;
  struct ipip_iface_entry *entry = NULL;

  while ((entry = TAILQ_FIRST(&(rt->iface_list->head))) != NULL) {
    TAILQ_REMOVE(&(rt->iface_list->head), entry, entries);
    // free entry only. iface is free on Go.
    free(entry);
    rt->iface_list->size--;
  }

  RTE_ASSERT(rt->iface_list->size == 0);

  free(rt->iface_list);
  free(rt);
}

struct lagopus_runtime_ops ipip_inbound_runtime_ops = {
  .init = ipip_init,
  .process = ipip_inbound_process,
  .deinit = ipip_deinit,
  .register_instance = ipip_register_iface,
  .unregister_instance = ipip_unregister_iface,
  .update_rings = NULL,
  .control_instance = ipip_control_iface,
};

struct lagopus_runtime_ops ipip_outbound_runtime_ops = {
  .init = ipip_init,
  .process = ipip_outbound_process,
  .deinit = ipip_deinit,
  .register_instance = ipip_register_iface,
  .unregister_instance = ipip_unregister_iface,
  .update_rings = NULL,
  .control_instance = ipip_control_iface,
};
