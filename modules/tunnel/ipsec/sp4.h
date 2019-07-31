/*
 * Copyright 2018-2019 Nippon Telegraph and Telephone Corporation.
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

#ifndef SP4_H
#define SP4_H

#include <rte_acl.h>

#include "lagopus_apis.h"
#include "sp.h"
#include "ipsec.h"

/*
 * Rule and trace formats definitions.
 */
enum {
  PROTO_FIELD_IPV4,
  SRC_FIELD_IPV4,
  DST_FIELD_IPV4,
  SRCP_FIELD_IPV4,
  DSTP_FIELD_IPV4,
  NUM_FIELDS_IPV4
};

/*
 * That effectively defines order of IPV4 classifications:
 *  - PROTO
 *  - SRC IP ADDRESS
 *  - DST IP ADDRESS
 *  - PORTS (SRC and DST)
 */
enum {
  RTE_ACL_IPV4_PROTO,
  RTE_ACL_IPV4_SRC,
  RTE_ACL_IPV4_DST,
  RTE_ACL_IPV4_PORTS,
  RTE_ACL_IPV4_NUM
};

struct acl4_params {
  uint16_t policy;
  int32_t priority;
  uint32_t spi;
  uint32_t entry_id; /* use 12-bit. */
  uint8_t proto;
  uint8_t proto_mask;
  uint32_t src_ip;
  uint32_t src_ip_mask;
  uint32_t dst_ip;
  uint32_t dst_ip_mask;
  uint16_t src_port;
  uint16_t src_port_mask;
  uint16_t dst_port;
  uint16_t dst_port_mask;
};

RTE_ACL_RULE_DEF(acl4_rules, NUM_FIELDS_IPV4);

struct spd4;

struct acl4_rules *
sp4_alloc_rules(size_t size);

void
sp4_free_rules(struct acl4_rules *rules);

lagopus_result_t
sp4_make_spd(struct spd4 *spd4,
             const struct acl4_rules *in_rules,
             uint32_t in_rules_nb,
             const struct acl4_rules *out_rules,
             uint32_t out_rules_nb);

lagopus_result_t
sp4_pre_process(struct spd4 *spd4);

lagopus_result_t
sp4_post_process(struct spd4 *spd4);

lagopus_result_t
sp4_classify_spd_in(void *spd,
                    const uint8_t **data,
                    uint32_t *results,
                    uint32_t num);

lagopus_result_t
sp4_classify_spd_out(void *spd,
                     const uint8_t **data,
                     uint32_t *results,
                     uint32_t num);

lagopus_result_t
sp4_set_lifetime_current(void *spd,
                         uint32_t sa_index,
                         lagopus_chrono_t now);

lagopus_result_t
sp4_get_stats(struct spd4 *spd4,
              struct spd_stats *stats,
              uint32_t spi);

lagopus_result_t
sp4_get_stats_array(struct spd4 *spd4,
                    struct spd_stats **stats);

lagopus_result_t
sp4_initialize(struct spd4 **spd4,
               uint32_t socket_id);

void
sp4_finalize(struct spd4 **spd4);

lagopus_result_t
sp4_set_rule(size_t index,
             struct acl4_rules *rules,
             const struct acl4_params *params);

void
sp4_dump_rules(const struct acl4_rules *rule,
               int32_t num);

#endif /* SP4_H */
