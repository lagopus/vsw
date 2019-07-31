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

#ifndef SP6_H
#define SP6_H

#include <rte_acl.h>

#include "lagopus_apis.h"
#include "sp.h"
#include "ipsec.h"

enum {
  PROTO_FIELD_IPV6,
  SRC0_FIELD_IPV6,
  SRC1_FIELD_IPV6,
  SRC2_FIELD_IPV6,
  SRC3_FIELD_IPV6,
  DST0_FIELD_IPV6,
  DST1_FIELD_IPV6,
  DST2_FIELD_IPV6,
  DST3_FIELD_IPV6,
  SRCP_FIELD_IPV6,
  DSTP_FIELD_IPV6,
  NUM_FIELDS_IPV6
};

#define IPV6_LEN 16

struct acl6_params {
  uint16_t policy;
  int32_t priority;
  uint32_t spi;
  uint32_t entry_id;  /* use 12-bit. */
  uint8_t proto;
  uint8_t proto_mask;
  uint8_t src_ip[IPV6_LEN];
  uint32_t src_ip_mask;
  uint8_t dst_ip[IPV6_LEN];
  uint32_t dst_ip_mask;
  uint16_t src_port;
  uint16_t src_port_mask;
  uint16_t dst_port;
  uint16_t dst_port_mask;
};

RTE_ACL_RULE_DEF(acl6_rules, NUM_FIELDS_IPV6);

struct spd6;

struct acl6_rules *
sp6_alloc_rules(size_t size);

void
sp6_free_rules(struct acl6_rules *rules);

lagopus_result_t
sp6_make_spd(struct spd6 *spd6,
             const struct acl6_rules *in_rules,
             uint32_t in_rules_nb,
             const struct acl6_rules *out_rules,
             uint32_t out_rules_nb);

lagopus_result_t
sp6_pre_process(struct spd6 *spd6);

lagopus_result_t
sp6_post_process(struct spd6 *spd6);

lagopus_result_t
sp6_classify_spd_in(void *spd,
                    const uint8_t **data,
                    uint32_t *results,
                    uint32_t num);

lagopus_result_t
sp6_classify_spd_out(void *spd,
                     const uint8_t **data,
                     uint32_t *results,
                     uint32_t num);

lagopus_result_t
sp6_set_lifetime_current(void *spd,
                         uint32_t sa_index,
                         lagopus_chrono_t now);

lagopus_result_t
sp6_get_stats(struct spd6 *spd6,
              struct spd_stats *stats,
              uint32_t spi);

lagopus_result_t
sp6_get_stats_array(struct spd6 *spd6,
                    struct spd_stats **stats);

lagopus_result_t
sp6_initialize(struct spd6 **spd6,
               uint32_t socket_id);

void
sp6_finalize(struct spd6 **spd6);

lagopus_result_t
sp6_set_rule(size_t index,
             struct acl6_rules *rules,
             const struct acl6_params *params);

void
sp6_dump_rules(const struct acl6_rules *rule,
               int32_t num);

#endif /* SP6_H */
