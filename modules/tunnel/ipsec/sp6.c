/*
 * Copyright 2019 Nippon Telegraph and Telephone Corporation.
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

/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Security Policies
 */
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <linux/ipsec.h>

#include <rte_acl.h>
#include <rte_ip.h>
#include <rte_random.h>
#include <rte_cycles.h>
#include <rte_atomic.h>

#include "lagopus_apis.h"
#include "ipsec.h"
#include "sp6.h"

struct rte_acl_field_def ip6_defs[NUM_FIELDS_IPV6] = {
  {
    .type = RTE_ACL_FIELD_TYPE_BITMASK,
    .size = sizeof(uint8_t),
    .field_index = PROTO_FIELD_IPV6,
    .input_index = PROTO_FIELD_IPV6,
    .offset = 0,
  },
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = 4,
    .field_index = SRC0_FIELD_IPV6,
    .input_index = SRC0_FIELD_IPV6,
    .offset = 2
  },
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = 4,
    .field_index = SRC1_FIELD_IPV6,
    .input_index = SRC1_FIELD_IPV6,
    .offset = 6
  },
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = 4,
    .field_index = SRC2_FIELD_IPV6,
    .input_index = SRC2_FIELD_IPV6,
    .offset = 10
  },
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = 4,
    .field_index = SRC3_FIELD_IPV6,
    .input_index = SRC3_FIELD_IPV6,
    .offset = 14
  },
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = 4,
    .field_index = DST0_FIELD_IPV6,
    .input_index = DST0_FIELD_IPV6,
    .offset = 18
  },
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = 4,
    .field_index = DST1_FIELD_IPV6,
    .input_index = DST1_FIELD_IPV6,
    .offset = 22
  },
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = 4,
    .field_index = DST2_FIELD_IPV6,
    .input_index = DST2_FIELD_IPV6,
    .offset = 26
  },
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = 4,
    .field_index = DST3_FIELD_IPV6,
    .input_index = DST3_FIELD_IPV6,
    .offset = 30
  },
  {
    .type = RTE_ACL_FIELD_TYPE_RANGE,
    .size = sizeof(uint16_t),
    .field_index = SRCP_FIELD_IPV6,
    .input_index = SRCP_FIELD_IPV6,
    .offset = 34
  },
  {
    .type = RTE_ACL_FIELD_TYPE_RANGE,
    .size = sizeof(uint16_t),
    .field_index = DSTP_FIELD_IPV6,
    .input_index = DSTP_FIELD_IPV6,
    .offset = 36
  }
};

struct spd6_attr {
  struct rte_acl_ctx *in;
  struct rte_acl_ctx *out;
  rte_atomic16_t refs;
};

struct spd6 {
  struct spd6_attr *db[2];
  struct spd_stats stats[IPSEC_SP_MAX_ENTRIES];
  rte_atomic64_t seq;
  uint64_t current;
};

static inline struct rte_acl_ctx *
spd6_alloc_acl_ctx(const char *name, uint32_t socketid) {
  struct rte_acl_param acl_param;
  char s[PATH_MAX];

  memset(&acl_param, 0, sizeof(acl_param));

  /* Create ACL contexts */
  snprintf(s, sizeof(s), "%s_%d_%"PRIu64, name, socketid, rte_rand());

  acl_param.name = s;
  acl_param.socket_id = (int) socketid;
  acl_param.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ip6_defs));
  acl_param.max_rule_num = MAX_ACL_RULE_NUM;

  return rte_acl_create(&acl_param);
}

static inline lagopus_result_t
spd6_alloc_spd_attr(uint32_t socketid,
                    struct spd6_attr **attr) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  const char *name;

  if (attr != NULL) {
    *attr = (struct spd6_attr *) calloc(1, sizeof(struct spd6_attr));
    if (*attr == NULL) {
      ret = LAGOPUS_RESULT_NO_MEMORY;
      TUNNEL_PERROR(ret);
      goto done;
    }

    rte_atomic16_init(&(*attr)->refs);

    name = "sp_ip6_in";
    (*attr)->in = spd6_alloc_acl_ctx(name, socketid);
    if ((*attr)->in == NULL) {
      ret = LAGOPUS_RESULT_NO_MEMORY;
      TUNNEL_PERROR(ret);
      goto done;
    }

    name = "sp_ip6_out";
    (*attr)->out = spd6_alloc_acl_ctx(name, socketid);
    if ((*attr)->out == NULL) {
      ret = LAGOPUS_RESULT_NO_MEMORY;
      TUNNEL_PERROR(ret);
      goto done;
    }
    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

done:
  return ret;
}

static inline void
spd6_free_spd_attr(struct spd6_attr **attr) {
  if (attr != NULL && *attr != NULL) {
    if ((*attr)->in != NULL) {
      rte_acl_free((*attr)->in);
      (*attr)->in= NULL;
    }

    if ((*attr)->out != NULL) {
      rte_acl_free((*attr)->out);
      (*attr)->in= NULL;
    }

    free(*attr);
    *attr = NULL;
  }
}

static inline void
spd6_free(struct spd6 **spd6) {
  if (*spd6 != NULL && spd6 != NULL) {
    spd6_free_spd_attr(&SPD_MODIFIED(*spd6));
    spd6_free_spd_attr(&SPD_CURRENT(*spd6));
  }
}

static inline lagopus_result_t
spd6_alloc(struct spd6 **spd6, uint32_t socketid) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (spd6 != NULL) {
    *spd6 = (struct spd6 *) calloc(1, sizeof(struct spd6));
    if (*spd6 == NULL) {
      ret = LAGOPUS_RESULT_NO_MEMORY;
      TUNNEL_PERROR(ret);
      goto done;
    }

    rte_atomic64_init(&(*spd6)->seq);

    if ((ret = spd6_alloc_spd_attr(socketid, &SPD_MODIFIED(*spd6))) !=
        LAGOPUS_RESULT_OK) {
      TUNNEL_PERROR(ret);
      goto done;
    }

    if ((ret = spd6_alloc_spd_attr(socketid, &SPD_CURRENT(*spd6))) !=
        LAGOPUS_RESULT_OK) {
      TUNNEL_PERROR(ret);
      goto done;
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

done:
  return ret;
}

static inline void
spd6_finalize_acl(struct spd6 *spd6) {
  if (spd6 != NULL) {
    spd6_free_spd_attr(&SPD_MODIFIED(spd6));
    spd6_free_spd_attr(&SPD_CURRENT(spd6));
  }
}

static inline void
spd6_finalize(struct spd6 **spd6) {
  spd6_finalize_acl(*spd6);
  spd6_free(spd6);
}

static inline lagopus_result_t
spd6_pre_process(struct spd6 *spd6) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(IS_VALID_SPD(spd6) == true)) {
    // switch.
    spd6->current = (uint64_t) rte_atomic64_read(&spd6->seq) % 2;
    // set referenced.
    rte_atomic16_inc(&SPD_CURRENT(spd6)->refs);
    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

static inline lagopus_result_t
spd6_post_process(struct spd6 *spd6) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(IS_VALID_SPD(spd6) == true)) {
    // unset referenced.
    rte_atomic16_dec(&SPD_CURRENT(spd6)->refs);
    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

static inline void
print_one_ip6_rule(int32_t i,
                   const struct acl6_rules *rule) {
  uint8_t a1, b1, c1, d1;
  uint8_t a2, b2, c2, d2;
  uint8_t a3, b3, c3, d3;
  uint8_t a4, b4, c4, d4;
  uint8_t a5, b5, c5, d5;
  uint8_t a6, b6, c6, d6;
  uint8_t a7, b7, c7, d7;
  uint8_t a8, b8, c8, d8;

  uint32_t_to_char(rule->field[SRC0_FIELD_IPV6].value.u32,
                   &a1, &b1, &c1, &d1);
  uint32_t_to_char(rule->field[SRC1_FIELD_IPV6].value.u32,
                   &a2, &b2, &c2, &d2);
  uint32_t_to_char(rule->field[SRC2_FIELD_IPV6].value.u32,
                   &a3, &b3, &c3, &d3);
  uint32_t_to_char(rule->field[SRC3_FIELD_IPV6].value.u32,
                   &a4, &b4, &c4, &d4);

  uint32_t_to_char(rule->field[DST0_FIELD_IPV6].value.u32,
                   &a5, &b5, &c5, &d5);
  uint32_t_to_char(rule->field[DST1_FIELD_IPV6].value.u32,
                   &a6, &b6, &c6, &d6);
  uint32_t_to_char(rule->field[DST2_FIELD_IPV6].value.u32,
                   &a7, &b7, &c7, &d7);
  uint32_t_to_char(rule->field[DST3_FIELD_IPV6].value.u32,
                   &a8, &b8, &c8, &d8);

  TUNNEL_DEBUG("%d:"
               "%.2x%.2x:%.2x%.2x"
               ":%.2x%.2x:%.2x%.2x"
               ":%.2x%.2x:%.2x%.2x"
               ":%.2x%.2x:%.2x%.2x/%u "
               "%.2x%.2x:%.2x%.2x"
               ":%.2x%.2x:%.2x%.2x"
               ":%.2x%.2x:%.2x%.2x"
               ":%.2x%.2x:%.2x%.2x/%u "
               "%hu : %hu %hu : %hu 0x%hhx/0x%hhx "
               "0x%x-0x%x-0x%x",
               i,
               a1, b1, c1, d1,
               a2, b2, c2, d2,
               a3, b3, c3, d3,
               a4, b4, c4, d4,
               rule->field[SRC0_FIELD_IPV6].mask_range.u32
               + rule->field[SRC1_FIELD_IPV6].mask_range.u32
               + rule->field[SRC2_FIELD_IPV6].mask_range.u32
               + rule->field[SRC3_FIELD_IPV6].mask_range.u32,
               a5, b5, c5, d5,
               a6, b6, c6, d6,
               a7, b7, c7, d7,
               a8, b8, c8, d8,
               rule->field[DST0_FIELD_IPV6].mask_range.u32
               + rule->field[DST1_FIELD_IPV6].mask_range.u32
               + rule->field[DST2_FIELD_IPV6].mask_range.u32
               + rule->field[DST3_FIELD_IPV6].mask_range.u32,
               rule->field[SRCP_FIELD_IPV6].value.u16,
               rule->field[SRCP_FIELD_IPV6].mask_range.u16,
               rule->field[DSTP_FIELD_IPV6].value.u16,
               rule->field[DSTP_FIELD_IPV6].mask_range.u16,
               rule->field[PROTO_FIELD_IPV6].value.u8,
               rule->field[PROTO_FIELD_IPV6].mask_range.u8,
               rule->data.category_mask,
               rule->data.priority,
               rule->data.userdata);
}

static inline void
spd6_dump_rules(const struct acl6_rules *rule,
                int32_t num) {
  int32_t i;

  if (rule != NULL) {
    TUNNEL_DEBUG("dump ip6 rules :");
    for (i = 0; i < num; i++, rule++) {
      print_one_ip6_rule(i, rule);
    }
  }
}

static inline lagopus_result_t
spd6_add_acl_rules(struct rte_acl_ctx *ctx, const struct acl6_rules *rules,
                   uint32_t rules_nb) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  int r = -1;

  if (ctx!= NULL && rules != NULL) {
    if ((r = rte_acl_add_rules(ctx, (const struct rte_acl_rule *)rules,
                               rules_nb)) == 0) {
      ret = LAGOPUS_RESULT_OK;
    } else {
      if (r == -ENOMEM) {
        ret = LAGOPUS_RESULT_NO_MEMORY;
      } else if (r == -EINVAL) {
        ret = LAGOPUS_RESULT_INVALID_ARGS;
      } else {
        ret = LAGOPUS_RESULT_ANY_FAILURES;
      }
      TUNNEL_PERROR(ret);
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

static inline lagopus_result_t
spd6_build_acl(struct rte_acl_ctx *ctx) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  int r = -1;
  struct rte_acl_config acl_build_param;

  if (ctx!= NULL) {
    /* Perform builds */
    memset(&acl_build_param, 0, sizeof(acl_build_param));

    acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
    acl_build_param.num_fields = RTE_DIM(ip6_defs);
    memcpy(&acl_build_param.defs, ip6_defs, sizeof(ip6_defs));

    if ((r = rte_acl_build(ctx, &acl_build_param)) != 0) {
      if (r == -ENOMEM) {
        ret = LAGOPUS_RESULT_NO_MEMORY;
      } else if (r == -EINVAL) {
        ret = LAGOPUS_RESULT_INVALID_ARGS;
      } else {
        ret = LAGOPUS_RESULT_ANY_FAILURES;
      }
      TUNNEL_PERROR(ret);
      goto done;
    }

    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

done:
  return ret;
}

static inline lagopus_result_t
spd6_classify_spd(const struct rte_acl_ctx *ctx,
                  const uint8_t **data,
                  uint32_t *results,
                  uint32_t num) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  int r = -1;

  if (likely(ctx != NULL && data != NULL && results != NULL)) {
    if (likely((r = rte_acl_classify(ctx, data, results,
                                     num, DEFAULT_MAX_CATEGORIES)) == 0)) {
      ret = LAGOPUS_RESULT_OK;
    } else {
      ret = LAGOPUS_RESULT_INVALID_ARGS;
      TUNNEL_PERROR(ret);
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

// public.

struct acl6_rules *
sp6_alloc_rules(size_t size) {
  return (struct acl6_rules *) calloc(size, sizeof(struct acl6_rules));
}

void
sp6_free_rules(struct acl6_rules *rules) {
  free(rules);
}

lagopus_result_t
sp6_set_rule(size_t index,
             struct acl6_rules *rules,
             const struct acl6_params *params) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct acl6_rules *rule;
  uint32_t depth;

  if (rules != NULL && params != NULL) {
    rule = &rules[index];
    rule->data.category_mask = 1;

    switch (params->policy) {
      case IPSEC_POLICY_IPSEC:
        // protect
        rule->data.userdata =
          PROTECT(params->spi);
        break;
      case IPSEC_POLICY_BYPASS:
        // bypass
        rule->data.userdata = BYPASS;
        break;
      case IPSEC_POLICY_DISCARD:
        // discard
        rule->data.userdata = DISCARD;
        break;
      default:
        ret = LAGOPUS_RESULT_INVALID_ARGS;
        TUNNEL_PERROR(ret);
        goto done;
    }

    // sp entry id.
    rule->data.userdata |= SP_ENTRY_ID(params->entry_id);

    // priority
    rule->data.priority = params->priority;

    // proto
    rule->field[0].value.u8 = params->proto;
    rule->field[0].mask_range.u8 = params->proto_mask;

    // src
    depth = params->src_ip_mask;
    rule->field[1].value.u32 =
      (uint32_t)params->src_ip[0] << 24 |
      (uint32_t)params->src_ip[1] << 16 |
      (uint32_t)params->src_ip[2] << 8 |
      (uint32_t)params->src_ip[3];
    rule->field[1].mask_range.u32 =
      (depth > 32) ? 32 : depth;
    depth = (depth > 32) ? (depth - 32) : 0;
    rule->field[2].value.u32 =
      (uint32_t)params->src_ip[4] << 24 |
      (uint32_t)params->src_ip[5] << 16 |
      (uint32_t)params->src_ip[6] << 8 |
      (uint32_t)params->src_ip[7];
    rule->field[2].mask_range.u32 =
      (depth > 32) ? 32 : depth;
    depth = (depth > 32) ? (depth - 32) : 0;
    rule->field[3].value.u32 =
      (uint32_t)params->src_ip[8] << 24 |
      (uint32_t)params->src_ip[9] << 16 |
      (uint32_t)params->src_ip[10] << 8 |
      (uint32_t)params->src_ip[11];
    rule->field[3].mask_range.u32 =
      (depth > 32) ? 32 : depth;
    depth = (depth > 32) ? (depth - 32) : 0;
    rule->field[4].value.u32 =
      (uint32_t)params->src_ip[12] << 24 |
      (uint32_t)params->src_ip[13] << 16 |
      (uint32_t)params->src_ip[14] << 8 |
      (uint32_t)params->src_ip[15];
    rule->field[4].mask_range.u32 =
      (depth > 32) ? 32 : depth;

    // dst
    depth = params->dst_ip_mask;
    rule->field[5].value.u32 =
      (uint32_t)params->dst_ip[0] << 24 |
      (uint32_t)params->dst_ip[1] << 16 |
      (uint32_t)params->dst_ip[2] << 8 |
      (uint32_t)params->dst_ip[3];
    rule->field[5].mask_range.u32 =
      (depth > 32) ? 32 : depth;
    depth = (depth > 32) ? (depth - 32) : 0;
    rule->field[6].value.u32 =
      (uint32_t)params->dst_ip[4] << 24 |
      (uint32_t)params->dst_ip[5] << 16 |
      (uint32_t)params->dst_ip[6] << 8 |
      (uint32_t)params->dst_ip[7];
    rule->field[6].mask_range.u32 =
      (depth > 32) ? 32 : depth;
    depth = (depth > 32) ? (depth - 32) : 0;
    rule->field[7].value.u32 =
      (uint32_t)params->dst_ip[8] << 24 |
      (uint32_t)params->dst_ip[9] << 16 |
      (uint32_t)params->dst_ip[10] << 8 |
      (uint32_t)params->dst_ip[11];
    rule->field[7].mask_range.u32 =
      (depth > 32) ? 32 : depth;
    depth = (depth > 32) ? (depth - 32) : 0;
    rule->field[8].value.u32 =
      (uint32_t)params->dst_ip[12] << 24 |
      (uint32_t)params->dst_ip[13] << 16 |
      (uint32_t)params->dst_ip[14] << 8 |
      (uint32_t)params->dst_ip[15];
    rule->field[8].mask_range.u32 =
      (depth > 32) ? 32 : depth;

    // sport
    rule->field[9].value.u16 = params->src_port;
    rule->field[9].mask_range.u16 = params->src_port_mask;

    // dport
    rule->field[10].value.u16 = params->dst_port;
    rule->field[10].mask_range.u16 = params->dst_port_mask;

    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

done:
  return ret;
}

void
sp6_dump_rules(const struct acl6_rules *rule,
               int32_t num) {
  if (rule != NULL && num != 0) {
    spd6_dump_rules(rule, num);
  }
}

lagopus_result_t
sp6_pre_process(struct spd6 *spd6) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (IS_VALID_SPD(spd6) == true) {
    ret = spd6_pre_process(spd6);
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

lagopus_result_t
sp6_post_process(struct spd6 *spd6) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (IS_VALID_SPD(spd6) == true) {
    ret = spd6_post_process(spd6);
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

lagopus_result_t
sp6_make_spd(struct spd6 *spd6,
             const struct acl6_rules *in_rules,
             uint32_t in_rules_nb,
             const struct acl6_rules *out_rules,
             uint32_t out_rules_nb) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  uint64_t next_modified;
  struct acl6_rules reserved_rules = {0};
  struct rte_acl_ctx *in;
  struct rte_acl_ctx *out;

  if (IS_VALID_SPD(spd6) == true) {
    next_modified = (uint64_t) (rte_atomic64_read(&spd6->seq) + 1) % 2;
    if (rte_atomic16_read(&SPD_GET_DB(spd6, next_modified)->refs) == 0) {
      in = SPD_GET_DB(spd6, next_modified)->in;
      out = SPD_GET_DB(spd6, next_modified)->out;

      /* clear ACL. */
      rte_acl_reset_rules(in);
      rte_acl_reset_rules(out);

      /* add reserved rules. */
      /*
       * NOTE: rte_acl_classify() requires one or more rules.
       * (Segmentation fault occurs)
       */
      reserved_rules.data.userdata = RESERVED;
      reserved_rules.data.category_mask = 1;
      reserved_rules.data.priority = RTE_ACL_MIN_PRIORITY;
      if ((ret = spd6_add_acl_rules(in, &reserved_rules, 1)) !=
          LAGOPUS_RESULT_OK) {
        TUNNEL_PERROR(ret);
        goto done;
      }
      if ((ret = spd6_add_acl_rules(out, &reserved_rules, 1)) !=
          LAGOPUS_RESULT_OK) {
        TUNNEL_PERROR(ret);
        goto done;
      }

      /* dump rules (reserved). */
      /* for debug. */
      // sp6_dump_rules(&reserved_rules, (int32_t) 1);

      /* add dynamic rules. */
      if (in_rules != NULL && in_rules_nb != 0) {
        if ((ret = spd6_add_acl_rules(in, in_rules, in_rules_nb)) !=
            LAGOPUS_RESULT_OK) {
          TUNNEL_PERROR(ret);
          goto done;
        }
      }
      if (out_rules != NULL && out_rules_nb != 0) {
        if ((ret = spd6_add_acl_rules(out, out_rules, out_rules_nb)) !=
            LAGOPUS_RESULT_OK) {
          TUNNEL_PERROR(ret);
          goto done;
        }
      }

      /* build ACL. */
      if ((ret = spd6_build_acl(in)) !=
          LAGOPUS_RESULT_OK) {
        TUNNEL_PERROR(ret);
        goto done;
      }
      if ((ret = spd6_build_acl(out)) !=
          LAGOPUS_RESULT_OK) {
        TUNNEL_PERROR(ret);
        goto done;
      }

      rte_atomic64_inc(&spd6->seq);

      if (in_rules != NULL) {
        /* dump rules (dynamic). */
        sp6_dump_rules(in_rules, (int32_t) in_rules_nb);
        /* dump acls. */
        TUNNEL_INFO("sp6 in(modified) :");
        rte_acl_dump(in);
      }
      if (out_rules != NULL) {
        /* dump rules (dynamic). */
        sp6_dump_rules(out_rules, (int32_t) out_rules_nb);
        /* dump acls. */
        TUNNEL_INFO("sp6 out(modified) :");
        rte_acl_dump(out);
      }
    } else {
      ret = LAGOPUS_RESULT_OK;
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

done:
  return ret;
}

lagopus_result_t
sp6_classify_spd_in(void *spd,
                    const uint8_t **data,
                    uint32_t *results,
                    uint32_t num) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct spd6 *spd6 = (struct spd6 *) spd;

  TUNNEL_DEBUG("call sp6_classify_spd_in.");

  if (likely(IS_VALID_SPD(spd6) == true && data != NULL && *data != NULL &&
             results != NULL && num != 0)) {
    if (unlikely((ret = spd6_classify_spd(
                          SPD_CURRENT(spd6)->in, data,
                          results, num)) != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

lagopus_result_t
sp6_classify_spd_out(void *spd,
                     const uint8_t **data,
                     uint32_t *results,
                     uint32_t num) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct spd6 *spd6 = (struct spd6 *) spd;

  TUNNEL_DEBUG("call sp6_classify_spd_out.");

  if (likely(IS_VALID_SPD(spd6) == true && data != NULL && *data != NULL &&
             results != NULL && num != 0)) {
    if (unlikely((ret = spd6_classify_spd(
                          SPD_CURRENT(spd6)->out, data,
                          results, num)) != LAGOPUS_RESULT_OK)) {
      TUNNEL_PERROR(ret);
    }
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

lagopus_result_t
sp6_set_lifetime_current(void *spd,
                         uint32_t sa_index,
                         lagopus_chrono_t now) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct spd6 *spd6 = (struct spd6 *) spd;

  if (spd6 != NULL && spd6->stats != NULL &&
      sa_index < IPSEC_SP_MAX_ENTRIES) {
    spd6->stats[sa_index].lifetime_current = (int64_t) now;
    mbar();
    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

lagopus_result_t
sp6_get_stats(struct spd6 *spd6,
              struct spd_stats *stats,
              uint32_t spi) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (spd6->stats != NULL && stats != NULL) {
    *stats = spd6->stats[SPI2IDX(spi)];
    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

lagopus_result_t
sp6_get_stats_array(struct spd6 *spd6,
                    struct spd_stats **stats) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (spd6->stats != NULL && stats != NULL) {
    *stats = spd6->stats;
    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}


lagopus_result_t
sp6_initialize(struct spd6 **spd6,
               uint32_t socket_id) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (spd6 != NULL) {
    rte_srand(rte_rdtsc());

    if ((ret = spd6_alloc(spd6, socket_id)) != LAGOPUS_RESULT_OK) {
      TUNNEL_PERROR(ret);
      spd6_finalize(spd6);
      return ret;
    }

    /* add/build reserved rules. */
    if ((ret = sp6_make_spd(*spd6, NULL, 0, NULL, 0))
        != LAGOPUS_RESULT_OK) {
      TUNNEL_PERROR(ret);
      spd6_finalize(spd6);
      return ret;
    }
  }

  return LAGOPUS_RESULT_OK;
}

void
sp6_finalize(struct spd6 **spd6) {
  spd6_finalize(spd6);
}
