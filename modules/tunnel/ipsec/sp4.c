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
#include <netinet/ip.h>
#include <linux/ipsec.h>

#include <rte_acl.h>
#include <rte_ip.h>
#include <rte_random.h>
#include <rte_cycles.h>
#include <rte_atomic.h>

#include "lagopus_apis.h"
#include "ipsec.h"
#include "sp4.h"

struct rte_acl_field_def ip4_defs[NUM_FIELDS_IPV4] = {
  {
    .type = RTE_ACL_FIELD_TYPE_BITMASK,
    .size = sizeof(uint8_t),
    .field_index = PROTO_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4_PROTO,
    .offset = 0,
  },
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = SRC_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4_SRC,
    .offset = offsetof(struct ip, ip_src) - offsetof(struct ip, ip_p)
  },
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = DST_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4_DST,
    .offset = offsetof(struct ip, ip_dst) - offsetof(struct ip, ip_p)
  },
  {
    .type = RTE_ACL_FIELD_TYPE_RANGE,
    .size = sizeof(uint16_t),
    .field_index = SRCP_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4_PORTS,
    .offset = sizeof(struct ip) - offsetof(struct ip, ip_p)
  },
  {
    .type = RTE_ACL_FIELD_TYPE_RANGE,
    .size = sizeof(uint16_t),
    .field_index = DSTP_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4_PORTS,
    .offset = sizeof(struct ip) - offsetof(struct ip, ip_p) +
    sizeof(uint16_t)
  },
};

struct spd4_attr {
  struct rte_acl_ctx *in;
  struct rte_acl_ctx *out;
  rte_atomic16_t refs;
};

struct spd4 {
  struct spd4_attr *db[2];
  struct spd_stats stats[IPSEC_SP_MAX_ENTRIES];
  rte_atomic64_t seq;
  uint64_t current;
};

static inline struct rte_acl_ctx *
spd4_alloc_acl_ctx(const char *name, uint32_t socketid) {
  struct rte_acl_param acl_param;
  char s[PATH_MAX];

  memset(&acl_param, 0, sizeof(acl_param));

  /* Create ACL contexts */
  snprintf(s, sizeof(s), "%s_%d_%"PRIu64, name, socketid, rte_rand());

  acl_param.name = s;
  acl_param.socket_id = (int) socketid;
  acl_param.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ip4_defs));
  acl_param.max_rule_num = MAX_ACL_RULE_NUM;

  return rte_acl_create(&acl_param);
}

static inline lagopus_result_t
spd4_alloc_spd_attr(uint32_t socketid,
                    struct spd4_attr **attr) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  const char *name;

  if (attr != NULL) {
    *attr = (struct spd4_attr *) calloc(1, sizeof(struct spd4_attr));
    if (*attr == NULL) {
      ret = LAGOPUS_RESULT_NO_MEMORY;
      TUNNEL_PERROR(ret);
      goto done;
    }

    rte_atomic16_init(&(*attr)->refs);

    name = "sp_ip4_in";
    (*attr)->in = spd4_alloc_acl_ctx(name, socketid);
    if ((*attr)->in == NULL) {
      ret = LAGOPUS_RESULT_NO_MEMORY;
      TUNNEL_PERROR(ret);
      goto done;
    }

    name = "sp_ip4_out";
    (*attr)->out = spd4_alloc_acl_ctx(name, socketid);
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
spd4_free_spd_attr(struct spd4_attr **attr) {
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
spd4_free(struct spd4 **spd4) {
  if (*spd4 != NULL && spd4 != NULL) {
    spd4_free_spd_attr(&SPD_MODIFIED(*spd4));
    spd4_free_spd_attr(&SPD_CURRENT(*spd4));
  }
}

static inline lagopus_result_t
spd4_alloc(struct spd4 **spd4, uint32_t socketid) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (spd4 != NULL) {
    *spd4 = (struct spd4 *) calloc(1, sizeof(struct spd4));
    if (*spd4 == NULL) {
      ret = LAGOPUS_RESULT_NO_MEMORY;
      TUNNEL_PERROR(ret);
      goto done;
    }

    rte_atomic64_init(&(*spd4)->seq);

    if ((ret = spd4_alloc_spd_attr(socketid, &SPD_MODIFIED(*spd4))) !=
        LAGOPUS_RESULT_OK) {
      TUNNEL_PERROR(ret);
      goto done;
    }

    if ((ret = spd4_alloc_spd_attr(socketid, &SPD_CURRENT(*spd4))) !=
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
spd4_finalize_acl(struct spd4 *spd4) {
  if (spd4 != NULL) {
    spd4_free_spd_attr(&SPD_MODIFIED(spd4));
    spd4_free_spd_attr(&SPD_CURRENT(spd4));
  }
}

static inline void
spd4_finalize(struct spd4 **spd4) {
  spd4_finalize_acl(*spd4);
  spd4_free(spd4);
}

static inline lagopus_result_t
spd4_pre_process(struct spd4 *spd4) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(IS_VALID_SPD(spd4) == true)) {
    // switch.
    spd4->current = (uint64_t) rte_atomic64_read(&spd4->seq) % 2;
    // set referenced.
    rte_atomic16_inc(&SPD_CURRENT(spd4)->refs);
    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

static inline lagopus_result_t
spd4_post_process(struct spd4 *spd4) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (likely(IS_VALID_SPD(spd4) == true)) {
    // unset referenced.
    rte_atomic16_dec(&SPD_CURRENT(spd4)->refs);
    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

static inline void
print_one_ip4_rule(int32_t i,
                   const struct acl4_rules *rule) {
  uint8_t a1, b1, c1, d1;
  uint8_t a2, b2, c2, d2;

  uint32_t_to_char(rule->field[SRC_FIELD_IPV4].value.u32,
                   &a1, &b1, &c1, &d1);
  uint32_t_to_char(rule->field[DST_FIELD_IPV4].value.u32,
                   &a2, &b2, &c2, &d2);

  TUNNEL_DEBUG("%d:"
               "%hhu.%hhu.%hhu.%hhu/%u "
               "%hhu.%hhu.%hhu.%hhu/%u "
               "%hu : %hu %hu : %hu 0x%hhx/0x%hhx "
               "0x%x-0x%x-0x%x",
               i,
               a1, b1, c1, d1,
               rule->field[SRC_FIELD_IPV4].mask_range.u32,
               a2, b2, c2, d2,
               rule->field[DST_FIELD_IPV4].mask_range.u32,
               rule->field[SRCP_FIELD_IPV4].value.u16,
               rule->field[SRCP_FIELD_IPV4].mask_range.u16,
               rule->field[DSTP_FIELD_IPV4].value.u16,
               rule->field[DSTP_FIELD_IPV4].mask_range.u16,
               rule->field[PROTO_FIELD_IPV4].value.u8,
               rule->field[PROTO_FIELD_IPV4].mask_range.u8,
               rule->data.category_mask,
               rule->data.priority,
               rule->data.userdata);
}

static inline void
spd4_dump_rules(const struct acl4_rules *rule,
                int32_t num) {
  int32_t i;

  if (rule != NULL) {
    TUNNEL_DEBUG("dump ip4 rules :");
    for (i = 0; i < num; i++, rule++) {
      print_one_ip4_rule(i, rule);
    }
  }
}

static inline lagopus_result_t
spd4_add_acl_rules(struct rte_acl_ctx *ctx, const struct acl4_rules *rules,
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
spd4_build_acl(struct rte_acl_ctx *ctx) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  int r = -1;
  struct rte_acl_config acl_build_param;

  if (ctx!= NULL) {
    /* Perform builds */
    memset(&acl_build_param, 0, sizeof(acl_build_param));

    acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
    acl_build_param.num_fields = RTE_DIM(ip4_defs);
    memcpy(&acl_build_param.defs, ip4_defs, sizeof(ip4_defs));

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
spd4_classify_spd(const struct rte_acl_ctx *ctx,
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

struct acl4_rules *
sp4_alloc_rules(size_t size) {
  return (struct acl4_rules *) calloc(size, sizeof(struct acl4_rules));
}

void
sp4_free_rules(struct acl4_rules *rules) {
  free(rules);
}

lagopus_result_t
sp4_set_rule(size_t index,
             struct acl4_rules *rules,
             const struct acl4_params *params) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct acl4_rules *rule;

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
    rule->field[1].value.u32 = rte_bswap32(params->src_ip);
    rule->field[1].mask_range.u32 = params->src_ip_mask;

    // dst
    rule->field[2].value.u32 = rte_bswap32(params->dst_ip);
    rule->field[2].mask_range.u32 = params->dst_ip_mask;

    // sport
    rule->field[3].value.u16 = params->src_port;
    rule->field[3].mask_range.u16 = params->src_port_mask;

    // dport
    rule->field[4].value.u16 = params->dst_port;
    rule->field[4].mask_range.u16 = params->dst_port_mask;

    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

done:
  return ret;
}

void
sp4_dump_rules(const struct acl4_rules *rule,
               int32_t num) {
  if (rule != NULL && num != 0) {
    spd4_dump_rules(rule, num);
  }
}

lagopus_result_t
sp4_pre_process(struct spd4 *spd4) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (IS_VALID_SPD(spd4) == true) {
    ret = spd4_pre_process(spd4);
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

lagopus_result_t
sp4_post_process(struct spd4 *spd4) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (IS_VALID_SPD(spd4) == true) {
    ret = spd4_post_process(spd4);
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

lagopus_result_t
sp4_make_spd(struct spd4 *spd4,
             const struct acl4_rules *in_rules,
             uint32_t in_rules_nb,
             const struct acl4_rules *out_rules,
             uint32_t out_rules_nb) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  uint64_t next_modified;
  struct acl4_rules reserved_rules = {0};
  struct rte_acl_ctx *in;
  struct rte_acl_ctx *out;

  if (IS_VALID_SPD(spd4) == true) {
    next_modified = (uint64_t) (rte_atomic64_read(&spd4->seq) + 1) % 2;
    if (rte_atomic16_read(&SPD_GET_DB(spd4, next_modified)->refs) == 0) {
      in = SPD_GET_DB(spd4, next_modified)->in;
      out = SPD_GET_DB(spd4, next_modified)->out;

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
      if ((ret = spd4_add_acl_rules(in, &reserved_rules, 1)) !=
          LAGOPUS_RESULT_OK) {
        TUNNEL_PERROR(ret);
        goto done;
      }
      if ((ret = spd4_add_acl_rules(out, &reserved_rules, 1)) !=
          LAGOPUS_RESULT_OK) {
        TUNNEL_PERROR(ret);
        goto done;
      }

      /* dump rules (reserved). */
      /* for debug. */
      // sp4_dump_rules(&reserved_rules, (int32_t) 1);

      /* add dynamic rules. */
      if (in_rules != NULL && in_rules_nb != 0) {
        if ((ret = spd4_add_acl_rules(in, in_rules, in_rules_nb)) !=
            LAGOPUS_RESULT_OK) {
          TUNNEL_PERROR(ret);
          goto done;
        }
      }
      if (out_rules != NULL && out_rules_nb != 0) {
        if ((ret = spd4_add_acl_rules(out, out_rules, out_rules_nb)) !=
            LAGOPUS_RESULT_OK) {
          TUNNEL_PERROR(ret);
          goto done;
        }
      }

      /* build ACL. */
      if ((ret = spd4_build_acl(in)) !=
          LAGOPUS_RESULT_OK) {
        TUNNEL_PERROR(ret);
        goto done;
      }
      if ((ret = spd4_build_acl(out)) !=
          LAGOPUS_RESULT_OK) {
        TUNNEL_PERROR(ret);
        goto done;
      }

      rte_atomic64_inc(&spd4->seq);

      if (in_rules != NULL) {
        /* dump rules (dynamic). */
        sp4_dump_rules(in_rules, (int32_t) in_rules_nb);
        /* dump acls. */
        TUNNEL_INFO("sp4 in(modified) :");
        rte_acl_dump(in);
      }
      if (out_rules != NULL) {
        /* dump rules (dynamic). */
        sp4_dump_rules(out_rules, (int32_t) out_rules_nb);
        /* dump acls. */
        TUNNEL_INFO("sp4 out(modified) :");
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
sp4_classify_spd_in(void *spd,
                    const uint8_t **data,
                    uint32_t *results,
                    uint32_t num) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct spd4 *spd4 = (struct spd4 *) spd;

  TUNNEL_DEBUG("call sp4_classify_spd_in.");

  if (likely(IS_VALID_SPD(spd4) == true && data != NULL && *data != NULL &&
             results != NULL && num != 0)) {
    if (unlikely((ret = spd4_classify_spd(
                          SPD_CURRENT(spd4)->in, data,
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
sp4_classify_spd_out(void *spd,
                     const uint8_t **data,
                     uint32_t *results,
                     uint32_t num) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct spd4 *spd4 = (struct spd4 *) spd;

  TUNNEL_DEBUG("call sp4_classify_spd_out.");

  if (likely(IS_VALID_SPD(spd4) == true && data != NULL && *data != NULL &&
             results != NULL && num != 0)) {
    if (unlikely((ret = spd4_classify_spd(
                          SPD_CURRENT(spd4)->out, data,
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
sp4_set_lifetime_current(void *spd,
                         uint32_t sa_index,
                         lagopus_chrono_t now) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;
  struct spd4 *spd4 = (struct spd4 *) spd;

  if (spd4 != NULL && spd4->stats != NULL &&
      sa_index < IPSEC_SP_MAX_ENTRIES) {
    spd4->stats[sa_index].lifetime_current = (int64_t) now;
    mbar();
    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

lagopus_result_t
sp4_get_stats(struct spd4 *spd4,
              struct spd_stats *stats,
              uint32_t spi) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (spd4->stats != NULL && stats != NULL) {
    *stats = spd4->stats[SPI2IDX(spi)];
    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

lagopus_result_t
sp4_get_stats_array(struct spd4 *spd4,
                    struct spd_stats **stats) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (spd4->stats != NULL && stats != NULL) {
    *stats = spd4->stats;
    ret = LAGOPUS_RESULT_OK;
  } else {
    ret = LAGOPUS_RESULT_INVALID_ARGS;
    TUNNEL_PERROR(ret);
  }

  return ret;
}

lagopus_result_t
sp4_initialize(struct spd4 **spd4,
               uint32_t socket_id) {
  lagopus_result_t ret = LAGOPUS_RESULT_ANY_FAILURES;

  if (spd4 != NULL) {
    rte_srand(rte_rdtsc());

    if ((ret = spd4_alloc(spd4, socket_id)) != LAGOPUS_RESULT_OK) {
      TUNNEL_PERROR(ret);
      spd4_finalize(spd4);
      return ret;
    }

    /* add/build reserved rules. */
    if ((ret = sp4_make_spd(*spd4, NULL, 0, NULL, 0))
        != LAGOPUS_RESULT_OK) {
      TUNNEL_PERROR(ret);
      spd4_finalize(spd4);
      return ret;
    }
  }

  return LAGOPUS_RESULT_OK;
}

void
sp4_finalize(struct spd4 **spd4) {
  spd4_finalize(spd4);
}
