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

#ifndef SP_H
#define SP_H

#define SPD_GET_DB(spd, index) ((spd)->db[(index)])
#define SPD_CURRENT(spd) (SPD_GET_DB((spd), (spd)->current))
#define SPD_MODIFIED(spd) (SPD_GET_DB((spd), ((spd)->current + 1) % 2))
#define IS_VALID_SPD(spd) (((spd) != NULL &&             \
                            (spd)->db[0] != NULL &&      \
                            (spd)->db[0]->out != NULL && \
                            (spd)->db[0]->in != NULL &&  \
                            (spd)->db[1] != NULL &&      \
                            (spd)->db[1]->out != NULL && \
                            (spd)->db[1]->in != NULL) ? true : false)

#define IPSEC_SP_MAX_ENTRIES IPSEC_SA_MAX_ENTRIES

#define MAX_ACL_RULE_NUM (1024)

typedef lagopus_result_t (*sp_classify_spd_proc_t)(void *spd,
    const uint8_t **data,
    uint32_t *results,
    uint32_t num);

typedef lagopus_result_t (*sp_set_lifetime_current_proc_t)(void *spd,
    uint32_t sa_index,
    lagopus_chrono_t now);

struct spd_stats {
  int64_t lifetime_current;
};

#endif /* SP_H */
