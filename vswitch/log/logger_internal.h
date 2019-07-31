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

#ifndef LOGGER_INTERNAL_H_
#define LOGGER_INTERNAL_H_

#include <time.h>
#include "../../include/logger.h"

typedef enum {
	t_fatal   = VSW_LOG_LEVEL_FATAL,
	t_err     = VSW_LOG_LEVEL_ERROR,
	t_warning = VSW_LOG_LEVEL_WARNING,
	t_info    = VSW_LOG_LEVEL_INFO,
	t_debug   = VSW_LOG_LEVEL_DEBUG,
} log_t;

struct logger_message {
	struct timespec ts;
	int id;
	log_t lt;
	const char *body;
};

#endif /* !LOGGER_INTERNAL_H_ */
