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

/*
 * Go runtime gets current time from clock_gettime() with CLOCK_REALTIME.
 * In order to sort the log messages generated in C and Go in proper order,
 * we should collect the curret time in C, and pass along with messages
 * to Go. Go then log messages.
 *
 * The order of messages appear in log may in the order of time. However,
 * they can be later sorted with timestamps in the messages if needed.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "_cgo_export.h"
#include "logger_internal.h"

vsw_enable_debug_t vsw_enable_debug = 0;
static bool verbose = false;
static uint8_t debug_level[VSW_LOGGER_MAX_MODULES];
static vsw_log_level_t log_level;

// Private for logger
void vsw_log_debug_all() {
	vsw_enable_debug = ~0;
}

void vsw_log_debug_none() {
	vsw_enable_debug = 0;
}

void vsw_log_debug_enable(int id) {
	vsw_enable_debug |= 1 << id;
}

void vsw_log_debug_disable(int id) {
	vsw_enable_debug &= ~(1 << id);
}

void vsw_log_verbose(bool enabled) {
	verbose = enabled;
}

void vsw_log_set_level(vsw_log_level_t l) {
	log_level = l;
}

void vsw_log_set_debug_level(uint32_t id, uint8_t l) {
	// ID is in between 0 and VSW_LOGGER_MAX_MODULES-1
	if (id >= VSW_LOGGER_MAX_MODULES)
		return;
	debug_level[id] = l;
}

//  Public API
int vsw_log_getid(const char *name) {
	// We're not going to modify name in Go.
	// Unfortunately, cgo doesn't support const.
	return LoggerGetID((char *)name);
}

static inline void vsw_log_output(vsw_log_level_t type, uint32_t id,
				      const char *file, int line, const char *func,
				      const char *fmt, va_list ap) {
	char body[VSW_LOGGER_MAX_LEN];
	struct logger_message msg = { .id = (int)id, .body = body, .lt = type };
	int len = 0;

	// Get current time as soon as possible
	clock_gettime(CLOCK_REALTIME, &msg.ts);

	if (verbose)
		len = snprintf(body, sizeof(body), "%s:%d: ", file, line);

	vsnprintf(body + len, sizeof(body) - len, fmt, ap);

	LoggerOutput(&msg);
}

void vsw_log_debug(uint32_t id, uint8_t level,
		       const char *file, int line, const char *func,
		       const char *fmt, ...) {
	_Static_assert((sizeof(vsw_enable_debug_t) * 8) >= VSW_LOGGER_MAX_MODULES,
			"VSW_LOGGER_MAX_MODULES is too big.");

	va_list ap;

	// ID shall be in between 0 and VSW_LOGGER_MAX_MODULES-1, and debugging shall be enabled.
	if ((id >= VSW_LOGGER_MAX_MODULES) || !(vsw_enable_debug & (1 << id)))
		return;

	// Check debug level
	if (level > debug_level[id & 0x3f])
		return;

	va_start(ap, fmt);
	vsw_log_output(VSW_LOG_LEVEL_DEBUG, id, file, line, func, fmt, ap);
	va_end(ap);
}

void vsw_log_msg(vsw_log_level_t type, uint32_t id,
		      const char *file, int line, const char *func,
		      const char *fmt, ...) {
	va_list ap;

	// ID shall be in between 0 and VSW_LOGGER_MAX_MODULES-1
	if (id >= VSW_LOGGER_MAX_MODULES)
		return;

	// Type shall be at least the given log level.
	if (log_level < type)
		return;

	va_start(ap, fmt);
	vsw_log_output(type, id, file, line, func, fmt, ap);
	va_end(ap);
}

// DEPRECATED: For backward compatibility only.
void vsw_printf(const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	vsw_log_output(VSW_LOG_LEVEL_INFO, 0, "", 0, "", fmt, ap);
	va_end(ap);
}

// DEPRECATED: For backward compatibility only.
void vsw_fatalf(const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	vsw_log_output(VSW_LOG_LEVEL_FATAL, 0, "", 0, "", fmt, ap);
	va_end(ap);
}
