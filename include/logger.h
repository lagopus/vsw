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
 * If you're using this API from C code compiled with cgo, make sure that
 * you add the following definition in #cgo directive:
 *
 * 	#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all
 *
 * If you see undefined symbol errors, then this may be the cause.
 */

#ifndef VSW_LOGGER_H_
#define VSW_LOGGER_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VSW_LOGGER_MAX_MODULES 64
#define VSW_LOGGER_MAX_LEN     256 // Maximum length per line (VSW_LOGGER_MAX_LEN - 1)

typedef uint64_t vsw_enable_debug_t;

typedef enum {
	VSW_LOG_LEVEL_FATAL,
	VSW_LOG_LEVEL_ERROR,
	VSW_LOG_LEVEL_WARNING,
	VSW_LOG_LEVEL_INFO,
	VSW_LOG_LEVEL_DEBUG,
} vsw_log_level_t;

extern void vsw_printf(const char *format, ...);
extern void vsw_fatalf(const char *format, ...);

extern int vsw_log_getid(const char *name);
extern void vsw_log_debug(uint32_t, uint8_t, const char*, int, const char*, const char*, ...);
extern void vsw_log_msg(vsw_log_level_t, uint32_t, const char*, int, const char*, const char*, ...);

extern vsw_enable_debug_t vsw_enable_debug;

#ifdef DEBUG
#	define VSW_DEBUG(s, x...)	{ vsw_printf(s, ## x); }
#else
#	define VSW_DEBUG(s, x...)	{ }
#endif

#define VSW_LOG_DEBUG_ENABLED(id)	(!!(vsw_enable_debug & (1 << (id % VSW_LOGGER_MAX_MODULES))))

/**
 * Log a debug message.
 *
 *      @param[in]      level   A debug level (uint8_t).
 */
#define vsw_msg_debug(id, level, fmt, x...)									  \
	{													  \
		if (VSW_LOG_DEBUG_ENABLED(id))									  \
			vsw_log_debug((uint32_t)(id), (uint8_t)(level), __FILE__, __LINE__, __func__, fmt, ## x); \
	}


/**
 * Log an informative message.
 */
#define vsw_msg_info(id, fmt, x...) \
	vsw_log_msg(VSW_LOG_LEVEL_INFO, (uint32_t)(id), __FILE__, __LINE__, __func__, fmt, ## x)

/**
 * Log a warning message.
 */
#define vsw_msg_warning(id, fmt, x...) \
	vsw_log_msg(VSW_LOG_LEVEL_WARNING, (uint32_t)(id), __FILE__, __LINE__, __func__, fmt, ## x)

/**
 * Log an error message.
 */
#define vsw_msg_error(id, fmt, x...) \
	vsw_log_msg(VSW_LOG_LEVEL_ERROR, (uint32_t)(id), __FILE__, __LINE__, __func__, fmt, ## x)

/**
 * Log a fatal message.
 */
#define vsw_msg_fatal(id, fmt, x...) \
	vsw_log_msg(VSW_LOG_LEVEL_FATAL, (uint32_t)(id), __FILE__, __LINE__, __func__, fmt, ## x)

#ifdef __cplusplus
}
#endif

#endif // VSW_LOGGER_H_
