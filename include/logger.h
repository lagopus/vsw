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

/*
 * If you're using this API from C code compiled with cgo, make sure that
 * you add the following definition in #cgo directive:
 *
 * 	#cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-all
 *
 * If you see undefined symbol errors, then this may be the cause.
 */

#ifndef LAGOPUS_LOGGER_H_
#define LAGOPUS_LOGGER_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOGGER_MAX_LEN 256 // Maximum length per line (LOGGER_MAX_LEN - 1)

extern bool _lagopus_verbose;
#define lagopus_printf(s, x...) { if (_lagopus_verbose) _lagopus_printf(s, ## x); }

extern int _lagopus_printf(const char *format, ...);
extern void lagopus_fatalf(const char *format, ...);

#ifdef DEBUG
#	define LAGOPUS_DEBUG(s, x...)	{ lagopus_printf(s, ## x); }
#else
#	define LAGOPUS_DEBUG(s, x...)	{ }
#endif

#ifdef __cplusplus
}
#endif

#endif // LAGOPUS_LOGGER_H_
