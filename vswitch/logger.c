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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>

#include "_cgo_export.h"
#include "../include/logger.h"

bool _lagopus_verbose;

void lagopus_verbose(bool enable) {
	_lagopus_verbose = enable;
}

int _lagopus_printf(const char *format, ...) {
	va_list ap;
	char msg[LOGGER_MAX_LEN];
	int rv;

	va_start(ap, format);
	rv = vsnprintf(msg, sizeof(msg), format, ap);
	LoggerPrint(msg);

	return rv;
}

void lagopus_fatalf(const char *format, ...) {
	va_list ap;
	char msg[LOGGER_MAX_LEN];

	va_start(ap, format);
	vsnprintf(msg, sizeof(msg), format, ap);
	LoggerFatal(msg);

}
