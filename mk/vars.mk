#
# Copyright 2018 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

GO 	:= go
GOLINT	:= golint
DEP	:= dep
CP	:= cp
RM	:= rm -rf
PWDIR		:= `pwd`
PKG_NAME	:= vsw
MAIN_FILE	:= vsw.go

CONFIG_PATH	:= /usr/local/etc
CONFIG_FILE	:= vsw.conf
ENV_FILE	:= $(PWDIR)/env.sh

LIBDIR		:= /usr/local/lib

ifeq ($(CGO_LDFLAGS),)
CGO_LDFLAGS	= -L/usr/local/lib -ldpdk
endif

ifeq ($(CGO_CFLAGS),)
CGO_CFLAGS	= -I/usr/local/include/dpdk -Wall
endif


LAGOPUS_ENV	+= CGO_LDFLAGS="$(CGO_LDFLAGS)"
LAGOPUS_ENV	+= CGO_CFLAGS="$(CGO_CFLAGS)"
LAGOPUS_ENV	+= LD_LIBRARY_PATH="$(LIBDIR):$$LD_LIBRARY_PATH"

CONFIG	:= "$(CONFIG_PATH)/$(CONFIG_FILE)"
