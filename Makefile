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

TOPDIR		= $(GOPATH)/src/github.com/lagopus/vsw
MKRULESDIR	= $(TOPDIR)/mk

include $(MKRULESDIR)/vars.mk

all:	vendor build

setup:
	@echo "Get dep..."
	$(GO) get -u github.com/golang/dep/cmd/dep
	@echo "Get golint..."
	$(GO) get -u golang.org/x/lint/golint

vendor:	setup
	@echo "Exec dep..."
	$(DEP) ensure

build:
	@echo "Build..."
	$(LAGOPUS_ENV) $(GO) build -o $(PKG_NAME) $(MAIN_FILE)

lint:
	@echo "Exec golint..."
	$(GOLINT) $$($(GO) list ./...)
	@echo "Exec vet..."
	$(LAGOPUS_ENV) $(GO) vet $$($(GO) list ./...)

install:
	@echo "Install..."
	$(LAGOPUS_ENV) $(GO) install

copy-config:
	@echo "Copy $(PWDIR)/$(CONFIG_FILE) => $(CONFIG)"
	$(CP) $(PWDIR)/$(CONFIG_FILE) $(CONFIG)

clean::
	$(GO) clean -cache
	$(RM) $(PKG_NAME)

distclean:: clean
	$(RM) vendor

include $(MKRULESDIR)/rules.mk

.PHONY: all dep vendor build install copy-config clean distclean
