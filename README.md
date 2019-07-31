## Prerequisite

Followings are expected to be installed under /usr/local:

* DPDK 18.11.1

DPDK shall be built as shared libraries for now.

vsw expects the following Go version, because it uses
dep to manage a package dependency.

* Go 1.9 or newer

# How to build
## Install utils.
Download to appropriate directory ($HOME, etc.).

```
% sudo apt-get install libnuma-dev
% git clone https://github.com/lagopus/utils ~/utils
% cd ~/utils/
% ./configure
% make
% sudo make install
```

## build vsw.

```
% make
```

or

```
# install/exec dep
% make vendor

# exec go build
% make build
```

## Install vsw.

```
# install/exec dep
% make vendor

# exec go install
% make install
```

# Unit tests.
## Unit tests.

```
% make test
```

## Unit tests of the package.
There are some ways of how to unit tests the package.

1. Use top-level Makefile of source tree.

ex.

```
% cd agents/tunnel/ipsec/config
% make -f ${GOPATH}/src/github.com/lagopus/vsw/Makefile test
```

2. Create Makefile in current directory. Use it.

ex.

```
% cd agents/tunnel/ipsec/config

# Create Makefile
% vi Makefile
TOPDIR          = $(GOPATH)/src/github.com/lagopus/vsw
MKRULESDIR      = $(TOPDIR)/mk

include $(MKRULESDIR)/vars.mk
include $(MKRULESDIR)/rules.mk

% make test
```

3. Generate env.sh. Use it and set environment variables.

ex.

```
# Generate env.sh.
% make env

% cat env.sh
#!/bin/bash

export "CGO_LDFLAGS=-L/usr/local/lib -ldpdk"
export "CGO_CFLAGS=-I/usr/local/include/dpdk"

% source ./env.sh
% cd agents/tunnel/ipsec/config
% go test -v --cover ./...
```
