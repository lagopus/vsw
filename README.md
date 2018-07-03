## Prerequisite

Followings are expected to be installed under /usr/local:

* DPDK 17.11.1

DPDK shall be built as shared libraries for now.

vsw expects the following Go version, because it uses
dep to manage a package dependency.

* Go 1.9 or newer

# How to build
## Install utils.

```
% sudo apt-get install libnuma-dev
% git clone https://github.com/lagopus/utils
% cd utils/
% ./configure
% make
% sudo make install
```

## Install vsw.

```
% dep ensure
% go install
```
