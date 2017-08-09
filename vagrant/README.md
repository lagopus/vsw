# What's this?

Setup test environment with mulltiple VMs.

# Summary of VMs
- ingress, egress
  - Linux host.
- lagopus
  - Linux with DPDK configuration.
  - hugepages: 2MB x 256pages
  - $GOPATH/src/github.com/lagopus/vsw, $GOPATH/src/github.com/lagopus/lagopus-router and $GOPATH/bin on host machine are
    mounted on $HOME,
- All VMs
  - vagrant automatically mounted this directory on /vagrant.

# Environment

Initial IP addresses are in Vagrantfile.

```
+------------------+                           +------------------+
|ingress           |   +-------------------+   |egerss            |
|            enp0s8|   |lagopus2 (w/ DPDK) |   |enp0s8            |
|         10.1.0.10-----portid0     portid1-----10.2.0.10         |
+------------------+   |                   |   +------------------+
                       +-------------------+
```

# Setup
- install vagrant from official site
- install openconfigd (master branch)
- get lagopus/lagopus-router (master branch)
- install vsw

# How to start VMs
```
% vagrant up
(take a minites...)
```

# How to test
```
% vagrant ssh lagopus
lagopus% sudo ./bin/vsw ...
% vagrant ssh ingress
ingress% ping 10.2.0.10
```

# How to stop VMs
```
% vagrant halt
```
