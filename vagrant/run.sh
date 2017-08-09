#!/bin/sh
DPDKDIR=dpdk-stable-16.11.2
cd lagopus-router/yang
sudo ../bin/openconfigd -y modules:modules/policy:modules/bgp:modules/interfaces:modules/local-routing:modules/vlan:modules/rib:modules/network-instance:modules/types -c /vagrant/openconfigd.conf lagopus-router.yang &
cd -
sudo env LD_LIBRARY_PATH=/home/ubuntu/$DPDKDIR/build/lib ./bin/vsw -v -p $DPDKDIR/build/lib -l 1,2,3,4,5,6,7 &
