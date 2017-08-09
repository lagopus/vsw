#!/bin/sh
echo 256 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
DPDKDIR=dpdk-stable-16.11.2
modprobe uio
cd $DPDKDIR
insmod build/kmod/igb_uio.ko || true
ip link set enp0s8 down
ip link set enp0s9 down
./tools/dpdk-devbind.py --bind=igb_uio enp0s8 enp0s9
cd -
