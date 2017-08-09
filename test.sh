#!/bin/sh -v

# +---------------------+   +--------NS0--------------+
# |        if0-0 - veth0 ---veth1    172.16.110.10/24 |
# |                     |   +-------------------------+
# |                     |
# |     	        |   +--------NS1--------------+
# |        if1-0 - veth2 ---veth3    10.10.0.10/24    |
# |        	        |   +-------------------------+
# | POC        	       	|
# |                     |   +--------NS2--------------+
# |        if2-0   veth4 ---veth5    172.16.210.10/24 |
# |                     |   +-------------------------+
# |                     |
# |                     |   +--------NS3--------------+
# |        if3-0   veth6 ---veth7    10.20.0.10/24    |
# +---------------------+   +-------------------------+

# Variables
RTE_SDK=$HOME/dpdk
POC_LIBPATH=$HOME/poc/lib
POC_BINPATH=$HOME/poc/bin

POC_NIC0=veth0
POC_NIC1=veth2
POC_NIC2=veth4
POC_NIC3=veth6
NS0_NIC=veth1
NS1_NIC=veth3
NS2_NIC=veth5
NS3_NIC=veth7
NS0_IP=172.16.110.10
NS1_IP=10.10.0.10
NS2_IP=172.16.210.10
NS3_IP=10.20.0.10

# DPDK setup
sudo modprobe uio_pci_generic
#sudo modprobe uio
#sudo insmod $RTE_SDK/build/kmod/igb_uio.ko
#sudo $RTE_SDK/tools/dpdk-devbind.py --bind=igb_uio $POC_NIC0 $POC_NIC1

# Virtual ethernet setup
sudo ip link add $POC_NIC0 type veth peer name $NS0_NIC
sudo ip link add $POC_NIC1 type veth peer name $NS1_NIC
sudo ip link add $POC_NIC2 type veth peer name $NS2_NIC
sudo ip link add $POC_NIC3 type veth peer name $NS3_NIC
sudo ip link set $POC_NIC0 up
sudo ip link set $POC_NIC1 up
sudo ip link set $POC_NIC2 up
sudo ip link set $POC_NIC3 up

# Network namespace setup
sudo ip netns add NS0
sudo ip netns add NS1
sudo ip netns add NS2
sudo ip netns add NS3
sudo ip link set $NS0_NIC netns NS0
sudo ip link set $NS1_NIC netns NS1
sudo ip link set $NS2_NIC netns NS2
sudo ip link set $NS3_NIC netns NS3
sudo ip netns exec NS0 ip address add $NS0_IP/24 dev $NS0_NIC
sudo ip netns exec NS1 ip address add $NS1_IP/24 dev $NS1_NIC
sudo ip netns exec NS2 ip address add $NS2_IP/24 dev $NS2_NIC
sudo ip netns exec NS3 ip address add $NS3_IP/24 dev $NS3_NIC
sudo ip netns exec NS0 ip link set $NS0_NIC up
sudo ip netns exec NS1 ip link set $NS1_NIC up
sudo ip netns exec NS2 ip link set $NS2_NIC up
sudo ip netns exec NS3 ip link set $NS3_NIC up

# Set routing
sudo ip netns exec NS0 ip route add default via 172.16.110.1 dev $NS0_NIC
sudo ip netns exec NS1 ip route add default via 10.10.0.1 dev $NS1_NIC
sudo ip netns exec NS2 ip route add default via 172.16.210.1 dev $NS2_NIC
sudo ip netns exec NS3 ip route add default via 10.20.0.2 dev $NS3_NIC

# Run POC
sudo $GOPATH/bin/vsw -l3 -v net_af_packet0,iface=$POC_NIC0 net_af_packet1,iface=$POC_NIC1 net_af_packet2,iface=$POC_NIC2 net_af_packet3,iface=$POC_NIC3 &

exit

# Run test
#ip address
#sudo ip netns exec NS0 ip address
#sudo ip netns exec NS1 ip address

# Run on ping flood on NS0. Monitor NS2.
#sudo ip netns exec NS2 tcpdump -vv -i $NS2_NIC &
#sudo ip netns exec NS0 tcpdump -vv -i $NS0_NIC &
#TCPDUMP_PID=$!
#sudo ip netns exec NS0 ping -c 3 $NS1_IP
#sudo kill $TCPDUMP_PID

# Run on ping flood on NS2. Monitor NS0.
#sudo ip netns exec NS3 tcpdump -vv -i $NS3_NIC &
#TCPDUMP_PID=$!
#sudo ip netns exec NS2 ping -c 3 $NS3_IP
#sudo kill $TCPDUMP_PID

# Cleanup
#sudo killall vsw

#sleep 1
#
#sudo ip netns delete NS0
#sudo ip netns delete NS1
#sudo ip netns delete NS2
#sudo ip netns delete NS3
#sudo ip link delete $POC_NIC0
#sudo ip link delete $POC_NIC1
#sudo ip link delete $POC_NIC2
#sudo ip link delete $POC_NIC3

