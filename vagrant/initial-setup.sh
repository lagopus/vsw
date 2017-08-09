#!/bin/sh
DPDKDIR=dpdk-stable-16.11.2
DPDKTAR=dpdk-16.11.2.tar.xz

# hugepages
if grep hugepages /etc/default/grub > /dev/null 2>&1; then
echo hugepage space already reserved.
else
sed 's|\(GRUB_CMDLINE_LINUX_DEFAULT=".*\)"|\1 hugepages=256"|' /etc/default/grub > tmp
mv tmp /etc/default/grub
update-grub
fi
if grep hugetlbfs /etc/fstab > /dev/null 2>&1; then
echo fstab already updated.
else
echo 'nodev /mnt/huge hugetlbfs defaults 0 0' >> /etc/fstab
fi

# DPDK
if [ \! -r dpdk-16.11.2.tar.xz ]; then
wget --timeout=60 http://fast.dpdk.org/rel/$DPDKTAR
fi
apt-get -y install gcc make python linux-image-extra-virtual
modprobe uio
insmod $DPDKDIR/build/kmod/igb_uio.ko
if [ "$?" != 0 ]; then
  tar xvf $DPDKTAR
  cd $DPDKDIR
  sed 's/SHARED_LIB=n/SHARED_LIB=y/' config/common_base > config.tmp
  mv config.tmp config/common_base
  make T=x86_64-native-linuxapp-gcc config
  make
fi
