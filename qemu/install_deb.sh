#!/bin/sh
qemu-system-arm -M virt -smp 3 -m 1536 \
  -kernel installer-vmlinuz \
  -initrd installer-initrd.gz \
  -drive if=none,file=hda.qcow2,format=qcow2,id=hd \
  -device virtio-blk-device,drive=hd \
  -netdev user,id=mynet \
  -device virtio-net-device,netdev=mynet \
  -nographic -no-reboot
