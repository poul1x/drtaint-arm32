#!/bin/sh
qemu-system-arm -M virt -smp 3 -m 1536 \
  -kernel boot/vmlinuz \
  -initrd boot/initrd.img \
  -append 'root=/dev/vda2' \
  -drive if=none,file=hda.qcow2,format=qcow2,id=hd \
  -device virtio-blk-device,drive=hd \
  -netdev user,id=mynet \
  -device virtio-net-device,netdev=mynet \
  -netdev user,id=n0,hostfwd=tcp::10022-:22,hostfwd=tcp::10023-:5555 \
  -device virtio-net-device,netdev=n0 \
  -nographic
