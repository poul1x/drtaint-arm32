#!/bin/sh
modprobe nbd max_part=16
qemu-nbd -c /dev/nbd0 hda.qcow2
