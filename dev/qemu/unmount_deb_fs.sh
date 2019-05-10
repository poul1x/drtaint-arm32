#!/bin/sh
qemu-nbd -d /dev/nbd0
killall qemu-nbd
