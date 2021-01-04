#!/bin/sh
mkdir -p /tmp/drtaint
scp -P 10022 user@localhost:~/*.json /tmp/drtaint
cp -r ./build /tmp/drtaint
mv /tmp/drtaint/* /mnt/c/Users/pasha/Documents/Projects/drtaint
rm -rf /tmp/drtaint