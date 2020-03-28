#!/bin/sh

if [ "$#" -ne 2 ]; then
    echo "Usage: *.sh <src-dir> <dst-dir>"
    exit 1
fi

mkdir -p $1/tmp

find $1 -name "lib*.so" | while read line; do
    cp $line $1/tmp
done

find $1 -name "*_app" | while read line; do
    cp $line $1/tmp
done

scp -P 10022 $1/tmp/* user@localhost:~/$2
rm -rf $1/tmp