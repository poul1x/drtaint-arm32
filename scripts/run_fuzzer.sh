#!/bin/bash
if [ "$#" -lt 1 ]; then
    echo "Usage: *.sh <app-name> [\"args\"]"
    exit 1
fi

rm tmap.json
rm -rf crashes
mkdir crashes
i=1

while true
do
    $BIN32/drrun -c $BUILD/lib$1.so -- $BUILD/$1_app $2
    # sleep 5
    mv crash.bin crashes/crash_$i.bin

    if [ $? -ne 0 ]
    then
        exit
    fi

    let "i+=1"
done