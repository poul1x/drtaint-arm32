#!/bin/sh

if [ "$#" -lt 2 ]; then
    echo "Usage: *.sh <debug|release> <app-name> [\"args\"]"
    exit 1
fi

if [ $1 = 'debug' ]; then
	$BIN32/drrun -debug -c $BUILD/lib$2.so -- $BUILD/$2_app $3
else
    $BIN32/drrun -c $BUILD/lib$2.so -- $BUILD/$2_app $3
fi



