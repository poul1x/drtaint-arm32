#!/bin/sh

if [ "$#" -ne 2 ] && [ "$#" -ne 3 ]; then
	echo "Usage: source ./run.sh <mode dbg> <app> ['<args>']" >&2
	exit 1
fi

CLIENT_LIB="/home/user/DrBuild/drtaint/lib$2.so"
CLIENT_APP="/home/user/DrBuild/drtaint/$2_app"

if [ $1 = 'debug' ]; then
	export LD_LIBRARY_PATH=/home/user/DrBuild/drmemory/debug
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/user/DrBuild/dynamorio/build_dbg/lib32/debug
	/home/user/DrBuild/dynamorio/build_dbg/bin32/drrun -c $CLIENT_LIB -- $CLIENT_APP $3
else
       	export LD_LIBRARY_PATH=/home/user/DrBuild/drmemory/release
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/user/DrBuild/dynamorio/build_rel/lib32/release
	/home/user/DrBuild/dynamorio/build_rel/bin32/drrun -c $CLIENT_LIB -- $CLIENT_APP $3
fi



