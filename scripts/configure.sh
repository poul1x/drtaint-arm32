#!/bin/sh

if [ "$#" -ne 2 ]; then
    echo "Usage: *.sh <arm|thumb> <opt|no-opt>"
    exit 1
fi

if [ $1 = 'arm' ]; then
    thumb=""
else
    thumb="-DThumb=1"
fi

if [ $2 = 'opt' ]; then
    optimized="-DOptimized=1"
else
    optimized=""
fi

mkdir -p build &&                                   \
cd build &&                                         \
rm -f CMakeCache.txt &&                             \
cmake ../                                           \
$thumb                                              \
$optimized                                          \
-DDynamoRIO_DIR=/mnt/c/Programs/NoInstaller/dynamorio/build/cmake                  \
-DDrMemoryFramework_DIR=/mnt/c/Programs/NoInstaller/drmemory/build/drmf                  \
-DCMAKE_TOOLCHAIN_FILE=toolchain-arm32.cmake