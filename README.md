# Dr. Taint

This project is an attempt to improve the DrTaint: https://github.com/toshipiazza/drtaint. 
It's still raw, with some bug fixes and new features added.

# Build

First, build DynamoRIO and DrMemory framework: https://github.com/DynamoRIO/drmemory/wiki/How-To-Build.

Then find their build directories:

```bash	

export DR_BUILD_DIR=<path-to-your-dynamorio-build-directory>
export DRMF_BUILD_DIR=<path-to-your-drmemory-build-directory>

```

Copy header files:

```bash	

cp $DRMF_BUILD_DIR/../umbra/umbra.h $DRMF_BUILD_DIR/drmf/include/umbra.h
cp $DRMF_BUILD_DIR/../drsyscall/drsyscall.h $DRMF_BUILD_DIR/drmf/include/drsyscall.h

```

We need *DrMemoryFrameworkConfig.cmake* and  *DynamoRIOConfig.cmake* files to build our project. They might be situated in folders *$DRMF_BUILD_DIR/drmf* and *$DR_BUILD_DIR/cmake*

Use cmake:

```bash	

git clone https://github.com/Super-pasha/DrTaint.git
cd DrTaint
mkdir build
cd build
cmake ../ -DDynamoRIO_DIR=$DR_BUILD_DIR/cmake/ -DDrMemoryFramework_DIR=$DRMF_BUILD_DIR/drmf -DCMAKE_TOOLCHAIN_FILE=toolchain-arm32.cmake
make

```

Optionally you can add *-DDebug=ON* for building in debug mode

If all was ok, then there are 4 libs with test applications must be created in build/<client-name> folders.
You can launch them the same way as dynamorio client library:

```bash

$DR_BUILD_DIR/bin32/drrun -c lib<client-name>.so -- <client-name>_app

```
	