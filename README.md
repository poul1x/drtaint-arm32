# DrTaint

This project is an attempt to improve the DrTaint: https://github.com/toshipiazza/drtaint. 
It's still raw, with some bug fixes and new features added.

## Build

1. Download and build DrMemory Framework ([Cross-Compiling for ARM on Linux](https://github.com/DynamoRIO/drmemory/wiki/How-To-Build)). 

2. Follow these instructions:

```bash
export DRMF_HOME="<path-to-your-drmemory-build-directory>"

# Find headers and copy them to include folder
cp `find $DRMF_HOME/../ -name umbra.h` $DRMF_HOME/drmf/include/umbra.h
cp `find $DRMF_HOME/../ -name drsyscall.h` $DRMF_HOME/drmf/include/drsyscall.h

# Comment some lines in cmake file for successfull build
sed -i 's/SET_PROPERTY/#SET_PROPERTY/g' $DRMF_HOME/drmf/DRMFTarget32.cmake
```

You need *DrMemoryFrameworkConfig.cmake* and *DynamoRIOConfig.cmake* files to build DrTaint. They must be situated in folders *\$DRMF_HOME/drmf* and  *\$DYNAMORIO_HOME/cmake*.
```bash
git clone https://github.com/Super-pasha/DrTaint.git
mkdir drt_build
cd drt_build
cmake ../DrTaint -DDynamoRIO_DIR=$DRMF_HOME/dynamorio/cmake -DDrMemoryFramework_DIR=$DRMF_HOME/drmf -DCMAKE_TOOLCHAIN_FILE=toolchain-arm32.cmake
make -j
```
## Launch

**Note:** *host* = Linux x86 machine (my is Ubuntu 18 x32), *guest* = Linux on ARM board (I've tested on *BeagleBone black* and *qemu*). 

Assume, you have a board and ssh access to your Linux guest. If not, look at this [manual](/dev/qemu).

On Linux host do:

```bash
export DRTAINT_HOME="<path-to-drtaint-build-directory>"

# Attributes of your guest ssh server
export USERNAME="<your-guest-username> (my is debian)"
export IP="<ip-of-ssh-server> (my is 127.0.0.1)"
export PORT="<port-of-ssh-server> (my is 10022)"

# Copy drtaint
scp -P $PORT -rp $DRTAINT_HOME $USERNAME@$IP:~/drt_build
```

On Linux guest do:

```bash
# Get prebuilt dynamorio package. I prefer latest
cd ~/
wget https://github.com/DynamoRIO/dynamorio/releases/download/release_7.1.0/DynamoRIO-ARM-Linux-EABIHF-7.1.0-1.tar.gz 
tar xvf DynamoRIO-ARM-Linux-EABIHF-7.1.0-1.tar.gz

# Launch self-test
export BIN32=~/DynamoRIO-ARM-Linux-EABIHF-7.1.0-1/bin32
$BIN32/drrun -c drt_build/drtaint_test/libdrtaint_test.so -- drt_build/drtaint_test/drtaint_test_app --all

# Expected output: 
# Results: passed - 33, failed - 8
# Exitting...
```

If successfull, you can try other samples:

| Name                              | Description                                                           |
| :-------------------------------- | :-------------------------------------------------------------------- |
| [DrTaint only](/app/drtaint_only) | Empty dynamorio client showing program slowdown running under DrTaint |
| [DrTaint test](/app/drtaint_test) | Developer tool intended to find bugs in DrTaint library               |
| [DrMarker](/app/drmarker)         | Performs instruction slicing                                          |
