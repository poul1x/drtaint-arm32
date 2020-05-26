drtaint
===

**disable ASLR!**

This project is an attempt to improve the drtaint: https://github.com/toshipiazza/drtaint.
It's still raw, with some bug fixes and new features added.

## Build (Cross compilation on linux host)

---
```bash
# Install ARM toolchain
sudo apt-get install gcc-arm-linux-gnueabihf binutils-arm-linux-gnueabihf g++-arm-linux-gnueabihf

# Get prebuilt DynamoRIO package
wget -O dynamorio.tar.gz https://github.com/DynamoRIO/dynamorio/releases/download/release_8.0.0-1/DynamoRIO-ARM-Linux-EABIHF-8.0.0-1.tar.gz
mkdir dynamorio && tar xvf dynamorio.tar.gz -C dynamorio --strip-components 1

# Download and build drtaint
git clone https://github.com/poul1x/drtaint
cd drtaint && mkdir build && cd build
cmake ../ -DDynamoRIO_DIR=../dynamorio/cmake -DDrMemoryFramework_DIR=../dynamorio/drmemory/drmf -DCMAKE_TOOLCHAIN_FILE=toolchain-arm32.cmake
make
```
---

## Launch

**Note:** *host* = Linux machine (I've used Ubuntu 18 x32 and WSL), *guest* = Linux on ARM board (I've tested on *BeagleBone Black* and *qemu*).

Assume, you have a board and ssh access to your Linux guest. If not, look at this [manual](/qemu).

On Linux host do:

```bash
export DRTAINT_HOME="<path-to-drtaint-build-directory>"

# Attributes of your guest ssh server
export USERNAME="<your-guest-username> (my is debian)"
export IP="<ip-of-ssh-server> (my is 127.0.0.1)"
export PORT="<port-of-ssh-server> (my is 10022)"

# Copy drtaint
scp -P $PORT -rp $DRTAINT_HOME $USERNAME@$IP:~/build
```

On Linux guest do:

```bash
# Get prebuilt DynamoRIO package
cd ~/
wget -O dynamorio.tar.gz https://github.com/DynamoRIO/dynamorio/releases/download/release_8.0.0-1/DynamoRIO-ARM-Linux-EABIHF-8.0.0-1.tar.gz
mkdir dynamorio && tar xvf dynamorio.tar.gz -C dynamorio --strip-components 1

# Setup env
export BIN32=~/dynamorio/bin32
export BUILD=~/build

# Launch self-test
$BIN32/drrun -c $BUILD/libdrtaint_test.so -- $BUILD/drtaint_test_app --all

# Expected output:
# Results: passed - 33, failed - 8
# Exitting...
```

If successfull, you can try other samples:

| Name                                  | Description                                                           |
| :------------------------------------ | :-------------------------------------------------------------------- |
| [drtaint only](/app/drtaint_only)     | Empty dynamorio client showing program slowdown running under drtaint |
| [drtaint test](/app/drtaint_test)     | Developer tool intended to find bugs in DrTaint library               |
| [drtaint marker](/app/drtaint_marker) | Performs tainted instruction recording                                |
