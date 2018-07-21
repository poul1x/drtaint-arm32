# Dr. Taint

A *very* WIP DynamoRIO module built on the Dr. Memory Framework to implement taint
analysis on ARM. Core functionality is still unfinished. Very raw, still has hardcoded
paths to my hard drive in CMakeLists.txt, etc.

# Limitations

Currently, taint propagation remains unimplemented for Neon and fpu instructions. glibc
must be compiled without fp support. The following worked for me (cross compiled on x86):

```bash
export CC="arm-linux-gnueabi-gcc"
export AR="arm-linux-gnueabi-ar"
export RANLIB="arm-linux-gnueabi-ranlib"
export CFLAGS="-march=armv7 -mthumb -mfloat-abi=soft"
export LDFLAGS="-march=armv7 -mthumb -mfloat-abi=soft"

# in glibc directory
./configure --without-fp --host="arm-linux-gnueabi"
```

Now, when compiling a userland application, use the following parameters:

```
LDFLAGS=-march=armv7 -mfloat-abi=soft -Wl,--rpath=/path/to/new/libc.so.6 -Wl,--dynamic-linker=/path/to/new/ld-linux.so.3
CFLAGS=-march=armv7 -mfloat-abi=soft
```

For some reason, this doesn't get rid of *all* fpu/neon instructions (to my knowledge) but
gets rid of almost all of them.


# Launch

once before launching:
 
current variables:

	export LD_LIBRARY_PATH=/home/debian/drbuild/drmemory-armhf/exports32/drmf/lib32/release
	export APP_PATH=/home/debian/drtaint/tests/build/drtaint_test
	export LIB_PATH=/home/debian/drtaint/build/libdrtaint_test.so
	export DRIO_PATH=/home/debian/drbuild/dynamorio-armhf/exports/bin32

variants:

	ls /home/debian/drtaint/tests/build
	export APP_PATH=/home/debian/drtaint/tests/build*

	ls /home/debian/drtaint/build/
	export LIB_PATH=/home/debian/drtaint/build/*


without debugging -> do:
	
	$DRIO_PATH/drrun -c $LIB_PATH -- ls

-------------

	$DRIO_PATH/drrun -c $LIB_PATH -- $APP_PATH
