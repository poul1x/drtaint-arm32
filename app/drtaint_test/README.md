# DrTaint test

Developer tool intended to find bugs in DrTaint library. The project has an application that has an API to make its memory regions tainted and to check that they are tainted or not. To use this API, application has to call drtaint_test tool, implementing taint operations, via system call invocation.

The common test looks like this:
```c
// check mov propagation
int a = 0, b = 1;
MAKE_TAINTED(&a, sizeof(a));
b = a;
TEST_ASERT(IS_TAINTED(&b, sizeof(b)));
```

Where *MAKE_TAINTED* macros (and others) is a call to drtaint_test client.

Usage:

```bash
# Setup env variables
export $DYNAMORIO_HOME=<path-to-your-dynamorio-package>
export $DRTAINT_HOME=<path-to-drtaint-build-folder>

export PROJECT=$DRTAINT_HOME/drtaint_test
$DYNAMORIO_HOME/bin32/drrun -c $PROJECT/libdrtaint_test.so -- $PROJECT/drtaint_test_app [<tests>]
```

Run all tests:

```bash=
# Setup env variables
export $DYNAMORIO_HOME=<path-to-your-dynamorio-package>
export $DRTAINT_HOME=<path-to-drtaint-build-folder>

export PROJECT=$DRTAINT_HOME/drtaint_test
$DYNAMORIO_HOME/bin32/drrun -c $PROJECT/libdrtaint_test.so -- $PROJECT/drtaint_test_app --all
```