# DT (drtaint test)

DT is a developer tool intended to find bugs in drtaint library. The project has an application that has an API to make its memory regions tainted and to check that they are tainted or not. To use this API, application has to call drtaint_test tool, implementing taint operations, via system call invocation.

The common test looks like this:
```c
// check mov propagation
int a = 0, b = 1;
MAKE_TAINTED(&a, sizeof(a));
b = a;
TEST_ASSERT(IS_TAINTED(&b, sizeof(b)));
```

where *MAKE_TAINTED* and *IS_TAINTED* macros perform calls to drtaint_test client.

Usage:

```bash
$BIN32/drrun -c $BUILD/libdrtaint_test.so -- $BUILD/drtaint_test_app [<test1 test2 ...> | <all>]
```