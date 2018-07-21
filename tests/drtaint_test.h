#include <unistd.h>

#define DRTAINT_SUCCESS 0xAA
#define FD_APP_START_TRACE 0xFFFFEEEE
#define FD_APP_IS_TRACED 0xFFFFEEEF

#define IS_TAINTED(mem, mem_sz) \
    (write(FD_APP_IS_TRACED, mem, mem_sz) == DRTAINT_SUCCESS)

#define MAKE_TAINTED(mem, mem_sz) \
    write(FD_APP_START_TRACE, mem, mem_sz)

typedef bool (*testfunc)(void);

void run_all_tests();


// test function prototypes
bool simple_test();
