#include <unistd.h>
#include <assert.h>

#define DRTAINT_SUCCESS 0xAA
#define FD_APP_START_TRACE 0xFFFFEEEE
#define FD_APP_IS_TRACED 0xFFFFEEEF

#define IS_TAINTED(mem, mem_sz) \
    (write(FD_APP_IS_TRACED, mem, mem_sz) == DRTAINT_SUCCESS)

#define MAKE_TAINTED(mem, mem_sz) \
    assert(write(FD_APP_START_TRACE, mem, mem_sz) == DRTAINT_SUCCESS)

#define TEST_ASSERT(q)                                         \
if (!(q))                                                       \
{                                                               \
    printf("Line %d: assertion %s failed\n", __LINE__, #q);     \
    return false;                                               \
}             

#define CLEAR(mem, mem_sz) my_zero_memory(mem, mem_sz)

typedef bool (*testfunc)(void);

void run_all_tests();

void show_all_tests();

void my_zero_memory(void* dst, int size);

void usage();

// test function prototypes
bool test_simple();
bool test_assign();
bool test_arith();
bool test_bitwise();
bool test_condex_op();
bool test_assign_ex();
bool test_struct();
bool test_func_call();
bool test_array();
bool test_untaint();

bool test_asm_ldr_imm();
bool test_asm_ldr_imm_ex();
bool test_asm_ldr_reg();
bool test_asm_ldr_reg_ex();
bool test_asm_ldrd_imm();
bool test_asm_ldrd_reg();
bool test_asm_ldm();
bool test_asm_ldm_w();
bool test_asm_ldm_ex();
bool test_asm_ldm_ex_w();