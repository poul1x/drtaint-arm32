#include "drtaint_test.h"

#include <sys/types.h>
#include <stdio.h>
#include <string.h>

/*
    This is a test application which checks 
    that drtaint library works properly. 
    This application must be launched under 
    dynamorio with libdrtaint_test.so (see app/drtaint_test.cpp) 

    This application is a table of test functions having a structure:

    function test_XXX
    {
        MAKE_TAINTED(mem_region)
        ... 
        inline arm assembler instructions 
        ...
        IS_TAINTED(mem_region) -> test failed / succeeded
    }
    
    Firstly, we use MAKE_TAINTED macro to let 
    libdrtaint_test.so taint our data.
    Then we insert inline arm assembler instructions with 
    the aim of testing their handlers in drtaint library (see drtaint/drtaint.cpp).
    Finally we use IS_TAINTED macro to let libdrtaint_test.so show 
    the data was tracked or not. CLEAR macro allows you to make data untainted
*/

Test gTests[] = {

    //{"simple", test_simple},
    //{"arith", test_arith},
    //{"assign", test_assign},
    //{"bitwise", test_bitwise},
    //{"struct", test_struct},
    //{"func_call", test_func_call},
    //{"array", test_array},
    //{"condex_op", test_condex_op},
    //{"assign_ex", test_assign_ex},
    //{"untaint", test_untaint},
    //{"untaint_stack", test_untaint_stack},

    //{"ldr_imm", test_asm_ldr_imm},
    //{"ldr_imm_ex", test_asm_ldr_imm_ex},
    //{"ldr_reg", test_asm_ldr_reg},
    //{"ldr_reg_ex", test_asm_ldr_reg_ex},
    //
    {"ldrd_imm", test_asm_ldrd_imm},
    {"ldrd_reg", test_asm_ldrd_reg},
    //
    //{"ldm", test_asm_ldm},
    //{"ldm_w", test_asm_ldm_w},
    //{"ldm_ex", test_asm_ldm_ex},
    //{"ldm_ex_w", test_asm_ldm_ex_w},
    //
    {"str_imm", test_asm_str_imm},
    {"str_reg", test_asm_str_reg},
    {"strex", test_asm_strex},

    {"strd_imm", test_asm_strd_imm},
    {"strd_reg", test_asm_strd_reg},
    {"strexd", test_asm_strexd},
    //{"stm", test_asm_stm},
    //{"stm_w", test_asm_stm_w},
    //{"stm_ex", test_asm_stm_ex},
    //{"stm_ex_w", test_asm_stm_ex_w},

};

const int gTests_sz = sizeof(gTests) / sizeof(gTests[0]);

int main(int argc, char *argv[])
{
    if (argc == 1)
    {
        usage();
        return 0;
    }

    if (!strcmp(argv[1], "--all"))
    {
        run_all_tests();
        return 0;
    }

    if (!strcmp(argv[1], "--show"))
    {
        show_all_tests();
        return 0;
    }

    int count_failed = 0, count_passed = 0;
    bool passed;
    Test *ptest;

    for (int i = 1; i < argc; i++)
    {
        ptest = find_test(argv[i]);
        if (ptest)
        {
            printf("\n\n--- Running test %s--- \n\n", ptest->name);
            passed = ptest->run();

            printf("Test %s is %s\n", ptest->name,
                   passed ? "passed" : "failed");

            passed ? count_passed++ : count_failed++;
        }

        else
        {
            printf("Error: test '%s' not found\n", argv[i]);
            break;
        }
    }

    printf("\nResults: passed - %d, failed - %d\nExitting...\n",
           count_passed, count_failed);

    return 0;
}

Test *find_test(const char *name)
{
    Test *pt;

    for (int i = 0; i < gTests_sz; i++)
    {
        pt = &gTests[i];

        if (!strcmp(name, pt->name))
            return pt;
    }

    return NULL;
}

void run_all_tests()
{
    int count_failed = 0, count_passed = 0;
    bool passed;
    Test *ptest;

    for (int i = 1; i < gTests_sz; i++)
    {
        ptest = &gTests[i];

        printf("\n\n--- Running test %s--- \n\n", ptest->name);
        passed = ptest->run();

        printf("Test %s is %s\n", ptest->name,
               passed ? "passed" : "failed");

        passed ? count_passed++ : count_failed++;
    }

    printf("\nResults: passed - %d, failed - %d\nExitting...\n",
           count_passed, count_failed);
}

void show_all_tests()
{
    printf("Available tests:\n");

    for (int i = 0; i<gTests_sz; i++)
        printf("  %-3d %s\n", i + 1, gTests[i].name);
}

void my_zero_memory(void *dst, int size)
{
    char *p = (char *)dst;
    while (p - (char *)dst < size)
        *p++ = 0;
}

void usage()
{
    printf("Usage:\n");
    printf("Run tests: file.exe <test1> <test2> ...\n");
    printf("Run all tests: file.exe --all\n");
    printf("Show all tests: file.exe --show\n");
}

#pragma region simple

bool test_simple()
{
    char buf[] = "12345";
    char buf2[] = "54321";
    MAKE_TAINTED(buf, sizeof(buf));

    printf("buf is tainted? -> %d\n", IS_TAINTED(buf, sizeof(buf)));
    printf("buf2 is tainted? -> %d\n", IS_TAINTED(buf2, sizeof(buf2)));

    int imm = 100500;
    int imm2 = 100501;
    MAKE_TAINTED(&imm, sizeof(int));

    printf("imm is tainted? -> %d\n", IS_TAINTED(&imm, sizeof(int)));
    printf("imm2 is tainted? -> %d\n", IS_TAINTED(&imm2, sizeof(int)));

    return IS_TAINTED(buf, sizeof(buf)) && IS_TAINTED(&imm, sizeof(int)) &&
           !IS_TAINTED(buf2, sizeof(buf2)) && !IS_TAINTED(&imm2, sizeof(int));
}

#pragma endregion simple

#pragma region assign

bool test_assign()
{
    int x = 0, y = 0, z = 0;
    MAKE_TAINTED(&x, sizeof(int));

    y = x;
    TEST_ASSERT(IS_TAINTED(&y, sizeof(int)));

    z = y;
    TEST_ASSERT(IS_TAINTED(&z, sizeof(int)));

    x = 0;
    TEST_ASSERT(!IS_TAINTED(&x, sizeof(int)));

    return true;
}

#pragma endregion assign

#pragma region assign_ex

bool test_assign_ex()
{
    int x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, y;
    x1 = x2 = x3 = x4 = x5 = x6 = x7 = x8 = x9 = x10 = x11 = y = 1;

    MAKE_TAINTED(&y, sizeof(int));

    // some of operations require conditional execution
    TEST_ASSERT(IS_TAINTED(&(x1 = y), sizeof(int)));
    TEST_ASSERT(IS_TAINTED(&(x2 += y), sizeof(int)));
    TEST_ASSERT(IS_TAINTED(&(x3 -= y), sizeof(int)));
    TEST_ASSERT(IS_TAINTED(&(x4 *= y), sizeof(int)));
    TEST_ASSERT(IS_TAINTED(&(x5 /= y), sizeof(int)));
    TEST_ASSERT(IS_TAINTED(&(x6 %= y), sizeof(int)));
    TEST_ASSERT(IS_TAINTED(&(x7 <<= y), sizeof(int)));
    TEST_ASSERT(IS_TAINTED(&(x8 >>= y), sizeof(int)));
    TEST_ASSERT(IS_TAINTED(&(x9 &= y), sizeof(int)));
    TEST_ASSERT(IS_TAINTED(&(x10 ^= y), sizeof(int)));
    TEST_ASSERT(IS_TAINTED(&(x11 |= y), sizeof(int)));

    return true;
}

#pragma endregion assign_ex

#pragma region arith

bool test_arith()
{
    int x1, x2, x3, y = 23, z = 5;
    MAKE_TAINTED(&z, sizeof(int));

    x1 = y + z;
    TEST_ASSERT(IS_TAINTED(&x1, sizeof(int)));

    x2 = y * z;
    TEST_ASSERT(IS_TAINTED(&x2, sizeof(int)));

    /* sdiv and udiv instructions are unsupported here
    functions __aeabi_idiv(PLT), __aeabi_udiv(PLT) are used instead.
    These functions require conditional execution 
    so division will be considered in another test */

    x3 = y - z;
    TEST_ASSERT(IS_TAINTED(&x3, sizeof(int)));

    x1++;
    TEST_ASSERT(IS_TAINTED(&x1, sizeof(int)));

    x1--;
    TEST_ASSERT(IS_TAINTED(&x1, sizeof(int)));

    return true;
}

#pragma endregion arith

#pragma region bitwise

bool test_bitwise()
{
    int x1, x2, x3, x4, x5, x6, y = 23, z = 5;
    MAKE_TAINTED(&z, sizeof(int));

    x1 = y | z;
    TEST_ASSERT(IS_TAINTED(&x1, sizeof(int)));

    x2 = y & z;
    TEST_ASSERT(IS_TAINTED(&x2, sizeof(int)));

    x3 = y ^ z;
    TEST_ASSERT(IS_TAINTED(&x3, sizeof(int)));

    x4 = y >> z;
    TEST_ASSERT(IS_TAINTED(&x4, sizeof(int)));

    x5 = y << z;
    TEST_ASSERT(IS_TAINTED(&x5, sizeof(int)));

    x6 = ~z;
    TEST_ASSERT(IS_TAINTED(&x6, sizeof(int)));

    return true;
}

#pragma endregion bitwise

#pragma region struct

bool test_struct()
{
    struct S
    {
        int x;
        char *p;
    };

    char p0[] = "123";
    int x0 = 3;

    MAKE_TAINTED(p0, sizeof(p0));
    MAKE_TAINTED(&x0, sizeof(int));

    // uses str arg1, [arg2, #imm]
    struct S s;
    s.p = p0;
    s.x = x0;

    TEST_ASSERT(IS_TAINTED(s.p, sizeof(p0)));
    TEST_ASSERT(IS_TAINTED(&s.x, sizeof(int)));

    char *p1;
    int x1;

    p1 = s.p;
    x1 = s.x;

    TEST_ASSERT(IS_TAINTED(p1, sizeof(p0)));
    TEST_ASSERT(IS_TAINTED(&x1, sizeof(int)));

    return true;
}

#pragma endregion struct

#pragma region array

bool test_array()
{
    char src1[] = "~DrTaint~";
    char *dst1 = new char[sizeof(src1)];
    char dst2[sizeof(src1)];

    MAKE_TAINTED(src1, sizeof(src1));
    strcpy(dst1, src1);
    strcpy(dst2, src1);

    bool b = IS_TAINTED(dst1, sizeof(src1));
    delete dst1;

    TEST_ASSERT(b);
    TEST_ASSERT(IS_TAINTED(dst2, sizeof(src1)));

    int C[2] = {1, 2};
    int D[2] = {0};

    MAKE_TAINTED(&C[0], sizeof(int));
    D[1] = C[0];

    TEST_ASSERT(IS_TAINTED(&D[1], sizeof(int)));
    TEST_ASSERT(!IS_TAINTED(&D[0], sizeof(int)));

    int A[2][2] = {{1, 2}, {3, 4}};
    int B[2][2] = {0};

    MAKE_TAINTED(&A[1][1], sizeof(int));
    B[0][0] = A[1][1];
    B[0][1] = A[1][1];

    TEST_ASSERT(IS_TAINTED(&B[0][0], sizeof(int)));
    TEST_ASSERT(IS_TAINTED(&B[0][1], sizeof(int)));
    TEST_ASSERT(!IS_TAINTED(&B[1][1], sizeof(int)));
    TEST_ASSERT(!IS_TAINTED(&B[1][0], sizeof(int)));

    return true;
}

#pragma endregion array

#pragma region func_call

static int cube_cp(int x)
{
    return x * x * x;
}

bool test_func_call()
{
    int x = 3, y, z, r1, r2;
    MAKE_TAINTED(&x, sizeof(int));

    printf("Simple func call\n");
    y = cube_cp(x);
    TEST_ASSERT(IS_TAINTED(&y, sizeof(int)));

    y = z = 2;
    MAKE_TAINTED(&y, sizeof(int));

    // require func call
    printf("Division\n");
    r1 = y / z;
    TEST_ASSERT(IS_TAINTED(&r1, sizeof(int)));

    r2 = y % z;
    TEST_ASSERT(IS_TAINTED(&r2, sizeof(int)));

    return true;
}

#pragma endregion func_call

#pragma region condex_op

bool test_condex_op()
{
    int x1, x2, x5, y = 23, z = 5;
    MAKE_TAINTED(&z, sizeof(int));

    x1 = y || z;
    TEST_ASSERT(IS_TAINTED(&x1, sizeof(int)));

    x2 = y && z;
    TEST_ASSERT(IS_TAINTED(&x2, sizeof(int)));

    x5 = !z;
    TEST_ASSERT(IS_TAINTED(&x5, sizeof(int)));

    return true;
}

#pragma endregion condex_op

#pragma region untaint

#define TEST_XOR_REG_REG(asm_command)               \
    printf("TEST_XOR_REG_REG: " #asm_command "\n"); \
    x1 = 80;                                        \
    x2 = 508;                                       \
    MAKE_TAINTED(&x2, sizeof(int));                 \
                                                    \
    asm(#asm_command " %0, %1, %1;"                 \
        : "=r"(x1)                                  \
        : "r"(x2));                                 \
                                                    \
    TEST_ASSERT(!IS_TAINTED(&x1, sizeof(int)))

bool test_untaint()
{
    // when assigning a value to k with mov r, imm
    // we untaint it, commands [eor | sub | ..] r1, r0, r0
    // are equivalent to mov r, imm

    int k = 8;
    TEST_ASSERT(!IS_TAINTED(&k, sizeof(int)));

    MAKE_TAINTED(&k, sizeof(int));
    TEST_ASSERT(IS_TAINTED(&k, sizeof(int)));

    k = 8;
    TEST_ASSERT(!IS_TAINTED(&k, sizeof(int)));

    int x1, x2;
    TEST_XOR_REG_REG(eor);
    TEST_XOR_REG_REG(eors);
    TEST_XOR_REG_REG(sub);
    TEST_XOR_REG_REG(subs);
    TEST_XOR_REG_REG(sbc);
    TEST_XOR_REG_REG(sbcs);

    char buf[] = "123456789";
    MAKE_TAINTED(buf, sizeof(buf));
    TEST_ASSERT(IS_TAINTED(buf, sizeof(buf)));

    CLEAR(buf, sizeof(buf));
    TEST_ASSERT(!IS_TAINTED(buf, sizeof(buf)));
    return true;
}

#pragma endregion untaint

#pragma region untaint_stack

void func_help_us1()
{
    char buf[512];
    printf("func_help_us1: buf is tainted\n");
    MAKE_TAINTED(buf, sizeof(buf));
}

bool func_help_us2()
{
    char buf[256];
    printf("func_help_us2: checking buf\n");
    for (int i = 0; i < (int)sizeof(buf); i++)
    {
        printf("Checking byte %d: ", i);
        TEST_ASSERT(!IS_TAINTED(&buf[i], sizeof(char)));
        printf("\r");
    }
    printf("\n");

    return true;
}

bool test_untaint_stack()
/*
    When freeing a stack frame with tainted memory part, 
    freed memory area still remains tainted.
    This test checks that behavior is false
*/
{
    func_help_us1();
    TEST_ASSERT(func_help_us2());
    return true;
}

#pragma endregion untaint_stack

#pragma region asm_ldr_imm

#define INL_LDR(com, r0, r1)              \
                                          \
    printf("Test '" #com " r0, [r1]'\n"); \
    r0 = 0;                               \
    asm volatile("ldr r1, %1;"            \
                 "" #com " r0, [r1];"     \
                 "str r0, %0;"            \
                 : "=m"(r0)               \
                 : "m"(r1)                \
                 : "r0", "r1")

#define INL_LDR_I(com, r0, r1)                \
                                              \
    printf("Test '" #com " r0, [r1, #4]'\n"); \
    r0 = 0;                                   \
    asm volatile("ldr r1, %1;"                \
                 "" #com " r0, [r1, #4];"     \
                 "str r0, %0;"                \
                 : "=m"(r0)                   \
                 : "m"(r1)                    \
                 : "r0", "r1")

#ifndef MTHUMB
#define INL_LDR_I_PRE(com, r0, r1)             \
                                               \
    printf("Test '" #com " r0, [r1, #4]!'\n"); \
    r0 = 0;                                    \
    asm volatile("ldr r1, %1;"                 \
                 "" #com " r0, [r1, #4]!;"     \
                 "str r0, %0;"                 \
                 : "=m"(r0)                    \
                 : "m"(r1)                     \
                 : "r0", "r1")

#define INL_LDR_I_POST(com, r0, r1)          \
                                             \
    printf("Test " #com " r0, [r1], #4'\n"); \
    r0 = 0;                                  \
    asm volatile("ldr r1, %1;"               \
                 "" #com " r0, [r1], #4;"    \
                 "str r0, %0;"               \
                 : "=m"(r0)                  \
                 : "m"(r1)                   \
                 : "r0", "r1")
#endif

#ifndef MTHUMB
#define CHECK_ALL_IMM(com, r0, r1)             \
                                               \
    INL_LDR(com, r0, r1);                      \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
                                               \
    INL_LDR_I(com, r0, r1);                    \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
                                               \
    INL_LDR_I_PRE(com, r0, r1);                \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
                                               \
    INL_LDR_I_POST(com, r0, r1);               \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int)))
#else
#define CHECK_ALL_IMM(com, r0, r1)             \
                                               \
    INL_LDR(com, r0, r1);                      \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
                                               \
    INL_LDR_I(com, r0, r1);                    \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int)))
#endif

bool test_asm_ldr_imm()
/*
    Checks 
    
    ldrXX r0, [r]
    ldrXX r0, [r1, #imm]
    ldrXX r0, [r1, #imm]!
    ldrXX r0, [r1], #imm

    where r1 is tainted
    
*/
{
    unsigned int A[2] = {0x12345678, 0x9ABCDEF0}, v;
    unsigned int **pA = (unsigned int **)&A;
    MAKE_TAINTED(A, sizeof(A));

    CHECK_ALL_IMM(ldr, v, pA);
    CHECK_ALL_IMM(ldrb, v, pA);
    CHECK_ALL_IMM(ldrh, v, pA);
    CHECK_ALL_IMM(ldrsb, v, pA);
    CHECK_ALL_IMM(ldrsh, v, pA);

#ifdef MTHUMB
    CHECK_ALL_IMM(ldrt, v, pA);
    CHECK_ALL_IMM(ldrbt, v, pA);
    CHECK_ALL_IMM(ldrsbt, v, pA);
    CHECK_ALL_IMM(ldrht, v, pA);
    CHECK_ALL_IMM(ldrsht, v, pA);
#endif

    INL_LDR(ldrex, v, pA);
    TEST_ASSERT(IS_TAINTED(&v, sizeof(int)));

    INL_LDR(ldrexb, v, pA);
    TEST_ASSERT(IS_TAINTED(&v, sizeof(int)));

    INL_LDR(ldrexh, v, pA);
    TEST_ASSERT(IS_TAINTED(&v, sizeof(int)));
    return true;
}

#ifndef MTHUMB
#define CHECK_ALL_I_EX(com, r0, r1)             \
                                                \
    INL_LDR_I(com, r0, r1);                     \
    TEST_ASSERT(!IS_TAINTED(&r0, sizeof(int))); \
                                                \
    INL_LDR_I_PRE(com, r0, r1);                 \
    TEST_ASSERT(!IS_TAINTED(&r0, sizeof(int)))
#else
#define CHECK_ALL_I_EX(com, r0, r1) \
    INL_LDR_I(com, r0, r1);         \
    TEST_ASSERT(!IS_TAINTED(&r0, sizeof(int)))
#endif

bool test_asm_ldr_imm_ex()
/*
    Checks 
    
    ldrXX r0, [r]
    ldrXX r0, [r1, #imm]
    ldrXX r0, [r1, #imm]!

    where r1 is not tainted
    
*/
{
    unsigned int A[2] = {0x12345678, 0x9ABCDEF0}, v;
    unsigned int **pA = (unsigned int **)&A;
    MAKE_TAINTED(A, sizeof(int));

    CHECK_ALL_I_EX(ldr, v, pA);
    CHECK_ALL_I_EX(ldrb, v, pA);
    CHECK_ALL_I_EX(ldrh, v, pA);
    CHECK_ALL_I_EX(ldrsb, v, pA);
    CHECK_ALL_I_EX(ldrsh, v, pA);

#ifdef MTHUMB
    CHECK_ALL_I_EX(ldrt, v, pA);
    CHECK_ALL_I_EX(ldrbt, v, pA);
    CHECK_ALL_I_EX(ldrsbt, v, pA);
    CHECK_ALL_I_EX(ldrht, v, pA);
    CHECK_ALL_I_EX(ldrsht, v, pA);
#endif

    return true;
}

#pragma endregion ldr_imm

#pragma region asm_ldr_reg

#define INL_REG(com, r0, r1, r2)              \
                                              \
    printf("Test '" #com " r0, [r4, r3]'\n"); \
    r0 = 0;                                   \
    asm volatile("ldr r4, %1\n\t"             \
                 "ldr r3, %2\n\t"             \
                 "" #com " r0, [r4, r3]\n\t"  \
                 "str r0, %0\n\t"             \
                 : "=m"(r0)                   \
                 : "m"(r1), "m"(r2)           \
                 : "r0", "r3", "r4")

#ifndef MTHUMB
#define INL_REG_PRE(com, r0, r1, r2)           \
                                               \
    printf("Test '" #com " r0, [r1, r2]!'\n"); \
    r0 = 0;                                    \
    asm volatile("ldr r1, %2;"                 \
                 "ldr r2, %1;"                 \
                 "" #com " r0, [r2, r1]!;"     \
                 "str r0, %0;"                 \
                 : "=m"(r0)                    \
                 : "m"(r1), "m"(r2)            \
                 : "r0", "r1", "r2")
#endif

#ifndef MTHUMB
#define CHECK_ALL_R(com, r0, r1, r2)           \
    INL_REG(com, r0, r1, r2);                  \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
    INL_REG_PRE(com, r0, r1, r2);              \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int)))
#else
#define CHECK_ALL_R(com, r0, r1, r2) \
    INL_REG(com, r0, r1, r2);        \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int)))
#endif

bool test_asm_ldr_reg()
/*
    Checks 

    ldrXX r0, [r1, r2]
    ldrXX r0, [r1, r2]!

    where r2 is tainted
*/
{
    unsigned int A[14] = {0, 1, 2, 3, 4, 5, 6, 7, 8}, v;
    unsigned int **pA = (unsigned int **)&A;
    int reg_offs = 7 * sizeof(int);

    MAKE_TAINTED(&reg_offs, sizeof(reg_offs));

    CHECK_ALL_R(ldr, v, pA, reg_offs);
    CHECK_ALL_R(ldrb, v, pA, reg_offs);
    CHECK_ALL_R(ldrh, v, pA, reg_offs);
    CHECK_ALL_R(ldrsb, v, pA, reg_offs);
    CHECK_ALL_R(ldrsh, v, pA, reg_offs);

    return true;
}

#ifndef MTHUMB
#define CHECK_ALL1(com, r0, r1, r2)            \
    printf("Both tainted:\n");                 \
    INL_REG(com, r0, r1, r2);                  \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
    INL_REG_PRE(com, r0, r1, r2);              \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int)))

#define CHECK_ALL2(com, r0, r1, r2)             \
    printf("Both untainted:\n");                \
    INL_REG(com, r0, r1, r2);                   \
    TEST_ASSERT(!IS_TAINTED(&r0, sizeof(int))); \
    INL_REG_PRE(com, r0, r1, r2);               \
    TEST_ASSERT(!IS_TAINTED(&r0, sizeof(int)))

#define CHECK_ALL3(com, r0, r1, r2)            \
    printf("R1 is tainted:\n");                \
    INL_REG(com, r0, r1, r2);                  \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
    INL_REG_PRE(com, r0, r1, r2);              \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int)))
#else
#define CHECK_ALL1(com, r0, r1, r2) \
    printf("Both tainted:\n");      \
    INL_REG(com, r0, r1, r2);       \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int)))

#define CHECK_ALL2(com, r0, r1, r2) \
    printf("Both untainted:\n");    \
    INL_REG(com, r0, r1, r2);       \
    TEST_ASSERT(!IS_TAINTED(&r0, sizeof(int)))

#define CHECK_ALL3(com, r0, r1, r2) \
    printf("R1 is tainted:\n");     \
    INL_REG(com, r0, r1, r2);       \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int)))
#endif

bool test_asm_ldr_reg_ex()
{
    unsigned int A[14] = {0, 1, 2, 3, 4, 5, 6, 7, 8}, v;
    unsigned int **pA = (unsigned int **)&A;
    int reg_offs = 7 * sizeof(int);

    // ------------------------------ 1
    MAKE_TAINTED(A + reg_offs, sizeof(int));
    MAKE_TAINTED(&reg_offs, sizeof(int));

    CHECK_ALL1(ldr, v, pA, reg_offs);
    CHECK_ALL1(ldrb, v, pA, reg_offs);
    CHECK_ALL1(ldrh, v, pA, reg_offs);
    CHECK_ALL1(ldrsb, v, pA, reg_offs);
    CHECK_ALL1(ldrsh, v, pA, reg_offs);

    CLEAR(&reg_offs, sizeof(int));
    CLEAR(A + reg_offs, sizeof(int));

    // ------------------------------ 2
    CHECK_ALL2(ldr, v, pA, reg_offs);
    CHECK_ALL2(ldrb, v, pA, reg_offs);
    CHECK_ALL2(ldrh, v, pA, reg_offs);
    CHECK_ALL2(ldrsb, v, pA, reg_offs);
    CHECK_ALL2(ldrsh, v, pA, reg_offs);

    // ------------------------------ 3
    MAKE_TAINTED(A + reg_offs, sizeof(int));

    CHECK_ALL3(ldr, v, pA, reg_offs);
    CHECK_ALL3(ldrb, v, pA, reg_offs);
    CHECK_ALL3(ldrh, v, pA, reg_offs);
    CHECK_ALL3(ldrsb, v, pA, reg_offs);
    CHECK_ALL3(ldrsh, v, pA, reg_offs);

    return true;
}

#pragma endregion ldr_reg

#pragma region asm_ldrd_imm

#define INL_LDRD(com, r0, r1, r2)             \
                                              \
    printf("Test '" #com " r0, r1, [r2]'\n"); \
    r0 = r1 = 0;                              \
    asm volatile("ldr r2, %2;"                \
                 "" #com " r0, r1, [r2];"     \
                 "str r0, %0;"                \
                 "str r1, %1;"                \
                 : "=m"(r0), "=m"(r1)         \
                 : "m"(r2)                    \
                 : "r0", "r1", "r2")

#define INL_LDRD_I(com, r0, r1, r2)               \
                                                  \
    printf("Test '" #com " r0, r1, [r2, #4]'\n"); \
    r0 = r1 = 0;                                  \
    asm volatile("ldr r2, %2;"                    \
                 "" #com " r0, r1, [r2, #4];"     \
                 "str r0, %0;"                    \
                 "str r1, %1;"                    \
                 : "=m"(r0), "=m"(r1)             \
                 : "m"(r2)                        \
                 : "r0", "r1", "r2")

#ifndef MTHUMB
#define INL_LDRD_I_PRE(com, r0, r1, r2)            \
                                                   \
    printf("Test '" #com " r0, r1, [r2, #4]!'\n"); \
    r0 = r1 = 0;                                   \
    asm volatile("ldr r2, %2;"                     \
                 "" #com " r0, r1, [r2, #4]!;"     \
                 "str r0, %0;"                     \
                 "str r1, %1;"                     \
                 : "=m"(r0), "=m"(r1)              \
                 : "m"(r2)                         \
                 : "r0", "r1", "r2")

#define INL_LDRD_I_POST(com, r0, r1, r2)         \
                                                 \
    printf("Test '" #com " r0, r1, [r2] #4'\n"); \
    r0 = r1 = 0;                                 \
    asm volatile("ldr r2, %2;"                   \
                 "" #com " r0, r1, [r2], #4;"    \
                 "str r0, %0;"                   \
                 "str r1, %1;"                   \
                 : "=m"(r0), "=m"(r1)            \
                 : "m"(r2)                       \
                 : "r0", "r1", "r2")
#endif

#ifndef MTHUMB
#define CHECK_ALL_2R(com, r0, r1, r2)          \
                                               \
    INL_LDRD(com, r0, r1, r2);                 \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
    TEST_ASSERT(IS_TAINTED(&r1, sizeof(int))); \
    printf("r0 = %08X, r1 = %08X\n", r0, r1);  \
                                               \
    INL_LDRD_I(com, r0, r1, r2);               \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
    TEST_ASSERT(IS_TAINTED(&r1, sizeof(int))); \
    printf("r0 = %08X, r1 = %08X\n", r0, r1);  \
                                               \
    INL_LDRD_I_PRE(com, r0, r1, r2);           \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
    TEST_ASSERT(IS_TAINTED(&r1, sizeof(int))); \
    printf("r0 = %08X, r1 = %08X\n", r0, r1);  \
                                               \
    INL_LDRD_I_POST(com, r0, r1, r2);          \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
    TEST_ASSERT(IS_TAINTED(&r1, sizeof(int))); \
    printf("r0 = %08X, r1 = %08X\n", r0, r1)

#else
#define CHECK_ALL_2R(com, r0, r1, r2)          \
                                               \
    INL_LDRD(com, r0, r1, r2);                 \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
    TEST_ASSERT(IS_TAINTED(&r1, sizeof(int))); \
                                               \
    INL_LDRD_I(com, r0, r1, r2);               \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
    TEST_ASSERT(IS_TAINTED(&r1, sizeof(int)))
#endif

#ifndef MTHUMB
#define CHECK_ALL_2R_EX(com, r0, r1, r2)       \
                                               \
    INL_LDRD_I(com, r0, r1, r2);               \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
    TEST_ASSERT(!IS_TAINTED(&r1, sizeof(int)))
#else
#define CHECK_ALL_2R_EX(com, r0, r1, r2)       \
    INL_LDRD_I(com, r0, r1, r2);               \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
    TEST_ASSERT(!IS_TAINTED(&r1, sizeof(int)))
#endif

bool test_asm_ldrd_imm()
/*
    Checks 
    
    ldrd r0, [r]
    ldrd r0, [r1, #imm]
    ldrd r0, [r1, #imm]!
    ldrd r0, [r1], #imm

    where r1 is tainted
    
*/
{
    unsigned int A[3] = {0x12345678, 0x9ABCDEF0, 0x87654321}, v0, v1;
    unsigned int **pA = (unsigned int **)&A;

    MAKE_TAINTED(A, sizeof(A));
    CHECK_ALL_2R(ldrd, v0, v1, pA);

    printf("Extended\n");
    CLEAR(A, sizeof(A));    
    MAKE_TAINTED(&A[1], sizeof(int));
    CHECK_ALL_2R_EX(ldrd, v0, v1, pA);

    return true;
}

bool test_asm_ldrd_reg()
/*
    Checks 
    
    ldrdex r0, [r1]
    
    where r1 is tainted
*/
{
    unsigned int A[2] = {0x12345678, 0x9ABCDEF0}, v0, v1;
    MAKE_TAINTED(A, sizeof(A));

    printf("Test 'ldrexd r0, r1, [r2]'\n");
    asm volatile(
        "mov r2, %2;"
        "ldrexd r0, r1, [r2];"
        "mov %0, r0;"
        "mov %1, r1;"
        : "=r"(v0), "=r"(v1) // out 0 1
        : "r"(A)             // in 2
        : "r0", "r1", "r2");

    printf("r0 = %08X, r1 = %08X\n", v0, v1);
    TEST_ASSERT(IS_TAINTED(&v0, sizeof(int)));
    TEST_ASSERT(IS_TAINTED(&v1, sizeof(int)));

    return true;
}

#ifndef MTHUMB
#define CHECK_ALL__EX(com, r0, r1, r2)       \
                                               \
    INL_LDRD_I(com, r0, r1, r2);               \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
    TEST_ASSERT(!IS_TAINTED(&r1, sizeof(int)))
#else
#define CHECK_ALL_2R_EX(com, r0, r1, r2)       \
    INL_LDRD_I(com, r0, r1, r2);               \
    TEST_ASSERT(IS_TAINTED(&r0, sizeof(int))); \
    TEST_ASSERT(!IS_TAINTED(&r1, sizeof(int)))
#endif

bool test_asm_ldrd_ex()
{
    unsigned int A[3] = {0x12345678, 0x9ABCDEF0}, v0, v1;
    unsigned int **pA = (unsigned int **)&A;

    MAKE_TAINTED(A, sizeof(int));
    CHECK_ALL_2R(ldrd, v0, v1, pA);

    CLEAR(A, sizeof(A));
    MAKE_TAINTED(&A[1], sizeof(int));
    CHECK_ALL_2R_EX(ldrd, v0, v1, pA);

    return true;
}

#pragma endregion ldrd_imm

#pragma region asm_ldm

#define INL_LDM(com, v1, v2, v3, v4, addr)                \
    v1 = v2 = v3 = v4 = 0;                                \
    printf("Test '" #com " r0, {r1, r2, r3, r4}'\n");     \
                                                          \
    asm volatile("mov r0, %4;"                            \
                 "" #com " r0, {r1, r2, r3, r4};"         \
                 "str r1, %0;"                            \
                 "str r2, %1;"                            \
                 "str r3, %2;"                            \
                 "str r4, %3;"                            \
                                                          \
                 : "=m"(v1), "=m"(v2), "=m"(v3), "=m"(v4) \
                 : "r"(addr)                              \
                 : "r0", "r1", "r2", "r3", "r4")

#define CHECK_LDM(com, v1, v2, v3, v4, addr)       \
                                                   \
    INL_LDM(com, v1, v2, v3, v4, addr);            \
    printf("r1 = %d, r2 = %d, r3 = %d, r4 = %d\n", \
           v1, v2, v3, v4);                        \
    TEST_ASSERT(IS_TAINTED(&v1, sizeof(int)));     \
    TEST_ASSERT(IS_TAINTED(&v2, sizeof(int)));     \
    TEST_ASSERT(IS_TAINTED(&v3, sizeof(int)));     \
    TEST_ASSERT(IS_TAINTED(&v4, sizeof(int)))

bool test_asm_ldm()
{
    int A[] = {1, 2, 3, 4};
    int val1, val2, val3, val4;
    MAKE_TAINTED(A, sizeof(A));

    CHECK_LDM(ldmia, val1, val2, val3, val4, A);
    CHECK_LDM(ldmdb, val1, val2, val3, val4, A + 4);

#ifndef MTHUMB
    CHECK_LDM(ldmib, val1, val2, val3, val4, A - 1);
    CHECK_LDM(ldmda, val1, val2, val3, val4, A + 3);
#endif

    return true;
}

#define INL_LDM_W(com, v1, v2, v3, v4, addr)              \
    v1 = v2 = v3 = v4 = 0;                                \
    printf("Test '" #com " r0!, {r1, r2, r3, r4}'\n");    \
                                                          \
    asm volatile("mov r0, %4;"                            \
                 "" #com " r0!, {r1, r2, r3, r4};"        \
                 "str r1, %0;"                            \
                 "str r2, %1;"                            \
                 "str r3, %2;"                            \
                 "str r4, %3;"                            \
                                                          \
                 : "=m"(v1), "=m"(v2), "=m"(v3), "=m"(v4) \
                 : "r"(addr)                              \
                 : "r0", "r1", "r2", "r3", "r4")

#define CHECK_LDM_W(com, v1, v2, v3, v4, addr)     \
                                                   \
    INL_LDM_W(com, v1, v2, v3, v4, addr);          \
    printf("r1 = %d, r2 = %d, r3 = %d, r4 = %d\n", \
           v1, v2, v3, v4);                        \
    TEST_ASSERT(IS_TAINTED(&v1, sizeof(int)));     \
    TEST_ASSERT(IS_TAINTED(&v2, sizeof(int)));     \
    TEST_ASSERT(IS_TAINTED(&v3, sizeof(int)));     \
    TEST_ASSERT(IS_TAINTED(&v4, sizeof(int)))

bool test_asm_ldm_w()
{
    int A[] = {1, 2, 3, 4};
    int val1, val2, val3, val4;

    MAKE_TAINTED(A, sizeof(A));

    int *p1 = (int *)A;
    int *p2 = (int *)(A + 4);
    CHECK_LDM_W(ldmia, val1, val2, val3, val4, p1);
    CHECK_LDM_W(ldmdb, val1, val2, val3, val4, p2);

#ifndef MTHUMB
    int *p3 = (int *)(A - 1);
    int *p4 = (int *)(A + 3);
    CHECK_LDM_W(ldmib, val1, val2, val3, val4, p3);
    CHECK_LDM_W(ldmda, val1, val2, val3, val4, p4);
#endif

    return true;
}

/*

printf("r1 = %d, r2 = %d, r3 = %d, r4 = %d\n", \
           v1, v2, v3, v4);                        \
    printf("%d", IS_TAINTED(&v1, sizeof(int)));    \
    printf("%d", !IS_TAINTED(&v2, sizeof(int)));   \
    printf("%d", IS_TAINTED(&v3, sizeof(int)));    \
    printf("%d", !IS_TAINTED(&v4, sizeof(int)));   \
    printf("\n");                                  \

*/

#define CHECK_LDM_EX(com, v1, v2, v3, v4, addr)    \
                                                   \
    INL_LDM(com, v1, v2, v3, v4, addr);            \
    printf("r1 = %d, r2 = %d, r3 = %d, r4 = %d\n", \
           v1, v2, v3, v4);                        \
    TEST_ASSERT(IS_TAINTED(&v1, sizeof(int)));     \
    TEST_ASSERT(!IS_TAINTED(&v2, sizeof(int)));    \
    TEST_ASSERT(IS_TAINTED(&v3, sizeof(int)));     \
    TEST_ASSERT(!IS_TAINTED(&v4, sizeof(int)))

bool test_asm_ldm_ex()
{
    int A[] = {1, 2, 3, 4};
    int val1, val2, val3, val4;
    MAKE_TAINTED(&A[0], sizeof(int));
    MAKE_TAINTED(&A[2], sizeof(int));

    CHECK_LDM_EX(ldmia, val1, val2, val3, val4, A);
    CHECK_LDM_EX(ldmdb, val1, val2, val3, val4, A + 4);

#ifndef MTHUMB
    CHECK_LDM_EX(ldmib, val1, val2, val3, val4, A - 1);
    CHECK_LDM_EX(ldmda, val1, val2, val3, val4, A + 3);
#endif

    return true;
}

#define CHECK_LDM_EX_W(com, v1, v2, v3, v4, addr)  \
                                                   \
    INL_LDM_W(com, v1, v2, v3, v4, addr);          \
    printf("r1 = %d, r2 = %d, r3 = %d, r4 = %d\n", \
           v1, v2, v3, v4);                        \
    TEST_ASSERT(IS_TAINTED(&v1, sizeof(int)));     \
    TEST_ASSERT(!IS_TAINTED(&v2, sizeof(int)));    \
    TEST_ASSERT(IS_TAINTED(&v3, sizeof(int)));     \
    TEST_ASSERT(!IS_TAINTED(&v4, sizeof(int)))

bool test_asm_ldm_ex_w()
{
    int A[] = {1, 2, 3, 4};
    int val1, val2, val3, val4;

    MAKE_TAINTED(&A[0], sizeof(int));
    MAKE_TAINTED(&A[2], sizeof(int));

    int *p1 = (int *)A;
    int *p2 = (int *)(A + 4);
    CHECK_LDM_EX_W(ldmia, val1, val2, val3, val4, p1);
    CHECK_LDM_EX_W(ldmdb, val1, val2, val3, val4, p2);

#ifndef MTHUMB
    int *p3 = (int *)(A - 1);
    int *p4 = (int *)(A + 3);
    CHECK_LDM_EX_W(ldmib, val1, val2, val3, val4, p3);
    CHECK_LDM_EX_W(ldmda, val1, val2, val3, val4, p4);
#endif

    return true;
}

#pragma endregion asm_ldm

#pragma region asm_str_imm

#define INL_STR(com, r0, base)            \
    base[0] = 0;                          \
    base[1] = 0;                          \
    printf("Test '" #com " r0, [r1]'\n"); \
                                          \
    asm volatile("ldr r0, %0;"            \
                 "mov r1, %1;"            \
                 "" #com " r0, [r1];"     \
                 :                        \
                 : "m"(r0), "r"(base)     \
                 : "r0", "r1")

#define INL_STR_IMM(com, r0, base)            \
    base[0] = 0;                              \
    base[1] = 0;                              \
    printf("Test '" #com " r0, [r1, #4]'\n"); \
                                              \
    asm volatile("ldr r0, %0;"                \
                 "mov r1, %1;"                \
                 "" #com " r0, [r1, #4];"     \
                 :                            \
                 : "m"(r0), "r"(base)         \
                 : "r0", "r1")

#ifndef MTHUMB
#define INL_STR_IMM_PRE(com, r0, base)         \
    base[0] = 0;                               \
    base[1] = 0;                               \
    printf("Test '" #com " r0, [r1, #4]!'\n"); \
                                               \
    asm volatile("ldr r0, %0;"                 \
                 "mov r1, %1;"                 \
                 "" #com " r0, [r1, #4]!;"     \
                 :                             \
                 : "m"(r0), "r"(base)          \
                 : "r0", "r1")

#define INL_STR_IMM_POST(com, r0, base)       \
    base[0] = 0;                              \
    base[1] = 0;                              \
    printf("Test '" #com " r0, [r1], #4'\n"); \
                                              \
    asm volatile("ldr r0, %0;"                \
                 "mov r1, %1;"                \
                 "" #com " r0, [r1], #4;"     \
                 :                            \
                 : "m"(r0), "r"(base)         \
                 : "r0", "r1")
#endif

#ifndef MTHUMB
#define CHECK_S_ALL_IMM(com, r0, base)              \
    INL_STR(com, r0, base);                         \
    printf("%d %d\n", base[0], base[1]);            \
    TEST_ASSERT(IS_TAINTED(&base[0], sizeof(int))); \
                                                    \
    INL_STR_IMM(com, r0, base);                     \
    printf("%d %d\n", base[0], base[1]);            \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int))); \
                                                    \
    INL_STR_IMM_PRE(com, r0, base);                 \
    printf("%d %d\n", base[0], base[1]);            \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int))); \
                                                    \
    INL_STR_IMM_POST(com, r0, base);                \
    printf("%d %d\n", base[0], base[1]);            \
    TEST_ASSERT(IS_TAINTED(&base[0], sizeof(int)))
#else
#define CHECK_S_ALL_IMM(com, r0, base)              \
    INL_STR(com, r0, base);                         \
    printf("%d %d\n", base[0], base[1]);            \
    TEST_ASSERT(IS_TAINTED(&base[0], sizeof(int))); \
                                                    \
    INL_STR_IMM(com, r0, base);                     \
    printf("%d %d\n", base[0], base[1]);            \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int)))
#endif

bool test_asm_str_imm()
{
    int A[2] = {0}, v = 1;
    MAKE_TAINTED(&v, sizeof(int));

#ifdef MTHUMB
    CHECK_S_ALL_IMM(strt, v, A);
    CHECK_S_ALL_IMM(strbt, v, A);
    CHECK_S_ALL_IMM(strht, v, A);
#endif

    CHECK_S_ALL_IMM(str, v, A);
    CHECK_S_ALL_IMM(strb, v, A);
    CHECK_S_ALL_IMM(strh, v, A);

    return true;
}

#define INL_STREX(com, rd, r0, base)          \
    base[0] = 0;                              \
    base[1] = 0;                              \
    printf("Test '" #com " rd, r2, [r1]'\n"); \
                                              \
    asm volatile("ldr r2, %1;"                \
                 "mov r1, %2;"                \
                 "" #com " r0, r2, [r1];"     \
                 "str r0, %0;"                \
                 : "=m"(rd)                   \
                 : "m"(r0), "r"(base)         \
                 : "r0", "r1", "r2")

#define CHECK_STREX(com, rd, r0, base)              \
    INL_STREX(com, rd, r0, base);                   \
    printf("%d %d\n", base[0], base[1]);            \
    TEST_ASSERT(IS_TAINTED(&base[0], sizeof(int))); \
    TEST_ASSERT(!IS_TAINTED(&rd, sizeof(int)))

bool test_asm_strex()
{
    int A[2] = {0}, v = 1, r = 0;
    MAKE_TAINTED(&v, sizeof(int));
    MAKE_TAINTED(&r, sizeof(int));

    CHECK_STREX(strex, r, v, A);
    CHECK_STREX(strexb, r, v, A);
    CHECK_STREX(strexh, r, v, A);

    return true;
}

#pragma endregion asm_str_imm

#pragma region asm_str_reg

#define INL_STR_REG(com, r0, base, roffs)         \
    base[0] = 0;                                  \
    base[1] = 0;                                  \
    printf("Test '" #com " r0, [r1, r2]'\n");     \
                                                  \
    asm volatile("ldr r0, %0;"                    \
                 "mov r1, %1;"                    \
                 "ldr r2, %2;"                    \
                 "" #com " r0, [r1, r2];"         \
                 :                                \
                 : "m"(r0), "r"(base), "m"(roffs) \
                 : "r0", "r1", "r2")

#ifndef MTHUMB
#define INL_STR_REG_PRE(com, r0, base, roffs)     \
    base[0] = 0;                                  \
    base[1] = 0;                                  \
    printf("Test '" #com " r0, [r1, r2]!'\n");    \
                                                  \
    asm volatile("ldr r0, %0;"                    \
                 "mov r1, %1;"                    \
                 "ldr r2, %2;"                    \
                 "" #com " r0, [r1, r2]!;"        \
                 :                                \
                 : "m"(r0), "r"(base), "m"(roffs) \
                 : "r0", "r1", "r2")

#define INL_STR_REG_POST(com, r0, base, roffs)    \
    base[0] = 0;                                  \
    base[1] = 0;                                  \
    printf("Test '" #com " r0, [r1], r2'\n");     \
                                                  \
    asm volatile("ldr r0, %0;"                    \
                 "mov r1, %1;"                    \
                 "ldr r2, %2;"                    \
                 "" #com " r0, [r1], r2;"         \
                 :                                \
                 : "m"(r0), "r"(base), "m"(roffs) \
                 : "r0", "r1", "r2")

#endif

#ifndef MTHUMB
#define CHECK_S_ALL_REG(com, r0, base, roffs)       \
    INL_STR_REG(com, r0, base, roffs);              \
    printf("%d %d\n", base[0], base[1]);            \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int))); \
                                                    \
    INL_STR_REG_PRE(com, r0, base, roffs);          \
    printf("%d %d\n", base[0], base[1]);            \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int))); \
                                                    \
    INL_STR_REG_POST(com, r0, base, roffs);         \
    printf("%d %d\n", base[0], base[1]);            \
    TEST_ASSERT(IS_TAINTED(&base[0], sizeof(int)))
#else
#define CHECK_S_ALL_REG(com, r0, base, roffs) \
    INL_STR_REG(com, r0, base, roffs);        \
    printf("%d %d\n", base[0], base[1]);      \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int)))
#endif

bool test_asm_str_reg()
{
    int A[2] = {0}, v = 1, r = 4;
    MAKE_TAINTED(&v, sizeof(int));

    CHECK_S_ALL_REG(str, v, A, r);
    CHECK_S_ALL_REG(strb, v, A, r);
    CHECK_S_ALL_REG(strh, v, A, r);

    return true;
}

#pragma endregion asm_str_reg

#pragma region asm_strd

#define INL_STRD(com, r0, r1, base)            \
    base[0] = base[1] = base[2] = 0;           \
    printf("Test '" #com " r0, r1, [r2]'\n");  \
    asm volatile("ldr r0, %0;"                 \
                 "ldr r1, %1;"                 \
                 "mov r2, %2;"                 \
                 "" #com " r0, r1, [r2];"      \
                 :                             \
                 : "m"(r0), "m"(r1), "r"(base) \
                 : "r0", "r1", "r2")

#define INL_STRD_IMM(com, r0, r1, base)           \
    base[0] = base[1] = base[2] = 0;              \
    printf("Test '" #com " r0, r1, [r2, #4]'\n"); \
    asm volatile("ldr r0, %0;"                    \
                 "ldr r1, %1;"                    \
                 "mov r2, %2;"                    \
                 "" #com " r0, r1, [r2, #4];"     \
                 :                                \
                 : "m"(r0), "m"(r1), "r"(base)    \
                 : "r0", "r1", "r2")

#ifndef MTHUMB
#define INL_STRD_IMM_PRE(com, r0, r1, base)        \
    base[0] = base[1] = base[2] = 0;               \
    printf("Test '" #com " r0, r1, [r2, #4]!'\n"); \
    asm volatile("ldr r0, %0;"                     \
                 "ldr r1, %1;"                     \
                 "mov r2, %2;"                     \
                 "" #com " r0, r1, [r2, #4]!;"     \
                 :                                 \
                 : "m"(r0), "m"(r1), "r"(base)     \
                 : "r0", "r1", "r2")

#define INL_STRD_IMM_POST(com, r0, r1, base)      \
    base[0] = base[1] = base[2] = 0;              \
    printf("Test '" #com " r0, r1, [r2], #4'\n"); \
    asm volatile("ldr r0, %0;"                    \
                 "ldr r1, %1;"                    \
                 "mov r2, %2;"                    \
                 "" #com " r0, r1, [r2], #4;"     \
                 :                                \
                 : "m"(r0), "m"(r1), "r"(base)    \
                 : "r0", "r1", "r2")
#endif

#ifndef MTHUMB
#define CHECK_SD_ALL_IMM(com, r0, r1, base)          \
    INL_STRD(com, r0, r1, base);                     \
    printf("%d %d %d\n", base[0], base[1], base[2]); \
    TEST_ASSERT(IS_TAINTED(&base[0], sizeof(int)));  \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int)));  \
                                                     \
    INL_STRD_IMM(com, r0, r1, base);                 \
    printf("%d %d %d\n", base[0], base[1], base[2]); \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int)));  \
    TEST_ASSERT(IS_TAINTED(&base[2], sizeof(int)));  \
                                                     \
    INL_STRD_IMM_PRE(com, r0, r1, base);             \
    printf("%d %d %d\n", base[0], base[1], base[2]); \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int)));  \
    TEST_ASSERT(IS_TAINTED(&base[2], sizeof(int)));  \
                                                     \
    INL_STRD_IMM_POST(com, r0, r1, base);            \
    printf("%d %d %d\n", base[0], base[1], base[2]); \
    TEST_ASSERT(IS_TAINTED(&base[0], sizeof(int)));  \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int)))
#else
#define CHECK_SD_ALL_IMM(com, r0, r1, base)          \
    INL_STRD(com, r0, r1, base);                     \
    printf("%d %d %d\n", base[0], base[1], base[2]); \
    TEST_ASSERT(IS_TAINTED(&base[0], sizeof(int)));  \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int)));  \
                                                     \
    INL_STRD_IMM(com, r0, r1, base);                 \
    printf("%d %d %d\n", base[0], base[1], base[2]); \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int)));  \
    TEST_ASSERT(IS_TAINTED(&base[2], sizeof(int)))
#endif

bool test_asm_strd_imm()
{
    int A[3] = {0}, v1 = 1, v2 = 2;
    MAKE_TAINTED(&v1, sizeof(int));
    MAKE_TAINTED(&v2, sizeof(int));
    CHECK_SD_ALL_IMM(strd, v1, v2, A);

    return true;
}

#define INL_STRD_REG(com, r0, r1, base)           \
    base[0] = base[1] = base[2] = 0;              \
    printf("Test '" #com " r0, r1, [r2, r3]'\n"); \
    asm volatile("ldr r0, %0;"                    \
                 "ldr r1, %1;"                    \
                 "mov r2, %2;"                    \
                 "mov r3, #4;"                    \
                 "" #com " r0, r1, [r2, r3];"     \
                 :                                \
                 : "m"(r0), "m"(r1), "r"(base)    \
                 : "r0", "r1", "r2", "r3")

#ifndef MTHUMB
#define INL_STRD_REG_PRE(com, r0, r1, base)        \
    base[0] = base[1] = base[2] = 0;               \
    printf("Test '" #com " r0, r1, [r2, r3]!'\n"); \
    asm volatile("ldr r0, %0;"                     \
                 "ldr r1, %1;"                     \
                 "mov r2, %2;"                     \
                 "mov r3, #4;"                     \
                 "" #com " r0, r1, [r2, r3]!;"     \
                 :                                 \
                 : "m"(r0), "m"(r1), "r"(base)     \
                 : "r0", "r1", "r2", "r3")

#define INL_STRD_REG_POST(com, r0, r1, base)      \
    base[0] = base[1] = base[2] = 0;              \
    printf("Test '" #com " r0, r1, [r2], r3'\n"); \
    asm volatile("ldr r0, %0;"                    \
                 "ldr r1, %1;"                    \
                 "mov r2, %2;"                    \
                 "mov r3, #4;"                    \
                 "" #com " r0, r1, [r2], r3;"     \
                 :                                \
                 : "m"(r0), "m"(r1), "r"(base)    \
                 : "r0", "r1", "r2", "r3")
#endif

#ifndef MTHUMB
#define CHECK_SD_ALL_REG(com, r0, r1, base)          \
                                                     \
    INL_STRD_REG(com, r0, r1, base);                 \
    printf("%d %d %d\n", base[0], base[1], base[2]); \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int)));  \
    TEST_ASSERT(IS_TAINTED(&base[2], sizeof(int)));  \
                                                     \
    INL_STRD_REG_PRE(com, r0, r1, base);             \
    printf("%d %d %d\n", base[0], base[1], base[2]); \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int)));  \
    TEST_ASSERT(IS_TAINTED(&base[2], sizeof(int)));  \
                                                     \
    INL_STRD_REG_POST(com, r0, r1, base);            \
    printf("%d %d %d\n", base[0], base[1], base[2]); \
    TEST_ASSERT(IS_TAINTED(&base[0], sizeof(int)));  \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int)))
#else
#define CHECK_SD_ALL_REG(com, r0, r1, base)          \
                                                     \
    INL_STRD_REG(com, r0, r1, base);                 \
    printf("%d %d %d\n", base[0], base[1], base[2]); \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int)));  \
    TEST_ASSERT(IS_TAINTED(&base[2], sizeof(int)))
#endif

bool test_asm_strd_reg()
{
    int A[3] = {0}, v1 = 1, v2 = 2;
    MAKE_TAINTED(&v1, sizeof(int));
    MAKE_TAINTED(&v2, sizeof(int));
    CHECK_SD_ALL_REG(strd, v1, v2, A);

    return true;
}

#define INL_STREXD(com, r0, r1, r2, base)               \
    base[0] = base[1] = 0;                              \
    printf("Test '" #com " r2, r0, r1, [r3]'\n");       \
    asm volatile("ldr r6, %1;"                          \
                 "ldr r0, %2;"                          \
                 "ldr r1, %3;"                          \
                 "mov r3, %4;"                          \
                 "" #com " r6, r0, r1, [r3];"           \
                 "str r2, %0;"                          \
                 : "=m"(r0)                             \
                 : "m"(r0), "m"(r1), "m"(r2), "r"(base) \
                 : "r0", "r1", "r2", "r3")

#define CHECK_STREXD(com, r0, r1, r2, base)         \
    INL_STREXD(com, r0, r1, r2, base);              \
    printf("%d %d %d\n", r0, base[0], base[1]);     \
    TEST_ASSERT(IS_TAINTED(&base[0], sizeof(int))); \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int))); \
    TEST_ASSERT(!IS_TAINTED(&r0, sizeof(int)))

bool test_asm_strexd()
{
    int A[2] = {0};
    int v1 = 1, v2 = 2, v3 = 3;
    MAKE_TAINTED(&v1, sizeof(int));
    MAKE_TAINTED(&v2, sizeof(int));
    MAKE_TAINTED(&v3, sizeof(int));

    CHECK_STREXD(strexd, v1, v2, v3, A);
    return true;
}

#pragma endregion asm_strd

#pragma region asm_stmd

#pragma endregion asm_stmd

#pragma region asm_stm

#define INL_STM(com, v1, v2, v3, v4, base, offs, base_sz)                 \
                                                                          \
    CLEAR(base, base_sz);                                                 \
    printf("Test '" #com " r0, {r1, r2, r3, r4}'\n");                     \
                                                                          \
    asm volatile("mov r0, %0;"                                            \
                 "ldr r1, %1;"                                            \
                 "ldr r2, %2;"                                            \
                 "ldr r3, %3;"                                            \
                 "ldr r4, %4;"                                            \
                 "" #com " r0, {r1, r2, r3, r4};"                         \
                 :                                                        \
                 : "r"(base + (offs)), "m"(v1), "m"(v2), "m"(v3), "m"(v4) \
                 : "r0", "r1", "r2", "r3", "r4")

#define CHECK_STM(com, v1, v2, v3, v4, base, offs, base_sz) \
    INL_STM(com, v1, v2, v3, v4, base, offs, base_sz);      \
    printf("%d %d %d %d\n",                                 \
           base[0], base[1], base[2], base[3]);             \
    TEST_ASSERT(IS_TAINTED(base, base_sz))

bool test_asm_stm()
{
    int A[4] = {0};
    int v1 = 1, v2 = 2, v3 = 3, v4 = 4;
    MAKE_TAINTED(&v1, sizeof(int));
    MAKE_TAINTED(&v2, sizeof(int));
    MAKE_TAINTED(&v3, sizeof(int));
    MAKE_TAINTED(&v4, sizeof(int));

    CHECK_STM(stmia, v1, v2, v3, v4, A, 0, sizeof(A));
    CHECK_STM(stmdb, v1, v2, v3, v4, A, 4, sizeof(A));

#ifndef MTHUMB
    CHECK_STM(stmib, v1, v2, v3, v4, A, -1, sizeof(A));
    CHECK_STM(stmda, v1, v2, v3, v4, A, 3, sizeof(A));
#endif

    return true;
}

#define INL_STM_W(com, v1, v2, v3, v4, base, offs, base_sz)               \
                                                                          \
    CLEAR(base, base_sz);                                                 \
    printf("Test '" #com " r0!, {r1, r2, r3, r4}'\n");                    \
                                                                          \
    asm volatile("mov r0, %0;"                                            \
                 "ldr r1, %1;"                                            \
                 "ldr r2, %2;"                                            \
                 "ldr r3, %3;"                                            \
                 "ldr r4, %4;"                                            \
                 "" #com " r0!, {r1, r2, r3, r4};"                        \
                 :                                                        \
                 : "r"(base + (offs)), "m"(v1), "m"(v2), "m"(v3), "m"(v4) \
                 : "r0", "r1", "r2", "r3", "r4")

#define CHECK_STM_W(com, v1, v2, v3, v4, base, tmp_ptr, offs, base_sz) \
    tmp_ptr = (int *)base;                                             \
    INL_STM_W(com, v1, v2, v3, v4, tmp_ptr, offs, base_sz);            \
    printf("%d %d %d %d\n",                                            \
           base[0], base[1], base[2], base[3]);                        \
    TEST_ASSERT(IS_TAINTED(base, base_sz))

bool test_asm_stm_w()
{
    int A[4] = {0};
    int v1 = 1, v2 = 2, v3 = 3, v4 = 4;
    int *p1, *p2;

    MAKE_TAINTED(&v1, sizeof(int));
    MAKE_TAINTED(&v2, sizeof(int));
    MAKE_TAINTED(&v3, sizeof(int));
    MAKE_TAINTED(&v4, sizeof(int));

    CHECK_STM_W(stmia, v1, v2, v3, v4, A, p1, 0, sizeof(A));
    CHECK_STM_W(stmdb, v1, v2, v3, v4, A, p2, 4, sizeof(A));

#ifndef MTHUMB
    int *p3, *p4;
    CHECK_STM_W(stmib, v1, v2, v3, v4, A, p3, -1, sizeof(A));
    CHECK_STM_W(stmda, v1, v2, v3, v4, A, p4, 3, sizeof(A));
#endif

    return true;
}

#define CHECK_STM_EX(com, v1, v2, v3, v4, base, offs, base_sz) \
    INL_STM_W(com, v1, v2, v3, v4, base, offs, base_sz);       \
    printf("%d %d %d %d\n",                                    \
           base[0], base[1], base[2], base[3]);                \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int)));            \
    TEST_ASSERT(IS_TAINTED(&base[3], sizeof(int)))

bool test_asm_stm_ex()
{
    int A[4] = {0};
    int v1 = 0, v2 = 1, v3 = 0, v4 = 1;

    MAKE_TAINTED(&v2, sizeof(int));
    MAKE_TAINTED(&v4, sizeof(int));

    CHECK_STM_EX(stmia, v1, v2, v3, v4, A, 0, sizeof(A));
    CHECK_STM_EX(stmdb, v1, v2, v3, v4, A, 4, sizeof(A));

#ifndef MTHUMB
    CHECK_STM_EX(stmib, v1, v2, v3, v4, A, -1, sizeof(A));
    CHECK_STM_EX(stmda, v1, v2, v3, v4, A, 3, sizeof(A));
#endif

    return true;
}

#define CHECK_STM_EX_W(com, v1, v2, v3, v4, base, tmp_ptr, offs, base_sz) \
    tmp_ptr = (int *)base;                                                \
    INL_STM_W(com, v1, v2, v3, v4, tmp_ptr, offs, base_sz);               \
    printf("%d %d %d %d\n",                                               \
           base[0], base[1], base[2], base[3]);                           \
    TEST_ASSERT(IS_TAINTED(&base[1], sizeof(int)));                       \
    TEST_ASSERT(IS_TAINTED(&base[3], sizeof(int)))

bool test_asm_stm_ex_w()
{
    int A[4] = {0};
    int v1 = 0, v2 = 1, v3 = 0, v4 = 1;
    int *p1, *p2;

    MAKE_TAINTED(&v2, sizeof(int));
    MAKE_TAINTED(&v4, sizeof(int));

    CHECK_STM_EX_W(stmia, v1, v2, v3, v4, A, p1, 0, sizeof(A));
    CHECK_STM_EX_W(stmdb, v1, v2, v3, v4, A, p2, 4, sizeof(A));

#ifndef MTHUMB
    int *p3, *p4;
    CHECK_STM_EX_W(stmib, v1, v2, v3, v4, A, p3, -1, sizeof(A));
    CHECK_STM_EX_W(stmda, v1, v2, v3, v4, A, p4, 3, sizeof(A));
#endif

    return true;
}

#pragma endregion asm_stm
