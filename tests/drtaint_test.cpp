#include "drtaint_test.h"

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <map>

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
    the data was tracked or not.
*/

std::map<std::string, testfunc> gTestfunc_table = {

    {"simple", test_simple},
    {"arith", test_arith},
    {"assign", test_assign},
    {"bitwise", test_bitwise},
    {"struct", test_struct},
    {"func_call", test_func_call},
    {"array", test_array},
    {"condex_op", test_condex_op},
    {"assign_ex", test_assign_ex},
    {"untaint", test_untaint},
    {"ldr", test_asm_check_ldr},
    {"ldrd", test_asm_check_ldrd},
    {"ldm", test_asm_check_ldm},
    {"asm", test_asm},

};

void usage()
{
    printf("Usage:\n");
    printf("Run tests: file.exe <test1> <test2> ...\n");
    printf("Run all tests: file.exe --all\n");
    printf("Show all tests: file.exe --show\n");
}

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

    try
    {
        bool passed;
        for (int i = 1; i < argc; i++)
        {
            if (gTestfunc_table.find(argv[i]) == gTestfunc_table.end())
                throw std::runtime_error(
                    "Test " + std::string(argv[i]) + " not found");

            printf("\n\n--- Running test %s--- \n\n", argv[i]);

            passed = gTestfunc_table[argv[i]]();
            printf("Test %s is %s\n", argv[i],
                   passed ? "passed" : "failed");

            passed ? count_passed++ : count_failed++;
        }
    }

    catch (std::runtime_error e)
    {
        printf("Runtime error occured: %s\n\n", e.what());
    }
    catch (...)
    {
        printf("Unknown error occured\n\n");
    }

    printf("\nResults: passed - %d, failed - %d\nExitting...\n",
           count_passed, count_failed);

    return 0;
}

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

void run_all_tests()
{
    int count_failed = 0, count_passed = 0;

    try
    {
        bool passed;
        for (const auto &elem : gTestfunc_table)
        {
            printf("\n\n--- Running test %s ---\n\n", elem.first.c_str());

            passed = elem.second();
            printf("Test %s is %s\n", elem.first.c_str(),
                   passed ? "passed" : "failed");

            passed ? count_passed++ : count_failed++;
        }
    }

    catch (std::runtime_error e)
    {
        printf("Runtime error occured: %s\n\n", e.what());
    }
    catch (...)
    {
        printf("Unknown error occured\n\n");
    }

    printf("\nResults: passed - %d, failed - %d\nExitting...\n",
           count_passed, count_failed);
}

void show_all_tests()
{
    int i = 1;

    printf("Available tests:\n");

    for (const auto &elem : gTestfunc_table)
        printf("  %-3d %s\n", i++, elem.first.c_str());
}

bool test_assign()
{
    int x = 0, y = 0, z = 0;
    MAKE_TAINTED(&x, sizeof(int));

    y = x;
    TEST_ASSSERT(IS_TAINTED(&y, sizeof(int)));

    z = y;
    TEST_ASSSERT(IS_TAINTED(&z, sizeof(int)));

    x = 0;
    TEST_ASSSERT(!IS_TAINTED(&x, sizeof(int)));

    return true;
}

bool test_assign_ex()
{
    int x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, y;
    x1 = x2 = x3 = x4 = x5 = x6 = x7 = x8 = x9 = x10 = x11 = y = 1;

    MAKE_TAINTED(&y, sizeof(int));

    // some of operations require conditional execution
    TEST_ASSSERT(IS_TAINTED(&(x1 = y), sizeof(int)));
    TEST_ASSSERT(IS_TAINTED(&(x2 += y), sizeof(int)));
    TEST_ASSSERT(IS_TAINTED(&(x3 -= y), sizeof(int)));
    TEST_ASSSERT(IS_TAINTED(&(x4 *= y), sizeof(int)));
    TEST_ASSSERT(IS_TAINTED(&(x5 /= y), sizeof(int)));
    TEST_ASSSERT(IS_TAINTED(&(x6 %= y), sizeof(int)));
    TEST_ASSSERT(IS_TAINTED(&(x7 <<= y), sizeof(int)));
    TEST_ASSSERT(IS_TAINTED(&(x8 >>= y), sizeof(int)));
    TEST_ASSSERT(IS_TAINTED(&(x9 &= y), sizeof(int)));
    TEST_ASSSERT(IS_TAINTED(&(x10 ^= y), sizeof(int)));
    TEST_ASSSERT(IS_TAINTED(&(x11 |= y), sizeof(int)));

    return true;
}

bool test_arith()
{
    int x1, x2, x3, y = 23, z = 5;
    MAKE_TAINTED(&z, sizeof(int));

    x1 = y + z;
    TEST_ASSSERT(IS_TAINTED(&x1, sizeof(int)));

    x2 = y * z;
    TEST_ASSSERT(IS_TAINTED(&x2, sizeof(int)));

    /* sdiv and udiv instructions are unsupported here
    functions __aeabi_idiv(PLT), __aeabi_udiv(PLT) are used instead.
    These functions require conditional execution 
    so division will be considered in another test */

    x3 = y - z;
    TEST_ASSSERT(IS_TAINTED(&x3, sizeof(int)));

    x1++;
    TEST_ASSSERT(IS_TAINTED(&x1, sizeof(int)));

    x1--;
    TEST_ASSSERT(IS_TAINTED(&x1, sizeof(int)));

    return true;
}

bool test_bitwise()
{
    int x1, x2, x3, x4, x5, x6, y = 23, z = 5;
    MAKE_TAINTED(&z, sizeof(int));

    x1 = y | z;
    TEST_ASSSERT(IS_TAINTED(&x1, sizeof(int)));

    x2 = y & z;
    TEST_ASSSERT(IS_TAINTED(&x2, sizeof(int)));

    x3 = y ^ z;
    TEST_ASSSERT(IS_TAINTED(&x3, sizeof(int)));

    x4 = y >> z;
    TEST_ASSSERT(IS_TAINTED(&x4, sizeof(int)));

    x5 = y << z;
    TEST_ASSSERT(IS_TAINTED(&x5, sizeof(int)));

    x6 = ~z;
    TEST_ASSSERT(IS_TAINTED(&x6, sizeof(int)));

    return true;
}

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

    TEST_ASSSERT(IS_TAINTED(s.p, sizeof(p0)));
    TEST_ASSSERT(IS_TAINTED(&s.x, sizeof(int)));

    char *p1;
    int x1;

    p1 = s.p;
    x1 = s.x;

    TEST_ASSSERT(IS_TAINTED(p1, sizeof(p0)));
    TEST_ASSSERT(IS_TAINTED(&x1, sizeof(int)));

    return true;
}

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

    TEST_ASSSERT(b);
    TEST_ASSSERT(IS_TAINTED(dst2, sizeof(src1)));

    int C[2] = {1, 2};
    int D[2] = {0};

    MAKE_TAINTED(&C[0], sizeof(int));
    D[1] = C[0];

    TEST_ASSSERT(IS_TAINTED(&D[1], sizeof(int)));
    TEST_ASSSERT(!IS_TAINTED(&D[0], sizeof(int)));

    int A[2][2] = {{1, 2}, {3, 4}};
    int B[2][2] = {0};

    MAKE_TAINTED(&A[1][1], sizeof(int));
    B[0][0] = A[1][1];
    B[0][1] = A[1][1];

    TEST_ASSSERT(IS_TAINTED(&B[0][0], sizeof(int)));
    TEST_ASSSERT(IS_TAINTED(&B[0][1], sizeof(int)));
    TEST_ASSSERT(!IS_TAINTED(&B[1][1], sizeof(int)));
    TEST_ASSSERT(!IS_TAINTED(&B[1][0], sizeof(int)));

    return true;
}

static int cube_cp(int x)
{
    return x * x * x;
}

bool test_func_call()
{
    int x = 3, y;
    MAKE_TAINTED(&x, sizeof(int));

    y = cube_cp(x);
    TEST_ASSSERT(IS_TAINTED(&y, sizeof(int)));
    return true;
}

bool test_condex_op()
/*
    Test operations which reqire conditional execution
*/
{
    int x1, x2, x3, x4, x5, y = 23, z = 5;
    MAKE_TAINTED(&z, sizeof(int));

    x1 = y || z;
    TEST_ASSSERT(IS_TAINTED(&x1, sizeof(int)));

    x2 = y && z;
    TEST_ASSSERT(IS_TAINTED(&x2, sizeof(int)));

    x5 = !z;
    TEST_ASSSERT(IS_TAINTED(&x5, sizeof(int)));

    x3 = y / z;
    TEST_ASSSERT(IS_TAINTED(&x3, sizeof(int)));

    x4 = y % z;
    TEST_ASSSERT(IS_TAINTED(&x4, sizeof(int)));

    return true;
}

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
    TEST_ASSSERT(!IS_TAINTED(&x1, sizeof(int)))

bool test_untaint()
{
    // when assigning a value to k with mov r, imm
    // we untaint it, commands [eor | sub | ..] r1, r0, r0
    // are equivalent to mov r, imm

    int k = 8;
    TEST_ASSSERT(!IS_TAINTED(&k, sizeof(int)));

    MAKE_TAINTED(&k, sizeof(int));
    TEST_ASSSERT(IS_TAINTED(&k, sizeof(int)));

    k = 8;
    TEST_ASSSERT(!IS_TAINTED(&k, sizeof(int)));

    int x1, x2;
    TEST_XOR_REG_REG(eor);
    TEST_XOR_REG_REG(eors);
    TEST_XOR_REG_REG(sub);
    TEST_XOR_REG_REG(subs);
    TEST_XOR_REG_REG(sbc);
    TEST_XOR_REG_REG(sbcs);

    return true;
}

#undef TEST_XOR_REG_REG

bool test_asm_check_ldrd()
{
    unsigned int A[2] = {0x12345678, 0x9ABCDEF0};
    MAKE_TAINTED(A, sizeof(A));

    int v = 0;
    int v2 = 0;

    printf("Test 'ldrd'\n");
    asm volatile("ldrd %0, %1, [%2, #0]"
                 : "=r"(v), "=r"(v2) // out 0
                 : "r"(A));          // in 1

    TEST_ASSSERT(IS_TAINTED(&v, sizeof(int)));
    TEST_ASSSERT(IS_TAINTED(&v2, sizeof(int)));

    v = 0;
    v2 = 0;

    printf("Test 'ldrexd'\n");
    asm volatile("ldrexd %0, %1, [%2]"
                 : "=r"(v), "=r"(v2) // out 0
                 : "r"(A));          // in 1

    TEST_ASSSERT(IS_TAINTED(&v, sizeof(int)));
    TEST_ASSSERT(IS_TAINTED(&v2, sizeof(int)));

    return true;
}

#define CHECK(com, r0, r1, offs)              \
                                              \
    printf("Test '" #com "'\n");              \
    r0 = 0;                                   \
    asm volatile(#com " %0, [%1, #" #offs "]" \
                 : "=r"(r0)                   \
                 : "r"(r1));                  \
                                              \
    TEST_ASSSERT(IS_TAINTED(&r0, sizeof(int)))

#define CHECK_EX(com, r0, r1)     \
                                  \
    printf("Test '" #com "'\n");  \
    r0 = 0;                       \
    asm volatile(#com " %0, [%1]" \
                 : "=r"(r0)       \
                 : "r"(r1));      \
                                  \
    TEST_ASSSERT(IS_TAINTED(&r0, sizeof(int)))

bool test_asm_check_ldr()
{
    unsigned int A[2] = {0x12345678, 0x9ABCDEF0}, v;
    MAKE_TAINTED(A, sizeof(A));

    CHECK(ldr, v, A, 0);
    CHECK(ldr, v, A, 4);
    CHECK(ldrb, v, A, 0);
    CHECK(ldrb, v, A, 4);
    CHECK(ldrh, v, A, 0);
    CHECK(ldrh, v, A, 4);
    CHECK(ldrsb, v, A, 0);
    CHECK(ldrsb, v, A, 4);
    CHECK(ldrsh, v, A, 0);
    CHECK(ldrsh, v, A, 4);

#ifdef MTHUMB

    CHECK(ldrt, v, A, 0);
    CHECK(ldrt, v, A, 4);
    CHECK(ldrbt, v, A, 0);
    CHECK(ldrbt, v, A, 4);
    CHECK(ldrsbt, v, A, 0);
    CHECK(ldrsbt, v, A, 4);
    CHECK(ldrht, v, A, 0);
    CHECK(ldrht, v, A, 4);
    CHECK(ldrsht, v, A, 0);
    CHECK(ldrsht, v, A, 4);

#endif

    CHECK_EX(ldrex, v, A);
    CHECK_EX(ldrex, v, A);
    CHECK_EX(ldrexb, v, A);
    CHECK_EX(ldrexb, v, A);
    CHECK_EX(ldrexh, v, A);
    CHECK_EX(ldrexh, v, A);

    return true;
}

#undef CHECK
#undef CHECK_EX

#define CHECK(com, v1, v2, v3, v4, c)                     \
    v1 = v2 = v3 = v4 = 0;                                \
    printf("Test '" #com "'\n");                          \
                                                          \
    asm volatile("mov r0, %4;"                            \
                 "" #com " r0, {r1, r2, r3, r4};"         \
                 "str r1, %0;"                            \
                 "str r2, %1;"                            \
                 "str r3, %2;"                            \
                 "str r4, %3;"                            \
                 : "=m"(v1), "=m"(v2), "=m"(v3), "=m"(v4) \
                 : "r"(A + c)                             \
                 : "r0", "r1", "r2", "r3", "r4");         \
                                                          \
    TEST_ASSSERT(IS_TAINTED(&val1, sizeof(int)));         \
    TEST_ASSSERT(IS_TAINTED(&val2, sizeof(int)));         \
    TEST_ASSSERT(IS_TAINTED(&val3, sizeof(int)));         \
    TEST_ASSSERT(IS_TAINTED(&val4, sizeof(int)))

#define CHECK_W(com, v1, v2, v3, v4, c)                   \
    v1 = v2 = v3 = v4 = 0;                                \
    printf("Test '" #com "'\n");                          \
                                                          \
    asm volatile("mov r0, %4;"                            \
                 "" #com " r0!, {r1, r2, r3, r4};"        \
                 "str r1, %0;"                            \
                 "str r2, %1;"                            \
                 "str r3, %2;"                            \
                 "str r4, %3;"                            \
                 : "=m"(v1), "=m"(v2), "=m"(v3), "=m"(v4) \
                 : "r"(A + c)                             \
                 : "r0", "r1", "r2", "r3", "r4");         \
                                                          \
    TEST_ASSSERT(IS_TAINTED(&val1, sizeof(int)));         \
    TEST_ASSSERT(IS_TAINTED(&val2, sizeof(int)));         \
    TEST_ASSSERT(IS_TAINTED(&val3, sizeof(int)));         \
    TEST_ASSSERT(IS_TAINTED(&val4, sizeof(int)))

bool test_asm_check_ldm()
{
    int A[] = {0, 1, 2, 3, 4};
    int val1, val2, val3, val4;
    MAKE_TAINTED(A, sizeof(A));

    CHECK(ldmia, val1, val2, val3, val4, 0);
    CHECK_W(ldmia, val1, val2, val3, val4, 0);

    CHECK(ldmdb, val1, val2, val3, val4, 4);
    CHECK_W(ldmdb, val1, val2, val3, val4, 4);

#ifndef MTHUMB

    CHECK(ldmib, val1, val2, val3, val4, 0);
    CHECK_W(ldmib, val1, val2, val3, val4, 0);

    CHECK(ldmda, val1, val2, val3, val4, 4);
    CHECK_W(ldmda, val1, val2, val3, val4, 4);

#endif

    return true;
}

#undef CHECK
#undef CHECK_W

bool test_asm()
{
    TEST_ASSSERT(test_ldm());
    //TEST_ASSSERT(test_asm_check_ldrd());

    return true;
}