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
    {"cmp", test_cmp},
    {"condex_op", test_condex_op},
    {"assign_ex", test_assign_ex},

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

bool
test_array()
{
    char src1[] = "~DrTaint~";
    char* dst1 = new char[sizeof(src1)];
    char dst2[sizeof(src1)];

    MAKE_TAINTED(src1, sizeof(src1));
    strcpy(dst1, src1);
    strcpy(dst2, src1);

    bool b = IS_TAINTED(dst1, sizeof(src1));
    delete dst1;

    TEST_ASSSERT(b);
    TEST_ASSSERT(IS_TAINTED(dst2, sizeof(src1)));

    int C[2] = {1,2};
    int D[2] = {0};

    MAKE_TAINTED(&C[0], sizeof(int));
    D[1] = C[0];

    TEST_ASSSERT(IS_TAINTED(&D[1], sizeof(int)));
    TEST_ASSSERT(!IS_TAINTED(&D[0], sizeof(int)));

    int A[2][2] = {{1,2},{3,4}};
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

#define CMP_PART_CODE_TYPE1(type)                        \
    type t1 = 1, t2 = 2, t3 = 3, t4 = 4, t5 = 5, t6 = 6; \
    type x1 = 2, x2 = 1, x3 = 4, x4 = 3, x5 = 3, x6 = 0; \
    type y1 = 1, y2 = 2, y3 = 3, y4 = 4, y5 = 4, y6 = 0; \
    type z1, z2, z3, z4, z5, z6;                         \
    MAKE_TAINTED(&t1, sizeof(type));                     \
    MAKE_TAINTED(&t2, sizeof(type));                     \
    MAKE_TAINTED(&t3, sizeof(type));                     \
    MAKE_TAINTED(&t4, sizeof(type));                     \
    MAKE_TAINTED(&t5, sizeof(type));                     \
    MAKE_TAINTED(&t6, sizeof(type));                     \
                                                         \
    if (x1 < y1)                                         \
        z1 = 0;                                          \
    else                                                 \
        z1 = t1;                                         \
                                                         \
    if (x2 > y2)                                         \
        z2 = 0;                                          \
    else                                                 \
        z2 = t2;                                         \
                                                         \
    if (x3 <= y3)                                        \
        z3 = 0;                                          \
    else                                                 \
        z3 = t3;                                         \
                                                         \
    if (x4 >= y4)                                        \
        z4 = 0;                                          \
    else                                                 \
        z4 = t4;                                         \
                                                         \
    if (x5 == y5)                                        \
        z5 = 0;                                          \
    else                                                 \
        z5 = t5;                                         \
                                                         \
    if (x6 != y6)                                        \
        z6 = 0;                                          \
    else                                                 \
        z6 = t6;                                         \
                                                         \
    TEST_ASSSERT(IS_TAINTED(&z1, sizeof(type)));         \
    TEST_ASSSERT(IS_TAINTED(&z2, sizeof(type)));         \
    TEST_ASSSERT(IS_TAINTED(&z3, sizeof(type)));         \
    TEST_ASSSERT(IS_TAINTED(&z4, sizeof(type)));         \
    TEST_ASSSERT(IS_TAINTED(&z5, sizeof(type)));         \
    TEST_ASSSERT(IS_TAINTED(&z6, sizeof(type)));         \
                                                         \
    return true

#define CMP_PART_CODE_TYPE2(type)                                            \
    type t1 = 1, t2 = 2, t3 = 3, t3_2 = 3, t4 = 4, t4_2 = 4, t5 = 5, t6 = 6; \
    type x1 = 1, x2 = 2, x3 = 3, x3_2 = 4, x4 = 4, x4_2 = 3, x5 = 3, x6 = 0; \
    type y1 = 2, y2 = 1, y3 = 4, y3_2 = 4, y4 = 3, y4_2 = 3, y5 = 3, y6 = 1; \
    type z1, z2, z3, z3_2, z4, z4_2, z5, z6;                                 \
    MAKE_TAINTED(&t1, sizeof(type));                                         \
    MAKE_TAINTED(&t2, sizeof(type));                                         \
    MAKE_TAINTED(&t3, sizeof(type));                                         \
    MAKE_TAINTED(&t3_2, sizeof(type));                                       \
    MAKE_TAINTED(&t4, sizeof(type));                                         \
    MAKE_TAINTED(&t4_2, sizeof(type));                                       \
    MAKE_TAINTED(&t5, sizeof(type));                                         \
    MAKE_TAINTED(&t6, sizeof(type));                                         \
                                                                             \
    if (x1 < y1)                                                             \
        z1 = t1;                                                             \
    else                                                                     \
        z1 = 0;                                                              \
                                                                             \
    if (x2 > y2)                                                             \
        z2 = t2;                                                             \
    else                                                                     \
        z2 = 0;                                                              \
                                                                             \
    if (x3 <= y3)                                                            \
        z3 = t3;                                                             \
    else                                                                     \
        z3 = 0;                                                              \
                                                                             \
    if (x3_2 <= y3_2)                                                        \
        z3_2 = t3_2;                                                         \
    else                                                                     \
        z3_2 = 0;                                                            \
                                                                             \
    if (x4 >= y4)                                                            \
        z4 = t4;                                                             \
    else                                                                     \
        z4 = 0;                                                              \
                                                                             \
    if (x4_2 >= y4_2)                                                        \
        z4_2 = t4_2;                                                         \
    else                                                                     \
        z4_2 = 0;                                                            \
                                                                             \
    if (x5 == y5)                                                            \
        z5 = t5;                                                             \
    else                                                                     \
        z5 = 0;                                                              \
                                                                             \
    if (x6 != y6)                                                            \
        z6 = t6;                                                             \
    else                                                                     \
        z6 = 0;                                                              \
                                                                             \
    TEST_ASSSERT(IS_TAINTED(&z1, sizeof(type)));                             \
    TEST_ASSSERT(IS_TAINTED(&z2, sizeof(type)));                             \
    TEST_ASSSERT(IS_TAINTED(&z3, sizeof(type)));                             \
    TEST_ASSSERT(IS_TAINTED(&z3_2, sizeof(type)));                           \
    TEST_ASSSERT(IS_TAINTED(&z4, sizeof(type)));                             \
    TEST_ASSSERT(IS_TAINTED(&z4_2, sizeof(type)));                           \
    TEST_ASSSERT(IS_TAINTED(&z5, sizeof(type)));                             \
    TEST_ASSSERT(IS_TAINTED(&z6, sizeof(type)));                             \
                                                                             \
    return true

static bool first_part()
{
    CMP_PART_CODE_TYPE1(int);
}

static bool second_part()
{
    CMP_PART_CODE_TYPE1(unsigned);
}

static bool third_part()
{
    CMP_PART_CODE_TYPE2(int);
}

static bool fourth_part()
{
    CMP_PART_CODE_TYPE2(unsigned);
}

bool test_cmp()
/*
    Test comparison operations
*/
{
    printf("Running first part signed\n");
    TEST_ASSSERT(first_part());

    printf("Running first part unsigned\n");
    TEST_ASSSERT(second_part());

    printf("Running second part signed\n");
    TEST_ASSSERT(third_part());

    printf("Running second part unsigned\n");
    TEST_ASSSERT(fourth_part());
    return true;
}

#undef CMP_PART_CODE_TYPE1
#undef CMP_PART_CODE_TYPE2

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
