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
    {"arifm", test_arifm},
    {"assign", test_assign},
    {"bitwise", test_bitwise},
    {"condex_op", test_condex_op},
    {"assign_ex", test_assign_ex},
    {"struct", test_struct},
    {"func_call", test_func_call},
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

bool test_arifm()
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
