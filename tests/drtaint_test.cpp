#include "drtaint_test.h"

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
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

    {"simple_test", simple_test},

};

void usage()
{
    printf("Usage:\n");
    printf("Run tests: file.exe <test1> <test2> ...\n");
    printf("Run all tests: file.exe all\n");
}

int main(int argc, char *argv[])
{
    if (argc == 1)
    {
        usage();
        return 0;
    }

    if (!strcmp(argv[1], "all"))
    {
        run_all_tests();
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

    printf("Results: passed - %d, failed - %d\nExitting...\n",
           count_passed, count_failed);

    return 0;
}

bool simple_test()
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

    printf("Results: passed - %d, failed - %d\nExitting...\n",
           count_passed, count_failed);
}