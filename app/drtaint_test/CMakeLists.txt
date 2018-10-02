cmake_minimum_required (VERSION 3.0)
project (drtaint_test)

add_library(drtaint_test SHARED
drtaint_test_cli.cpp
../../core/drtaint.cpp
../../core/drtaint_simd.cpp
../../core/drtaint_shadow.c
../../core/drtaint_helper.cpp
)

set(CMAKE_C_FLAGS "-mthumb -Wall")
set(CMAKE_CXX_FLAGS "-mthumb -Wall")

if (Debug)
    message(STATUS "libdrtaint_test.so: configuring debug build")
    set(CMAKE_C_FLAGS "-g ${CMAKE_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "-g ${CMAKE_CXX_FLAGS}")
else()
    message(STATUS "libdrtaint_test.so: configuring release build")
    set(CMAKE_C_FLAGS "-O3 ${CMAKE_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "-O3 ${CMAKE_CXX_FLAGS}")
endif (Debug)

# build client library
configure_DynamoRIO_client(drtaint_test)
use_DynamoRIO_extension(drtaint_test "drreg")
use_DynamoRIO_extension(drtaint_test "drmgr")
use_DynamoRIO_extension(drtaint_test "drutil")
use_DynamoRIO_extension(drtaint_test "drx")
use_DynamoRIO_extension(drtaint_test "umbra")
use_DynamoRIO_extension(drtaint_test "drsyscall")

# by default compile for arm, not thumb
if (Thumb)
    set(CMAKE_CXX_FLAGS "-mthumb -DMTHUMB -Wall -Wno-unknown-pragmas -O3")
    message(STATUS "drtaint_test_app: configuring thumb ISA")
else()
    set(CMAKE_CXX_FLAGS "-marm -Wall -Wno-unknown-pragmas -O3")
    message(STATUS "drtaint_test_app: configuring arm ISA")
endif (Thumb)

# build aplication for client library
add_executable(drtaint_test_app drtaint_test_app.cpp)
