cmake_minimum_required (VERSION 3.0)
project (draslrharden)

add_library(draslrharden SHARED
draslrharden_cli.cpp
../../core/drtaint.cpp
../../core/drtaint_simd.cpp
../../core/drtaint_shadow.c
../../core/drtaint_helper.cpp
)

set(CMAKE_C_FLAGS "-mthumb -Wall")
set(CMAKE_CXX_FLAGS "-mthumb -Wall")

if (Debug)
    message(STATUS "libdraslrharden.so: configuring debug build")
    set(CMAKE_C_FLAGS "-g ${CMAKE_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "-g ${CMAKE_CXX_FLAGS}")
else()
    message(STATUS "libdraslrharden.so: configuring release build")
    set(CMAKE_C_FLAGS "-O3 ${CMAKE_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "-O3 ${CMAKE_CXX_FLAGS}")
endif (Debug)

# build client library
configure_DynamoRIO_client(draslrharden)
use_DynamoRIO_extension(draslrharden "drreg")
use_DynamoRIO_extension(draslrharden "drmgr")
use_DynamoRIO_extension(draslrharden "drutil")
use_DynamoRIO_extension(draslrharden "drx")
use_DynamoRIO_extension(draslrharden "droption")
use_DynamoRIO_extension(draslrharden "umbra")
use_DynamoRIO_extension(draslrharden "drsyscall")

# by default compile for arm, not thumb
if (Thumb)
    set(CMAKE_CXX_FLAGS "-mthumb -DMTHUMB -Wall -Wno-unknown-pragmas -O3")
    message(STATUS "draslrharden_app: configuring thumb ISA")
else()
    set(CMAKE_CXX_FLAGS "-marm -Wall -Wno-unknown-pragmas -O3")
    message(STATUS "draslrharden_app: configuring arm ISA")
endif (Thumb)

# build aplications for client library
add_executable(simple_argv_app simple_argv_app.c)
add_executable(simple_code_leaks_app simple_code_leaks_app.c)
add_executable(simple_leaks_app simple_leaks_app.c)