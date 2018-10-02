cmake_minimum_required (VERSION 3.0)
project (drtaint_only)

add_library(drtaint_only SHARED
drtaint_only_cli.cpp
../../core/drtaint.cpp
../../core/drtaint_simd.cpp
../../core/drtaint_shadow.c
../../core/drtaint_helper.cpp
)

set(CMAKE_C_FLAGS "-mthumb -Wall")
set(CMAKE_CXX_FLAGS "-mthumb -Wall")

if (Debug)
    message(STATUS "libdrtaint_only.so: configuring debug build")
    set(CMAKE_C_FLAGS "-g ${CMAKE_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "-g ${CMAKE_CXX_FLAGS}")
else()
    message(STATUS "libdrtaint_only.so: configuring release build")
    set(CMAKE_C_FLAGS "-O3 ${CMAKE_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "-O3 ${CMAKE_CXX_FLAGS}")
endif (Debug)

# build client library
configure_DynamoRIO_client(drtaint_only)
use_DynamoRIO_extension(drtaint_only "drreg")
use_DynamoRIO_extension(drtaint_only "drmgr")
use_DynamoRIO_extension(drtaint_only "drutil")
use_DynamoRIO_extension(drtaint_only "drx")
use_DynamoRIO_extension(drtaint_only "umbra")
use_DynamoRIO_extension(drtaint_only "drsyscall")
