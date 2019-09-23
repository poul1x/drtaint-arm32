cmake_minimum_required (VERSION 3.0)
project (drtaint_only)

add_library(drtaint_only SHARED
drtaint_only_cli.cpp
../../core/drtaint.cpp
../../core/drtaint_simd.cpp
../../core/drtaint_shadow.c
../../core/drtaint_helper.cpp
)

# configuration for client library
set(CMAKE_C_FLAGS "${CMAKE_FLAGS_CLI}")
set(CMAKE_CXX_FLAGS "${CMAKE_FLAGS_CLI}")

configure_DynamoRIO_client(drtaint_only)
use_DynamoRIO_extension(drtaint_only "drreg")
use_DynamoRIO_extension(drtaint_only "drmgr")
use_DynamoRIO_extension(drtaint_only "drutil")
use_DynamoRIO_extension(drtaint_only "drx")
use_DynamoRIO_extension(drtaint_only "umbra")
use_DynamoRIO_extension(drtaint_only "drsyscall")
