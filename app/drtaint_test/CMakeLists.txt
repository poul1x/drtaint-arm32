cmake_minimum_required (VERSION 3.0)
project (drtaint_test)

add_library(drtaint_test SHARED
drtaint_test_cli.cpp
../../core/drtaint.cpp
../../core/drtaint_simd.cpp
../../core/drtaint_shadow.c
../../core/drtaint_helper.cpp
)

# configuration for client library
set(CMAKE_C_FLAGS "${CMAKE_FLAGS_CLI}")
set(CMAKE_CXX_FLAGS "${CMAKE_FLAGS_CLI}")

configure_DynamoRIO_client(drtaint_test)
use_DynamoRIO_extension(drtaint_test "drreg")
use_DynamoRIO_extension(drtaint_test "drmgr")
use_DynamoRIO_extension(drtaint_test "drutil")
use_DynamoRIO_extension(drtaint_test "drx")
use_DynamoRIO_extension(drtaint_test "umbra")
use_DynamoRIO_extension(drtaint_test "drsyscall")

# configuration for client app
set(CMAKE_C_FLAGS "${CMAKE_FLAGS_APP}")
set(CMAKE_CXX_FLAGS "${CMAKE_FLAGS_APP}")
add_executable(drtaint_test_app drtaint_test_app.cpp)
