cmake_minimum_required (VERSION 3.0)
project (drtaint_marker)

add_library(drtaint_marker SHARED
drtaint_marker_cli.cpp
taint_processing.cpp
../../core/drtaint.cpp
../../core/drtaint_simd.cpp
../../core/drtaint_shadow.c
../../core/drtaint_helper.cpp
)

# configuration for client library
set(CMAKE_C_FLAGS "${CMAKE_FLAGS_CLI}")
set(CMAKE_CXX_FLAGS "${CMAKE_FLAGS_CLI}")

configure_DynamoRIO_client(drtaint_marker)
use_DynamoRIO_extension(drtaint_marker "drreg")
use_DynamoRIO_extension(drtaint_marker "drmgr")
use_DynamoRIO_extension(drtaint_marker "drutil")
use_DynamoRIO_extension(drtaint_marker "drx")
use_DynamoRIO_extension(drtaint_marker "umbra")
use_DynamoRIO_extension(drtaint_marker "drsyscall")

# configuration for client app
set(CMAKE_C_FLAGS "${CMAKE_FLAGS_APP}")
set(CMAKE_CXX_FLAGS "${CMAKE_FLAGS_APP}")
add_executable(drtaint_marker_app drtaint_marker_app.cpp)
