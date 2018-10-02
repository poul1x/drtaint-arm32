cmake_minimum_required (VERSION 3.0)
project (drtaint_demo)

add_library(drtaint_demo SHARED
drtaint_demo_cli.cpp
../../core/drtaint.cpp
../../core/drtaint_simd.cpp
../../core/drtaint_shadow.c
../../core/drtaint_helper.cpp
)

set(CMAKE_C_FLAGS "-mthumb -Wall -DASM_TAINT")
set(CMAKE_CXX_FLAGS "-mthumb -Wall -DASM_TAINT")

if (Debug)
    message(STATUS "libdrtaint_demo.so: configuring debug build")
    set(CMAKE_C_FLAGS "-g ${CMAKE_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "-g ${CMAKE_CXX_FLAGS}")
else()
    message(STATUS "libdrtaint_demo.so: configuring release build")
    set(CMAKE_C_FLAGS "-O3 ${CMAKE_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "-O3 ${CMAKE_CXX_FLAGS}")
endif (Debug)

# build client library
configure_DynamoRIO_client(drtaint_demo)
use_DynamoRIO_extension(drtaint_demo "drreg")
use_DynamoRIO_extension(drtaint_demo "drmgr")
use_DynamoRIO_extension(drtaint_demo "drutil")
use_DynamoRIO_extension(drtaint_demo "drx")
use_DynamoRIO_extension(drtaint_demo "umbra")
use_DynamoRIO_extension(drtaint_demo "drsyscall")

# by default compile for arm, not thumb
if (Thumb)
    set(CMAKE_CXX_FLAGS "-mthumb -DMTHUMB -Wall -Wno-unknown-pragmas -O3")
    message(STATUS "drtaint_demo_app: configuring thumb ISA")
else()
    set(CMAKE_CXX_FLAGS "-marm -Wall -Wno-unknown-pragmas -O3")
    message(STATUS "drtaint_demo_app: configuring arm ISA")
endif (Thumb)

# build aplication for client library
add_executable(drtaint_demo_app drtaint_demo_app.cpp)
