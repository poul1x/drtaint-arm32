cmake_minimum_required (VERSION 3.0)
project (drmarker)

add_library(drmarker SHARED
drmarker_cli.cpp
../../core/drtaint.cpp
../../core/drtaint_simd.cpp
../../core/drtaint_shadow.c
../../core/drtaint_helper.cpp
)

set(CMAKE_C_FLAGS "-mthumb -Wall -Wno-unknown-pragmas")
set(CMAKE_CXX_FLAGS "-mthumb -Wall -Wno-unknown-pragmas")

if (Debug)
    message(STATUS "libdrmarker.so: configuring debug build")
    set(CMAKE_C_FLAGS "-g ${CMAKE_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "-g ${CMAKE_CXX_FLAGS}")
else()
    message(STATUS "libdrmarker.so: configuring release build")
    set(CMAKE_C_FLAGS "-O3 ${CMAKE_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "-O3 ${CMAKE_CXX_FLAGS}")
endif (Debug)

# build client library
configure_DynamoRIO_client(drmarker)
use_DynamoRIO_extension(drmarker "drreg")
use_DynamoRIO_extension(drmarker "drmgr")
use_DynamoRIO_extension(drmarker "drutil")
use_DynamoRIO_extension(drmarker "drx")
use_DynamoRIO_extension(drmarker "umbra")
use_DynamoRIO_extension(drmarker "drsyscall")

# by default compile for arm, not thumb
if (Thumb)
    set(CMAKE_CXX_FLAGS "-mthumb -DMTHUMB -Wall -Wno-unknown-pragmas -Wno-array-bounds -O0")
    message(STATUS "drmarker_app: configuring thumb ISA")
else()
    set(CMAKE_CXX_FLAGS "-marm -Wall -Wno-unknown-pragmas -Wno-array-bounds -O0")
    message(STATUS "drmarker_app: configuring arm ISA")
endif (Thumb)

# build aplication for client library
add_executable(drmarker_app drmarker_app.cpp)
