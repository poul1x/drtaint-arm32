cmake_minimum_required (VERSION 3.0)
project (drtaint)

set(CMAKE_CXX_STANDARD 17)

if (NOT DEFINED DynamoRIO_DIR)
  message(FATAL_ERROR "Need to specify directory DynamoRIO_DIR containing DynamoRIOConfig.cmake")
endif ()

if (NOT DEFINED DrMemoryFramework_DIR)
  message(FATAL_ERROR "Need to specify directory DrMemoryFramework_DIR containing DRMFTarget32.cmake")
endif ()

find_package(DynamoRIO REQUIRED)
find_package(DrMemoryFramework REQUIRED)

# compile client libraries in thumb mode, otherwise it crashes after
set(CMAKE_FLAGS_CLI "-mthumb -Wall -Wno-unknown-pragmas -O3")

# by default compile client app in arm/thumb2 mode
if (Thumb)
    set(CMAKE_FLAGS_APP "-mthumb -DMTHUMB -Wall -Wno-unknown-pragmas -Wno-array-bounds")
else()
    set(CMAKE_FLAGS_APP "-marm -Wall -Wno-unknown-pragmas -Wno-array-bounds")
endif (Thumb)

if (Optimized)
    set(CMAKE_FLAGS_APP "${CMAKE_FLAGS_APP} -O2")
else()
    set(CMAKE_FLAGS_APP "${CMAKE_FLAGS_APP} -O0")
endif (Optimized)

message(STATUS "Drtaint client library build configuration: ${CMAKE_FLAGS_CLI}")
message(STATUS "Drtaint client application build configuration: ${CMAKE_FLAGS_APP}")

# build projects
add_subdirectory(app/drtaint_test drtaint_test)
add_subdirectory(app/drtaint_only drtaint_only)
add_subdirectory(app/drtaint_marker drtaint_marker)

