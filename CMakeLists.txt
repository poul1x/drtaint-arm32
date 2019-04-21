cmake_minimum_required (VERSION 3.0)
project (drtaint)

# cmake ../ -DDynamoRIO_DIR=/home/user/Downloads/dynamorio/build/cmake/ -DDrMemoryFramework_DIR=/home/user/Downloads/drmemory/build/drmf/ -DCMAKE_TOOLCHAIN_FILE=toolchain-arm32.cmake
# cmake ../ -DDynamoRIO_DIR=/home/debian/Downloads/dynamorio/build/cmake/ -DDrMemoryFramework_DIR=/home/debian/Downloads/drmemory/build/drmf/ -DDebug=ON

if (NOT DEFINED DynamoRIO_DIR)
  message(FATAL_ERROR "Need to specify directory DynamoRIO_DIR containing DynamoRIOConfig.cmake")
endif ()

if (NOT DEFINED DrMemoryFramework_DIR)
  message(FATAL_ERROR "Need to specify directory DrMemoryFramework_DIR containing DRMFTarget32.cmake")
endif ()


find_package(DynamoRIO REQUIRED)
find_package(DrMemoryFramework REQUIRED)

# build projects
add_subdirectory(app/drtaint_test drtaint_test)
add_subdirectory(app/drtaint_only drtaint_only)
add_subdirectory(app/drmarker drmarker)

