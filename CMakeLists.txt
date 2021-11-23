cmake_minimum_required(VERSION 3.0)
project(libvhost)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

#set(ENABLE_SANITIZERS true CACHE BOOL "Enable Sanitizers")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

# example: https://github.com/amzn/hawktracer/blob/master/CMakeLists.txt
# https://github.com/soedinglab/hh-suite/blob/master/CMakeLists.txt

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
#if (ENABLE_SANITIZERS)
    include(FindUBSan)
    include(FindASan)
    include(FindMSan)
    include(FindTSan)
#endif()

include_directories(include)
add_subdirectory(lib)
add_subdirectory(examples)