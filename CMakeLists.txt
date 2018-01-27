cmake_minimum_required(VERSION 3.4.1)
project(ndcrash)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror=implicit-function-declaration")

set(NDCRASH_SOURCE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/src)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include ${NDCRASH_SOURCE_ROOT})
file(GLOB NDCRASH_SOURCES ${NDCRASH_SOURCE_ROOT}/*.c)

if (${ENABLE_LIBCORKSCREW})
    message(STATUS "Backend enabled: libcorkscrew")
    add_definitions(-DENABLE_LIBCORKSCREW)
    file(GLOB NDCRASH_BACKEND_SOURCES ${NDCRASH_SOURCE_ROOT}/backends/libcorkscrew/*.c)
    list(APPEND NDCRASH_SOURCES ${NDCRASH_BACKEND_SOURCES})
else()
    message(STATUS "Backend disabled: libcorkscrew")
endif()

if (${ENABLE_LIBUNWIND})
    message(STATUS "Backend enabled: libunwind")
    add_definitions(-DENABLE_LIBUNWIND)
    file(GLOB NDCRASH_BACKEND_SOURCES ${NDCRASH_SOURCE_ROOT}/backends/libunwind/*.c)
    list(APPEND NDCRASH_SOURCES ${NDCRASH_BACKEND_SOURCES})
else()
    message(STATUS "Backend disabled: libunwind")
endif()

if (${ENABLE_LIBUNWINDSTACK})
    message(STATUS "Backend enabled: libunwindstack")
    add_definitions(-DENABLE_LIBUNWINDSTACK)
    file(GLOB NDCRASH_BACKEND_SOURCES ${NDCRASH_SOURCE_ROOT}/backends/libunwindstack/*.c)
    list(APPEND NDCRASH_SOURCES ${NDCRASH_BACKEND_SOURCES})
else()
    message(STATUS "Backend disabled: libunwindstack")
endif()

add_library(ndcrash STATIC ${NDCRASH_SOURCES})
