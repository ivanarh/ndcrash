cmake_minimum_required(VERSION 3.4.1)
project(ndcrash)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror=implicit-function-declaration")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11") #For libunwindstack only.

set(NDCRASH_SOURCE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/src)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include ${NDCRASH_SOURCE_ROOT})
file(GLOB NDCRASH_SOURCES ${NDCRASH_SOURCE_ROOT}/*.c)

if (${ENABLE_INPROCESS})
    add_definitions(-DENABLE_INPROCESS)
endif()

if (${ENABLE_OUTOFPROCESS})
    add_definitions(-DENABLE_OUTOFPROCESS)
endif()


if (${ENABLE_LIBCORKSCREW})
    message(STATUS "Backend enabled: libcorkscrew")
    add_definitions(-DENABLE_LIBCORKSCREW)
    file(GLOB NDCRASH_BACKEND_SOURCES ${NDCRASH_SOURCE_ROOT}/backends/libcorkscrew/*.c)
    list(APPEND NDCRASH_SOURCES ${NDCRASH_BACKEND_SOURCES})

    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/libcorkscrew-ndk/include)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/libcorkscrew-ndk/cmake)
    list(APPEND LINK_LIBRARIES corkscrew)
else()
    message(STATUS "Backend disabled: libcorkscrew")
endif()

if (${ENABLE_LIBUNWIND})
    message(STATUS "Backend enabled: libunwind")
    add_definitions(-DENABLE_LIBUNWIND)
    add_definitions(-DHAVE_CONFIG_H -D_GNU_SOURCE)
    file(GLOB NDCRASH_BACKEND_SOURCES ${NDCRASH_SOURCE_ROOT}/backends/libunwind/*.c)
    list(APPEND NDCRASH_SOURCES ${NDCRASH_BACKEND_SOURCES})

    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/libunwind-ndk/include ${CMAKE_CURRENT_SOURCE_DIR}/external/libunwind-ndk/include/tdep ${CMAKE_CURRENT_SOURCE_DIR}/external/libunwind-ndk/src)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/libunwind-ndk/cmake)
    list(APPEND LINK_LIBRARIES unwind)
else()
    message(STATUS "Backend disabled: libunwind")
endif()

if (${ENABLE_LIBUNWINDSTACK})
    message(STATUS "Backend enabled: libunwindstack")
    add_definitions(-DENABLE_LIBUNWINDSTACK)
    file(GLOB NDCRASH_BACKEND_SOURCES ${NDCRASH_SOURCE_ROOT}/backends/libunwindstack/*.cpp)
    list(APPEND NDCRASH_SOURCES ${NDCRASH_BACKEND_SOURCES})

    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/libunwindstack-ndk/include)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/libunwindstack-ndk/cmake)
    list(APPEND LINK_LIBRARIES unwindstack)
else()
    message(STATUS "Backend disabled: libunwindstack")
endif()

add_library(ndcrash STATIC ${NDCRASH_SOURCES})
target_link_libraries(ndcrash ${LINK_LIBRARIES})