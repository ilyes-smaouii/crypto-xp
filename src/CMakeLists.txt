cmake_minimum_required(VERSION 3.15)
project(crypto-xp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CPP_COMMON_SOURCE_DIR ../../cpp-common)

# --- Library: cpp_common ---
file(GLOB CPP_COMMON_SOURCES
    ${CPP_COMMON_SOURCE_DIR}/*.cpp
    ${CPP_COMMON_SOURCE_DIR}/*.hpp
)

add_library(cpp_common ${CPP_COMMON_SOURCES})


target_include_directories(cpp_common PUBLIC
    ${CPP_COMMON_SOURCE_DIR}/..
)

# --- Library: crypto_helpers ---
add_library(crypto_helpers
    crypto_helpers.cpp
)

target_include_directories(crypto_helpers PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# crypto_helpers needs cpp_common
target_link_libraries(crypto_helpers PUBLIC cpp_common)

# --- Library: crypto_tea ---
add_library(crypto_tea
    tea/tea_impl.cpp
)

target_include_directories(crypto_tea PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/tea
)

#
# CRYPTO_STRUCT
#

target_link_libraries(crypto_tea PUBLIC crypto_helpers)

add_library(tea_struct
tea/tea_struct.cpp
)

target_include_directories(tea_struct PUBLIC
${CMAKE_CURRENT_SOURCE_DIR}/tea
)

target_link_libraries(tea_struct PUBLIC crypto_helpers)

#
# /CRYPTO_STRUCT
#


# --- Executable: tea_testing ---
add_executable(tea_testing
    testing/tea_testing.cpp
)

# only link tea (which already pulls helpers + common)
target_link_libraries(tea_testing PRIVATE crypto_tea)

# --- Executable: tea_testing2 ---
add_executable(tea_testing2
    testing/tea_testing2.cpp
)

# only link tea (which already pulls helpers + common)
target_link_libraries(tea_testing2 PRIVATE tea_struct)
