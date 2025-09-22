cmake_minimum_required(VERSION 3.15)
project(crypto-xp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)

set(CPP_COMMON_SOURCE_DIR ../../cpp-common)

# Create a library with shared crypto code
add_library(cpp_common
    ${CPP_COMMON_SOURCE_DIR}/misc.hpp
    ${CPP_COMMON_SOURCE_DIR}/misc.cpp
    ${CPP_COMMON_SOURCE_DIR}/common-common.hpp
    ${CPP_COMMON_SOURCE_DIR}/logging.hpp
)

add_library(crypto_helpers
    crypto_helpers.hpp
    crypto_helpers.cpp
)

add_library(crypto_tea
    tea/tea_impl.hpp
    tea/tea_impl.cpp
)

# target_include_directories(tea_testing PUBLIC
#     ${CPP_COMMON_SOURCE_DIR}
#     ${CMAKE_CURRENT_SOURCE_DIR}
#     ${CMAKE_CURRENT_SOURCE_DIR}/TEA
# )

# include_directories(${CPP_COMMON_SOURCE_DIR})
# link_directories(${CPP_COMMON_SOURCE_DIR})

# Main program
add_executable(first_one
    first_one.cpp
    )

target_link_libraries(first_one PRIVATE crypto_helpers cpp_common)

# Test program
add_executable(tea_testing
testing/tea_testing.cpp
)

target_link_libraries(tea_testing PRIVATE crypto_helpers cpp_common crypto_tea)
