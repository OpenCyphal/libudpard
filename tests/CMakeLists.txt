# This software is distributed under the terms of the MIT License.
# Copyright (c) OpenCyphal.
# Author: Pavel Kirienko <pavel@opencyphal.org>

cmake_minimum_required(VERSION 3.12)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)

project(udpard_tests C CXX)
enable_testing()

set(CTEST_OUTPUT_ON_FAILURE ON)
set(library_dir "${CMAKE_SOURCE_DIR}/../libudpard")

set(NO_STATIC_ANALYSIS OFF CACHE BOOL "disable udpard static analysis")

# Use -DNO_STATIC_ANALYSIS=1 to suppress static analysis.
# If not suppressed, the tools used here shall be available, otherwise the build will fail.
if (NOT NO_STATIC_ANALYSIS)
    # clang-tidy (separate config files per directory)
    find_program(clang_tidy NAMES clang-tidy)
    if (NOT clang_tidy)
        message(FATAL_ERROR "Could not locate clang-tidy")
    endif ()
    message(STATUS "Using clang-tidy: ${clang_tidy}")
    set(CMAKE_C_CLANG_TIDY ${clang_tidy})
    set(CMAKE_CXX_CLANG_TIDY ${clang_tidy})
endif ()

# clang-format
find_program(clang_format NAMES clang-format)
if (NOT clang_format)
    message(STATUS "Could not locate clang-format")
else ()
    file(GLOB format_files ${library_dir}/*.[ch] ${CMAKE_SOURCE_DIR}/*.[ch]pp)
    message(STATUS "Using clang-format: ${clang_format}; files: ${format_files}")
    add_custom_target(format COMMAND ${clang_format} -i -fallback-style=none -style=file --verbose ${format_files})
endif ()

add_compile_options(
        -Wall -Wextra -Werror -pedantic -Wdouble-promotion -Wswitch-enum -Wfloat-equal -Wundef
        -Wconversion -Wtype-limits -Wsign-conversion -Wcast-align -Wmissing-declarations
)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Woverloaded-virtual -Wnon-virtual-dtor -Wsign-promo")

function(gen_test name files compile_definitions compile_flags link_flags c_standard)
    add_executable(${name} ${files})
    target_include_directories(${name} PUBLIC SYSTEM ${library_dir})
    target_compile_definitions(${name} PUBLIC ${compile_definitions})
    # We're not using find_package(GTest) because this method can only find the package for one specific architecture,
    # which is not what we want. We build tests for AMD64 and x86 separately, which requires linking against different
    # GTest libraries located in different directories. Instead of doing it the hard way via find_package separately
    # per architecture, we just pass the library names directly and let the linker figure out where to find them.
    target_link_libraries(${name} pthread gtest gtest_main)
    set_target_properties(
            ${name}
            PROPERTIES
            COMPILE_FLAGS "${compile_flags}"
            LINK_FLAGS "${link_flags}"
            C_STANDARD "${c_standard}"
            C_EXTENSIONS OFF
    )
    add_test("run_${name}" "${name}" --gtest_random_seed=0 --gtest_color=yes)
endfunction()

function(gen_test_matrix name files)
    gen_test("${name}_x64_c99" "${files}" "" "-m64" "-m64" "99")
    gen_test("${name}_x32_c99" "${files}" "" "-m32" "-m32" "99")
    gen_test("${name}_x64_c11" "${files}" "" "-m64" "-m64" "11")
    gen_test("${name}_x32_c11" "${files}" "" "-m32" "-m32" "11")
endfunction()

gen_test_matrix(test_main "${library_dir}/udpard.c;test_self.cpp;test_tx.cpp;")

file(GLOB_RECURSE intrusive_test_files "${CMAKE_CURRENT_SOURCE_DIR}/test_intrusive_*.cpp")
foreach (file ${intrusive_test_files})
    string(REGEX REPLACE "^.*/(test_intrusive_.*).cpp" "\\1" name "${file}")
    message(STATUS "Generating test for ${name} obtained from ${file}")
    gen_test_matrix("test_intrusive_${name}" "${file}")
endforeach ()
