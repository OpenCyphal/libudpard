# This software is distributed under the terms of the MIT License.
# Copyright (c) OpenCyphal.
# Author: Pavel Kirienko <pavel@opencyphal.org>

cmake_minimum_required(VERSION 3.12)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Woverloaded-virtual -Wnon-virtual-dtor -Wsign-promo")

project(udpard_tests C CXX)
enable_testing()

set(CTEST_OUTPUT_ON_FAILURE ON)
set(NO_STATIC_ANALYSIS OFF CACHE BOOL "disable udpard static analysis")

set(library_dir "${CMAKE_SOURCE_DIR}/../libudpard")
set(unity_root "${CMAKE_CURRENT_SOURCE_DIR}/../submodules/unity")

# Use -DNO_STATIC_ANALYSIS=1 to suppress static analysis.
# If not suppressed, the tools used here shall be available, otherwise the build will fail.
if (NOT NO_STATIC_ANALYSIS)
    # clang-tidy (separate config files per directory)
    find_program(clang_tidy NAMES clang-tidy)
    if (NOT clang_tidy)
        message(FATAL_ERROR "Could not locate clang-tidy")
    endif ()
    message(STATUS "Using clang-tidy: ${clang_tidy}")
endif ()

# clang-format
find_program(clang_format NAMES clang-format)
if (NOT clang_format)
    message(STATUS "Could not locate clang-format")
else ()
    file(GLOB_RECURSE format_files
            ${library_dir}/*.[ch]
            ${CMAKE_SOURCE_DIR}/src/*.[ch]
            ${CMAKE_SOURCE_DIR}/src/*.[ch]pp)
    message(STATUS "Using clang-format: ${clang_format}; files: ${format_files}")
    add_custom_target(format COMMAND ${clang_format} -i -fallback-style=none -style=file --verbose ${format_files})
endif ()

function(gen_test name files compile_definitions compile_flags link_flags c_standard)
    # Unity
    add_library("${name}_unity" STATIC "${unity_root}/src/unity.c")
    target_include_directories("${name}_unity" SYSTEM PUBLIC "${unity_root}/src/")
    target_compile_definitions("${name}_unity" PUBLIC
            UNITY_INCLUDE_DOUBLE=1 UNITY_OUTPUT_COLOR=1 UNITY_SUPPORT_64=1 UNITY_SHORTHAND_AS_RAW=1)
    set_target_properties(
            "${name}_unity"
            PROPERTIES
            COMPILE_FLAGS "${compile_flags} \
            -Wno-sign-conversion -Wno-conversion -Wno-switch-enum -Wno-float-equal -Wno-double-promotion"
            LINK_FLAGS "${link_flags}"
    )
    # Target executable
    add_executable(${name} ${files})
    target_include_directories(${name} PUBLIC ${library_dir})
    target_compile_definitions(${name} PUBLIC ${compile_definitions})
    target_link_libraries(${name} "${name}_unity")
    set_target_properties(
            ${name}
            PROPERTIES
            COMPILE_FLAGS "${compile_flags} -Wall -Wextra -Werror -pedantic -Wdouble-promotion -Wswitch-enum \
            -Wfloat-equal -Wundef -Wconversion -Wtype-limits -Wsign-conversion -Wcast-align -Wmissing-declarations"
            LINK_FLAGS "${link_flags}"
            C_STANDARD "${c_standard}"
            C_EXTENSIONS OFF
            C_CLANG_TIDY "${clang_tidy}"
            CXX_CLANG_TIDY "${clang_tidy}"
    )
    add_test("run_${name}" "${name}")
endfunction()

function(gen_test_matrix name files)
    gen_test("${name}_x64_c99" "${files}" "" "-m64" "-m64" "99")
    gen_test("${name}_x32_c99" "${files}" "" "-m32" "-m32" "99")
    gen_test("${name}_x64_c11" "${files}" "" "-m64" "-m64" "11")
    gen_test("${name}_x32_c11" "${files}" "" "-m32" "-m32" "11")
endfunction()

# Add the test targets.
# Those that are written in C may #include <udpard.c> to reach its internals; they are called "intrusive".
# The public interface tests may be written in C++ for convenience.
gen_test_matrix(test_helpers "src/test_helpers.c")
gen_test_matrix(test_cavl "src/test_cavl.cpp")
gen_test_matrix(test_tx "${library_dir}/udpard.c;src/test_tx.cpp")
gen_test_matrix(test_misc "${library_dir}/udpard.c;src/test_misc.cpp")
gen_test_matrix(test_intrusive_crc "src/test_intrusive_crc.c")
gen_test_matrix(test_intrusive_tx "src/test_intrusive_tx.c")
gen_test_matrix(test_intrusive_rx "src/test_intrusive_rx.c")
