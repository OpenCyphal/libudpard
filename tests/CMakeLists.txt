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
        -Wall -Wextra -Werror -pedantic -fstrict-aliasing -Wdouble-promotion -Wswitch-enum -Wfloat-equal -Wundef
        -Wconversion -Wtype-limits -Wsign-conversion -Wcast-align
)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Woverloaded-virtual -Wnon-virtual-dtor -Wsign-promo")

include_directories(${library_dir})
include_directories(SYSTEM catch)

set(common_sources ${CMAKE_SOURCE_DIR}/main.cpp ${library_dir}/udpard.c)

function(gen_test name files compile_definitions compile_flags link_flags c_standard)
    add_executable(${name} ${common_sources} ${files})
    target_compile_definitions(${name} PUBLIC ${compile_definitions})
    target_link_libraries(${name} pthread)
    set_target_properties(
            ${name}
            PROPERTIES
            COMPILE_FLAGS "${compile_flags}"
            LINK_FLAGS "${link_flags}"
            C_STANDARD "${c_standard}"
            C_EXTENSIONS OFF
    )
    add_test("run_${name}" "${name}" --rng-seed time)
endfunction()

function(gen_test_matrix name files compile_definitions compile_flags link_flags)
    gen_test("${name}_x64_c99" "${files}" "${compile_definitions}" "${compile_flags} -m64" "-m64 ${link_flags}" "99")
    gen_test("${name}_x32_c99" "${files}" "${compile_definitions}" "${compile_flags} -m32" "-m32 ${link_flags}" "99")
    target_link_libraries("${name}_x32_c99" ${ADDITIONAL_LIBS_32})
    gen_test("${name}_x64_c11" "${files}" "${compile_definitions}" "${compile_flags} -m64" "-m64 ${link_flags}" "11")
    gen_test("${name}_x32_c11" "${files}" "${compile_definitions}" "${compile_flags} -m32" "-m32 ${link_flags}" "11")
    target_link_libraries("${name}_x32_c11" ${ADDITIONAL_LIBS_32})
    # Coverage is only available for GCC builds.
    if ((CMAKE_CXX_COMPILER_ID STREQUAL "GNU") AND (CMAKE_BUILD_TYPE STREQUAL "Debug"))
        gen_test("${name}_cov"
                "${files}"
                "${compile_definitions}"
                "${compile_flags} -g -O0 --coverage"
                "--coverage"
                "11")
    endif ()
endfunction()

# Disable missing declaration warning to allow exposure of private definitions.
gen_test_matrix(test_private
        "test_private_cavl.cpp;"
        "-DUDPARD_CONFIG_HEADER=\"${CMAKE_CURRENT_SOURCE_DIR}/udpard_config_private.h\""
        "-Wno-missing-declarations"
        "")

gen_test_matrix(test_public
        "test_self.cpp"
        ""
        "-Wmissing-declarations"
        "")
