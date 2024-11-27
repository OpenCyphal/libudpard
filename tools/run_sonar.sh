#!/usr/bin/env sh
# This helper script is mostly invoked from a CI workflow,
# but it can also be used to submit SonarCloud analysis from a developer's machine directly,
# which is useful during large refactorings.
#
# Usage: install the SonarCloud build wrapper and scanner as explained in the official docs
# (or simply follow the steps defined in the CI workflow that does the same), then run this script.

set -u

die()
{
    echo "$@" 1>&2
    exit 1
}

ensure_executable() { command -v $1 || die "Executable not found: $1" ; }

# Check preconditions early.
[ -z "$SONAR_TOKEN" ] && die "SonarCloud token is not set"
ensure_executable build-wrapper-linux-x86-64
ensure_executable sonar-scanner
ensure_executable llvm-profdata
ensure_executable llvm-cov

cd "${0%/*}/.." && [ -f libudpard/udpard.c ] && [ -f LICENSE ] || die "Could not cd to the project root"
echo "Working directory: $(pwd)"

# Set up a clean build directory. This is necessary for the analysis to be correct and complete.
BUILD_DIR=sonar_build
rm -rf $BUILD_DIR >/dev/null 2>&1
mkdir $BUILD_DIR && cd $BUILD_DIR || die

# Build everything and run the test suite; merge the coverage data.
# Clang produces better coverage reports than GCC for heavily templated code.
# It is also supposed to work well with optimizations.
# RTFM: https://clang.llvm.org/docs/UsersManual.html#profiling-with-instrumentation
#       https://clang.llvm.org/docs/SourceBasedCodeCoverage.html
profile_flags="-fprofile-instr-generate='%p.profraw' -fcoverage-mapping"
cmake .. \
-DNO_STATIC_ANALYSIS=1 \
-DCMAKE_BUILD_TYPE=Debug \
-DCMAKE_C_COMPILER=clang \
-DCMAKE_CXX_COMPILER=clang++ \
-DCMAKE_C_FLAGS="$profile_flags" \
-DCMAKE_CXX_FLAGS="$profile_flags"  || die "CMake failed"
build-wrapper-linux-x86-64 --out-dir . make VERBOSE=1 -j"$(nproc)" || die "Build wrapper failed"
make test ARGS="--verbose" || die "Test execution failed"
# These tools shall be of the same version as LLVM/Clang.
llvm-profdata merge -sparse tests/*.profraw -o profdata || die

# Generate coverage reports both for the SonarCloud scanner and for us humans.
llvm_cov_objects=""
for file in tests/test_*_*; do llvm_cov_objects="$llvm_cov_objects -object $file"; done
echo "llvm-cov objects: $llvm_cov_objects"
llvm-cov report $llvm_cov_objects -instr-profile=profdata || die
llvm-cov show   $llvm_cov_objects -instr-profile=profdata -format=text > "coverage.txt"  || die
llvm-cov show   $llvm_cov_objects -instr-profile=profdata -format=html > "coverage.html" || die

# Run SonarScanner from the project root.
cd ..
[ -d $BUILD_DIR ] || die "Unexpected directory structure"
# Please keep the entire sonar configuration only here to maintain encapsulation and simplicity.
# Related: https://community.sonarsource.com/t/analyzing-a-header-only-c-library/51468
sonar-scanner \
--define sonar.host.url="https://sonarcloud.io" \
--define sonar.projectName=libudpard \
--define sonar.organization=opencyphal-garage \
--define sonar.projectKey=libudpard \
--define sonar.sources=libudpard \
--define sonar.exclusions=libudpard/_udpard_cavl.h \
--define sonar.cfamily.compile-commands="$BUILD_DIR/compile_commands.json"
--define sonar.cfamily.llvm-cov.reportPath="$BUILD_DIR/coverage.txt" \
--define sonar.cfamily.threads="$(nproc)" \
|| die
