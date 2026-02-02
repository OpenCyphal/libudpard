# LibUDPard contribution guidelines

## Standards

The library shall be implemented in ISO C99/C11 following MISRA C:2012.
The MISRA compliance is enforced by Clang-Tidy and SonarQube.
Deviations are documented directly in the source code as follows:

```c
// Intentional violation of MISRA: <some valid reason>
<... deviant construct ...>
```

The full list of deviations with the accompanying explanation can be found by grepping the sources.

Do not suppress compliance warnings using the means provided by static analysis tools because such deviations
are impossible to track at the source code level.
An exception applies for the case of false-positive (invalid) warnings -- those should not be mentioned in the codebase.

Unfortunately, some rules are hard or impractical to enforce automatically,
so code reviewers should be aware of MISRA and general high-reliability coding practices
to prevent non-compliant code from being accepted into upstream.

## Build & test

Consult with the CI workflow files for the required tools and build & test instructions.
You may want to use the [toolshed](https://github.com/OpenCyphal/docker_toolchains/pkgs/container/toolshed)
container for this.

To run tests with coverage reports, refer to the instructions in `tests/CMakeLists.txt`.

## Releasing

Simply create a new release & tag on GitHub.
