# LibUDPard instructions for AI agents

Please read `README.md` for general information about LibUDPard, and `CONTRIBUTING.md` for development-related notes.

DO NOT COMMENT THE CODE unless comments add critical information that is impossible to infer from reading the code (design rationale, gotchas, etc), in which case extremely terse comments are allowed.

If you need a build directory, create one in the project root named with a `build` prefix;
you can also use existing build directories if you prefer so,
but avoid using `cmake-build-*` because these are used by CLion.
When building the code, don't hesitate to use multiple jobs to use all CPU cores.

Run all tests in debug build to ensure that all assertion checks are enabled.

It is best to use Clang-Format to format the code when done editing.
