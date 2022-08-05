# Compact Cyphal/UDP v0 in C

Libethard is a compact implementation of the Cyphal/UDP protocol stack in C99/C11 for high-integrity real-time
embedded systems.

[Cyphal](https://opencyphal.org) is an open lightweight data bus standard designed for reliable intravehicular
communication in aerospace and robotic applications via CAN bus, Ethernet, and other robust transports.

## WORK IN PROGRESS, NOT READY FOR FORMAL USE

**Read the docs in [`libethard/ethard.h`](/libethard/ethard.h).**

Building
```
cmake -B ./build -DCMAKE_BUILD_TYPE=Debug -DNO_STATIC_ANALYSIS=1 -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DCMAKE_EXPORT_COMPILE_COMMANDS=1 tests
```
Testing
```
cd build
make test
```

## Features, Description, and Usage

To be added at a later date.

## Revisions
### v0.0

Prototype commit
