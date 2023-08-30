# NOTICE

This package is a staging package to make changes before committing a pull request for the github repo: https://github.com/OpenCyphal-Garage/libudpard based on @schoberm's prototype work

# Compact Cyphal/UDP v1 in C

[![Main Workflow](https://github.com/OpenCyphal-Garage/libudpard/actions/workflows/main.yml/badge.svg)](https://github.com/OpenCyphal-Garage/libudpard/actions/workflows/main.yml)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=libudpard&metric=reliability_rating)](https://sonarcloud.io/summary?id=libudpard)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=libudpard&metric=coverage)](https://sonarcloud.io/summary?id=libudpard)
[![Forum](https://img.shields.io/discourse/users.svg?server=https%3A%2F%2Fforum.opencyphal.org&color=1700b3)](https://forum.opencyphal.org)

LibUDPard is a compact implementation of the Cyphal/UDP protocol stack in C99/C11 for high-integrity real-time
embedded systems.

[Cyphal](https://opencyphal.org) is an open lightweight data bus standard designed for reliable intravehicular
communication in aerospace and robotic applications via CAN bus, UDP, and other robust transports.

We pronounce LibUDPard as *lib-you-dee-pee-ard*.

## WORK IN PROGRESS, NOT READY FOR FORMAL USE

**Read the docs in [`libudpard/udpard.h`](/libudpard/udpard.h).**

Building
```
cmake -B ./build -DCMAKE_BUILD_TYPE=Debug -DNO_STATIC_ANALYSIS=1 -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DCMAKE_EXPORT_COMPILE_COMMANDS=1 tests
```
Testing
```
cd build
make
make test
```
Or to debug
```
TEST_OUTPUT_ON_FAILURE=TRUE make test
```

## Features, Description, and Usage

To be added at a later date.

## Revisions
### v0.0

Prototype commit
