# Compact Cyphal/UDP in C

[![Main Workflow](https://github.com/OpenCyphal-Garage/libudpard/actions/workflows/main.yml/badge.svg)](https://github.com/OpenCyphal-Garage/libudpard/actions/workflows/main.yml)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=libudpard&metric=reliability_rating)](https://sonarcloud.io/summary?id=libudpard)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=libudpard&metric=coverage)](https://sonarcloud.io/summary?id=libudpard)
[![Forum](https://img.shields.io/discourse/users.svg?server=https%3A%2F%2Fforum.opencyphal.org&color=1700b3)](https://forum.opencyphal.org)

LibUDPard is a compact implementation of the Cyphal/UDP protocol in C99/C11 for high-integrity real-time
embedded systems.

[Cyphal](https://opencyphal.org) is an open lightweight data bus standard designed for reliable intravehicular
communication in aerospace and robotic applications via CAN bus, UDP, and other robust transports.

We pronounce LibUDPard as *lib-you-dee-pee-ard*.

## Features

Some of the features listed here are intrinsic properties of Cyphal.

- Full branch coverage and extensive static analysis.

- Compliance with automatically enforceable MISRA C rules (reach out to https://forum.opencyphal.org for details).

- Detailed time complexity and memory requirement models for the benefit of real-time high-integrity applications.

- Purely reactive time-deterministic API without the need for background servicing.

- Zero-copy data pipeline on reception --
  payload is moved from the underlying NIC driver all the way to the application without copying.

- Support for redundant network interfaces with seamless interface aggregation and no fail-over delay.

- Out-of-order multi-frame transfer reassembly, including cross-transfer interleaved frames.

- Support for repetition-coding forward error correction (FEC) for lossy links (e.g., wireless)
  transparent to the application.

- No dependency on heap memory; the library can be used with fixed-size block pool allocators.

- Compatibility with all conventional 8/16/32/64-bit platforms.

- Compatibility with extremely resource-constrained baremetal environments starting from 64K ROM and 64K RAM.

- Implemented in ≈2000 lines of code.

## Usage

The library implements the Cyphal/UDP protocol, which is a transport-layer entity.
An application using this library will need to implement the presentation layer above the library,
perhaps with the help of the [Nunavut transpiler](https://github.com/OpenCyphal/nunavut),
and the network layer below the library using a third-party UDP/IP stack implementation with multicast/IGMP support
(TCP and ARP are not needed).
In the most straightforward case, the network layer can be based on the standard Berkeley socket API
or a lightweight embedded stack such as LwIP.

**Read the API docs in [`libudpard/udpard.h`](libudpard/udpard.h).**
For complete usage examples, please refer to <https://github.com/OpenCyphal-Garage/demos>.

## Revisions

### v1.0

Initial release.
