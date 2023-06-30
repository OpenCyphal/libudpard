/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#pragma once

#include <udpard.h>  // Must be always included first.
#include <cstdarg>
#include <cstdint>
#include <limits>
#include <stdexcept>

/// Definitions that are not exposed by the library but that are needed for testing.
/// Please keep them in sync with the library by manually updating as necessary.
namespace exposed
{
// Extern C effectively discards the outer namespaces.
extern "C" {
std::uint16_t headerCRCCompute(const std::size_t size, const void* const data);

std::uint32_t transferCRCAdd(const std::uint32_t crc, const std::size_t size, const void* const data);
}
}  // namespace exposed
