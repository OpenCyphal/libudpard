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
using byte_t = std::uint_least8_t;

constexpr std::size_t HeaderSize = 24U;

// Extern C effectively discards the outer namespaces.
extern "C" {
struct Metadata final
{
    UdpardPriority   priority;
    UdpardNodeID     src_node_id;
    UdpardNodeID     dst_node_id;
    std::uint16_t    data_specifier;
    UdpardTransferID transfer_id;
};

struct TxItem final : public UdpardTxItem
{
    std::uint_least8_t precedence;
    // flex array not included
};

struct TxChain final
{
    TxItem*       head;
    TxItem*       tail;
    std::uint32_t count;
};

std::uint16_t headerCRCCompute(const std::size_t size, const void* const data);

std::uint32_t transferCRCAdd(const std::uint32_t crc, const std::size_t size, const void* const data);

byte_t* txSerializeHeader(byte_t* const       destination_buffer,
                          const Metadata      meta,
                          const std::uint32_t frame_index,
                          const bool          end_of_transfer);

TxChain txMakeChain(UdpardMemoryResource* const memory,
                    const std::uint_least8_t    dscp_value_per_priority[UDPARD_PRIORITY_MAX + 1U],
                    const std::size_t           mtu,
                    const UdpardMicrosecond     deadline_usec,
                    const Metadata              meta,
                    const UdpardUDPIPEndpoint   endpoint,
                    const UdpardConstPayload    payload,
                    void* const                 user_transfer_reference);
}
}  // namespace exposed
