/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include "exposed.hpp"
#include <gtest/gtest.h>

// Generate reference data using PyCyphal:
//
// >>> from pycyphal.transport.udp import UDPFrame
// >>> from pycyphal.transport import Priority, MessageDataSpecifier
// >>> frame = UDPFrame(priority=Priority.FAST, transfer_id=0xbadc0ffee0ddf00d, index=12345, end_of_transfer=False,
//  payload=memoryview(b''), source_node_id=2345, destination_node_id=5432,
//  data_specifier=MessageDataSpecifier(7654), user_data=0)
// >>> list(frame.compile_header_and_payload()[0])
// [1, 2, 41, 9, 56, 21, 230, 29, 13, 240, 221, 224, 254, 15, 220, 186, 57, 48, 0, 0, 0, 0, 224, 60]
TEST(TxPrivate, SerializeHeader)
{
    using exposed::txSerializeHeader;
    using exposed::Metadata;
    using HeaderBuffer = std::array<exposed::byte_t, 24>;
    {
        HeaderBuffer   buffer{};
        const Metadata meta{
            .priority       = UdpardPriorityFast,
            .src_node_id    = 2345,
            .dst_node_id    = 5432,
            .data_specifier = 7654,
            .transfer_id    = 0xBADC'0FFE'E0DD'F00dULL,

        };
        ASSERT_EQ(buffer.end(), txSerializeHeader(buffer.data(), &meta, 12345, false));
        const HeaderBuffer ref{
            {1, 2, 41, 9, 56, 21, 230, 29, 13, 240, 221, 224, 254, 15, 220, 186, 57, 48, 0, 0, 0, 0, 224, 60}};
        ASSERT_EQ(ref, buffer);
    }
    {
        HeaderBuffer   buffer{};
        const Metadata meta{
            .priority       = UdpardPriorityLow,
            .src_node_id    = 0xFEDC,
            .dst_node_id    = 0xBA98,
            .data_specifier = 1234,
            .transfer_id    = 0x0BAD'C0DE'0BAD'C0DEULL,

        };
        ASSERT_EQ(buffer.end(), txSerializeHeader(buffer.data(), &meta, 0x7FFF, true));
        const HeaderBuffer ref{
            {1, 5, 220, 254, 152, 186, 210, 4, 222, 192, 173, 11, 222, 192, 173, 11, 255, 127, 0, 128, 0, 0, 229, 4}};
        ASSERT_EQ(ref, buffer);
    }
}
