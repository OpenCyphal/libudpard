/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c>  // NOLINT(bugprone-suspicious-include)
#include "helpers.h"
#include <unity.h>

// Generate reference data using PyCyphal:
//
// >>> from pycyphal.transport.udp import UDPFrame
// >>> from pycyphal.transport import Priority, MessageDataSpecifier
// >>> frame = UDPFrame(priority=Priority.FAST, transfer_id=0xbadc0ffee0ddf00d, index=12345, end_of_transfer=False,
//  payload=memoryview(b''), source_node_id=2345, destination_node_id=5432,
//  data_specifier=MessageDataSpecifier(7654), user_data=0)
// >>> list(frame.compile_header_and_payload()[0])
// [1, 2, 41, 9, 56, 21, 230, 29, 13, 240, 221, 224, 254, 15, 220, 186, 57, 48, 0, 0, 0, 0, 224, 60]
void testRxParseFrame(void)
{
    {                                                                                  // Valid frame.
        const byte_t data[] = {1,   2,   41,  9,   56, 21, 230, 29, 13, 240, 221, 224,
                               254, 15,  220, 186, 57, 48, 0,   0,  0,  0,   224, 60,  //
                               'a', 'b', 'c'};
        RxFrame      rxf    = {0};
        TEST_ASSERT(rxParseFrame((UdpardConstPayload){.data = data, .size = sizeof(data)}, &rxf));
        TEST_ASSERT_EQUAL_UINT64(UdpardPriorityFast, rxf.meta.priority);
        TEST_ASSERT_EQUAL_UINT64(2345, rxf.meta.src_node_id);
        TEST_ASSERT_EQUAL_UINT64(5432, rxf.meta.dst_node_id);
        TEST_ASSERT_EQUAL_UINT64(7654, rxf.meta.data_specifier);
        TEST_ASSERT_EQUAL_UINT64(0xbadc0ffee0ddf00d, rxf.meta.transfer_id);
        TEST_ASSERT_EQUAL_UINT64(12345, rxf.frame_index);
        TEST_ASSERT_FALSE(rxf.end_of_transfer);
        TEST_ASSERT_EQUAL_UINT64(3, rxf.payload.size);
        TEST_ASSERT_EQUAL_UINT8_ARRAY("abc", rxf.payload.data, 3);
    }
    {                                                                                  // Bad header CRC.
        const byte_t data[] = {1,   2,   41,  9,   56, 21, 230, 29, 13, 240, 221, 224,
                               254, 15,  220, 186, 57, 48, 0,   0,  0,  0,   224, 61,  //
                               'a', 'b', 'c'};
        RxFrame      rxf    = {0};
        TEST_ASSERT_FALSE(rxParseFrame((UdpardConstPayload){.data = data, .size = sizeof(data)}, &rxf));
    }
    {  // Unsupported header version.
        // >>> from pycyphal.transport.commons.crc import CRC16CCITT
        // >>> list(CRC16CCITT.new(bytes(
        //    [0, 2, 41, 9, 56, 21, 230, 29, 13, 240, 221, 224, 254, 15, 220, 186, 57, 48, 0, 0, 0, 0])).value_as_bytes)
        const byte_t data[] = {0,   2,   41,  9,   56, 21, 230, 29, 13, 240, 221, 224,
                               254, 15,  220, 186, 57, 48, 0,   0,  0,  0,   141, 228,  //
                               'a', 'b', 'c'};
        RxFrame      rxf    = {0};
        TEST_ASSERT_FALSE(rxParseFrame((UdpardConstPayload){.data = data, .size = sizeof(data)}, &rxf));
    }
    {  // No frame payload, just the valid header (not acceptable).
        const byte_t data[] = {1,   2,  41,  9,   56, 21, 230, 29, 13, 240, 221, 224,
                               254, 15, 220, 186, 57, 48, 0,   0,  0,  0,   224, 60};
        RxFrame      rxf    = {0};
        TEST_ASSERT_FALSE(rxParseFrame((UdpardConstPayload){.data = data, .size = sizeof(data)}, &rxf));
    }
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(testRxParseFrame);
    return UNITY_END();
}
