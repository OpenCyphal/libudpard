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
// >>> from pycyphal.transport import Priority, MessageDataSpecifier, ServiceDataSpecifier
// >>> frame = UDPFrame(priority=Priority.FAST, transfer_id=0xbadc0ffee0ddf00d, index=12345, end_of_transfer=False,
//  payload=memoryview(b''), source_node_id=2345, destination_node_id=5432,
//  data_specifier=MessageDataSpecifier(7654), user_data=0)
// >>> list(frame.compile_header_and_payload()[0])
// [1, 2, 41, 9, 56, 21, 230, 29, 13, 240, 221, 224, 254, 15, 220, 186, 57, 48, 0, 0, 0, 0, 224, 60]
static void testParseFrameValidMessage(void)
{
    byte_t  data[] = {1,   2,   41,  9,   255, 255, 230, 29, 13, 240, 221, 224,
                      254, 15,  220, 186, 57,  48,  0,   0,  0,  0,   30,  179,  //
                      'a', 'b', 'c'};
    RxFrame rxf    = {0};
    TEST_ASSERT(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
    TEST_ASSERT_EQUAL_UINT64(UdpardPriorityFast, rxf.meta.priority);
    TEST_ASSERT_EQUAL_UINT64(2345, rxf.meta.src_node_id);
    TEST_ASSERT_EQUAL_UINT64(UDPARD_NODE_ID_UNSET, rxf.meta.dst_node_id);
    TEST_ASSERT_EQUAL_UINT64(7654, rxf.meta.data_specifier);
    TEST_ASSERT_EQUAL_UINT64(0xbadc0ffee0ddf00d, rxf.meta.transfer_id);
    TEST_ASSERT_EQUAL_UINT64(12345, rxf.index);
    TEST_ASSERT_FALSE(rxf.end_of_transfer);
    TEST_ASSERT_EQUAL_UINT64(3, rxf.payload.size);
    TEST_ASSERT_EQUAL_UINT8_ARRAY("abc", rxf.payload.data, 3);
}

static void testParseFrameValidRPCService(void)
{
    // frame = UDPFrame(priority=Priority.FAST, transfer_id=0xbadc0ffee0ddf00d, index=6654, end_of_transfer=False,
    // payload=memoryview(b''), source_node_id=2345, destination_node_id=4567,
    // data_specifier=ServiceDataSpecifier(role=ServiceDataSpecifier.Role.REQUEST, service_id=123), user_data=0)
    byte_t  data[] = {1,   2,   41,  9,   215, 17, 123, 192, 13, 240, 221, 224,
                      254, 15,  220, 186, 254, 25, 0,   0,   0,  0,   173, 122,  //
                      'a', 'b', 'c'};
    RxFrame rxf    = {0};
    TEST_ASSERT(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
    TEST_ASSERT_EQUAL_UINT64(UdpardPriorityFast, rxf.meta.priority);
    TEST_ASSERT_EQUAL_UINT64(2345, rxf.meta.src_node_id);
    TEST_ASSERT_EQUAL_UINT64(4567, rxf.meta.dst_node_id);
    TEST_ASSERT_EQUAL_UINT64(123U | DATA_SPECIFIER_SERVICE_NOT_MESSAGE_MASK |
                                 DATA_SPECIFIER_SERVICE_REQUEST_NOT_RESPONSE_MASK,
                             rxf.meta.data_specifier);
    TEST_ASSERT_EQUAL_UINT64(0xbadc0ffee0ddf00d, rxf.meta.transfer_id);
    TEST_ASSERT_EQUAL_UINT64(6654, rxf.index);
    TEST_ASSERT_FALSE(rxf.end_of_transfer);
    TEST_ASSERT_EQUAL_UINT64(3, rxf.payload.size);
    TEST_ASSERT_EQUAL_UINT8_ARRAY("abc", rxf.payload.data, 3);
}

static void testParseFrameValidMessageAnonymous(void)
{
    byte_t  data[] = {1,   2,   255, 255, 255, 255, 230, 29,  13, 240, 221, 224,
                      254, 15,  220, 186, 0,   0,   0,   128, 0,  0,   168, 92,  //
                      'a', 'b', 'c'};
    RxFrame rxf    = {0};
    TEST_ASSERT(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
    TEST_ASSERT_EQUAL_UINT64(UdpardPriorityFast, rxf.meta.priority);
    TEST_ASSERT_EQUAL_UINT64(UDPARD_NODE_ID_UNSET, rxf.meta.src_node_id);
    TEST_ASSERT_EQUAL_UINT64(UDPARD_NODE_ID_UNSET, rxf.meta.dst_node_id);
    TEST_ASSERT_EQUAL_UINT64(7654, rxf.meta.data_specifier);
    TEST_ASSERT_EQUAL_UINT64(0xbadc0ffee0ddf00d, rxf.meta.transfer_id);
    TEST_ASSERT_EQUAL_UINT64(0, rxf.index);
    TEST_ASSERT_TRUE(rxf.end_of_transfer);
    TEST_ASSERT_EQUAL_UINT64(3, rxf.payload.size);
    TEST_ASSERT_EQUAL_UINT8_ARRAY("abc", rxf.payload.data, 3);
}

static void testParseFrameRPCServiceAnonymous(void)
{
    byte_t  data[] = {1,   2,   255, 255, 215, 17, 123, 192, 13, 240, 221, 224,
                      254, 15,  220, 186, 254, 25, 0,   0,   0,  0,   75,  79,  //
                      'a', 'b', 'c'};
    RxFrame rxf    = {0};
    TEST_ASSERT_FALSE(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
}

static void testParseFrameRPCServiceBroadcast(void)
{
    byte_t  data[] = {1,   2,   41,  9,   255, 255, 123, 192, 13, 240, 221, 224,
                      254, 15,  220, 186, 254, 25,  0,   0,   0,  0,   248, 152,  //
                      'a', 'b', 'c'};
    RxFrame rxf    = {0};
    TEST_ASSERT_FALSE(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
}

static void testParseFrameAnonymousNonSingleFrame(void)
{  // Invalid anonymous message frame because EOT not set (multi-frame anonymous transfers are not allowed).
    byte_t  data[] = {1,   2,   255, 255, 255, 255, 230, 29, 13, 240, 221, 224,
                      254, 15,  220, 186, 0,   0,   0,   0,  0,  0,   147, 6,  //
                      'a', 'b', 'c'};
    RxFrame rxf    = {0};
    TEST_ASSERT_FALSE(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
}

static void testParseFrameBadHeaderCRC(void)
{  // Bad header CRC.
    byte_t  data[] = {1,   2,   41,  9,   255, 255, 230, 29, 13, 240, 221, 224,
                      254, 15,  220, 186, 57,  48,  0,   0,  0,  0,   30,  180,  //
                      'a', 'b', 'c'};
    RxFrame rxf    = {0};
    TEST_ASSERT_FALSE(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
}

static void testParseFrameUnknownHeaderVersion(void)
{
    // >>> from pycyphal.transport.commons.crc import CRC16CCITT
    // >>> list(CRC16CCITT.new(bytes(
    //    [0, 2, 41, 9, 56, 21, 230, 29, 13, 240, 221, 224, 254, 15, 220, 186, 57, 48, 0, 0, 0, 0])).value_as_bytes)
    byte_t  data[] = {0,   2,   41,  9,   56, 21, 230, 29, 13, 240, 221, 224,
                      254, 15,  220, 186, 57, 48, 0,   0,  0,  0,   141, 228,  //
                      'a', 'b', 'c'};
    RxFrame rxf    = {0};
    TEST_ASSERT_FALSE(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
}

static void testParseFrameHeaderWithoutPayload(void)
{
    byte_t data[] = {1, 2, 41, 9, 255, 255, 230, 29, 13, 240, 221, 224, 254, 15, 220, 186, 57, 48, 0, 0, 0, 0, 30, 179};
    RxFrame rxf   = {0};
    TEST_ASSERT_FALSE(rxParseFrame((struct UdpardMutablePayload){.data = data, .size = sizeof(data)}, &rxf));
}

static void testParseFrameEmpty(void)
{
    RxFrame rxf = {0};
    TEST_ASSERT_FALSE(rxParseFrame((struct UdpardMutablePayload){.data = "", .size = 0}, &rxf));
}

static void testSessionSlotRestartEmpty(void)
{
    // TODO
}

static void testSessionSlotRestartNonEmpty(void)
{
    // TODO
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(testParseFrameValidMessage);
    RUN_TEST(testParseFrameValidRPCService);
    RUN_TEST(testParseFrameValidMessageAnonymous);
    RUN_TEST(testParseFrameRPCServiceAnonymous);
    RUN_TEST(testParseFrameRPCServiceBroadcast);
    RUN_TEST(testParseFrameAnonymousNonSingleFrame);
    RUN_TEST(testParseFrameBadHeaderCRC);
    RUN_TEST(testParseFrameUnknownHeaderVersion);
    RUN_TEST(testParseFrameHeaderWithoutPayload);
    RUN_TEST(testParseFrameEmpty);
    RUN_TEST(testSessionSlotRestartEmpty);
    RUN_TEST(testSessionSlotRestartNonEmpty);
    return UNITY_END();
}
