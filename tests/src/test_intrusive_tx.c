/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c> // NOLINT(bugprone-suspicious-include)
#include "helpers.h"
#include <unity.h>

static void test_tx_serialize_header(void)
{
    typedef struct
    {
        byte_t data[HEADER_SIZE_BYTES];
    } header_buffer_t;

    // Test case 1: Basic header serialization
    {
        header_buffer_t buffer;
        const meta_t    meta = {
               .priority              = udpard_prio_fast,
               .flag_ack              = false,
               .transfer_payload_size = 12345,
               .transfer_id           = 0xBADC0FFEE0DDF00DULL,
               .sender_uid            = 0x0123456789ABCDEFULL,
               .topic_hash            = 0xFEDCBA9876543210ULL,
        };
        (void)header_serialize(buffer.data, meta, 12345, 0, 0);
        TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES, sizeof(buffer.data));
        // Verify version and priority in first byte
        TEST_ASSERT_EQUAL((HEADER_VERSION | ((unsigned)udpard_prio_fast << 5U)), buffer.data[0]);
    }
    // Test case 2: Ack flag
    {
        header_buffer_t buffer;
        const meta_t    meta = {
               .priority              = udpard_prio_nominal,
               .flag_ack              = true,
               .transfer_payload_size = 5000,
               .transfer_id           = 0xAAAAAAAAAAAAAAAAULL,
               .sender_uid            = 0xBBBBBBBBBBBBBBBBULL,
               .topic_hash            = 0xCCCCCCCCCCCCCCCCULL,
        };
        (void)header_serialize(buffer.data, meta, 100, 200, 0);
        TEST_ASSERT_EQUAL((HEADER_VERSION | ((unsigned)udpard_prio_nominal << 5U)), buffer.data[0]);
        TEST_ASSERT_EQUAL(HEADER_FLAG_ACK, buffer.data[1]);
    }
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_tx_serialize_header);
    return UNITY_END();
}
