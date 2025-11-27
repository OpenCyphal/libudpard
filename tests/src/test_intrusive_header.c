/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c> // NOLINT(bugprone-suspicious-include)
#include <unity.h>

static void test_header_v2(void)
{
    byte_t   buffer[64];
    header_t hdr_in = {
        .priority              = udpard_prio_high,
        .flag_eot              = true,
        .flag_ack              = false,
        .frame_index           = 0x123456,
        .frame_payload_offset  = 0x654321,
        .transfer_payload_size = 0xDEADBEEF,
        .transfer_id           = 0xAABBCCDDEEFF0011ULL,
        .sender_uid            = 0x1122334455667788ULL,
        .topic_hash            = 0x99AABBCCDDEEFF00ULL,
    };

    header_serialize(buffer, hdr_in);

    // >>> from pycyphal.transport.commons.crc import CRC32C
    // >>> list(CRC32C.new(data).value_as_bytes)
    // clang-format off
    const byte_t reference[48] = {
        (2U | ((size_t)udpard_prio_high << 5U)),            // version | priority
        (HEADER_FLAG_EOT),                                  // flags
        0, 0,                                               // reserved
        0x56, 0x34, 0x12, 0x00,                             // frame_index
        0x21, 0x43, 0x65, 0x00,                             // frame_payload_offset
        0xEF, 0xBE, 0xAD, 0xDE,                             // transfer_payload_size
        0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,     // transfer_id
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,     // sender_uid
        0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99,     // topic_hash
        0, 0, 0, 0,                                         // reserved
        8, 200, 228, 86                                     // header CRC
    };
    // clang-format on
    TEST_ASSERT_EQUAL_MEMORY(reference, buffer, HEADER_SIZE_BYTES);

    header_t           hdr_out;
    udpard_bytes_mut_t payload_out;
    TEST_ASSERT(
      header_deserialize((udpard_bytes_mut_t){ .size = sizeof(buffer), .data = buffer }, &hdr_out, &payload_out));
    TEST_ASSERT_EQUAL(sizeof(buffer) - HEADER_SIZE_BYTES, payload_out.size);
    TEST_ASSERT_EQUAL(&buffer[HEADER_SIZE_BYTES], payload_out.data);

    TEST_ASSERT_EQUAL_UINT8(hdr_in.priority, hdr_out.priority);
    TEST_ASSERT_EQUAL_UINT8(hdr_in.flag_eot, hdr_out.flag_eot);
    TEST_ASSERT_EQUAL_UINT8(hdr_in.flag_ack, hdr_out.flag_ack);
    TEST_ASSERT_EQUAL_UINT32(hdr_in.frame_index, hdr_out.frame_index);
    TEST_ASSERT_EQUAL_UINT32(hdr_in.frame_payload_offset, hdr_out.frame_payload_offset);
    TEST_ASSERT_EQUAL_UINT32(hdr_in.transfer_payload_size, hdr_out.transfer_payload_size);
    TEST_ASSERT_EQUAL_UINT64(hdr_in.transfer_id, hdr_out.transfer_id);
    TEST_ASSERT_EQUAL_UINT64(hdr_in.sender_uid, hdr_out.sender_uid);
    TEST_ASSERT_EQUAL_UINT64(hdr_in.topic_hash, hdr_out.topic_hash);

    TEST_ASSERT_FALSE(header_deserialize((udpard_bytes_mut_t){ .size = 23, .data = buffer }, &hdr_out, &payload_out));

    TEST_ASSERT(
      header_deserialize((udpard_bytes_mut_t){ .size = sizeof(buffer), .data = buffer }, &hdr_out, &payload_out));
    buffer[HEADER_SIZE_BYTES - 1] ^= 0xFFU; // Corrupt the CRC.
    TEST_ASSERT_FALSE(
      header_deserialize((udpard_bytes_mut_t){ .size = sizeof(buffer), .data = buffer }, &hdr_out, &payload_out));
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_header_v2);
    return UNITY_END();
}
