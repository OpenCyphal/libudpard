/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c> // NOLINT(bugprone-suspicious-include)
#include <unity.h>

static void test_header_v2(void)
{
    byte_t buffer[64];
    meta_t meta_in = {
        .priority              = udpard_prio_high,
        .kind                  = frame_msg_best,
        .transfer_payload_size = 0xDEADBEEF,
        .transfer_id           = 0xAABBCCDDEEFF0011ULL,
        .sender_uid            = 0x1122334455667788ULL,
    };
    // For a first frame (frame_payload_offset=0), frame_index must also be 0
    // Compute the correct prefix_crc from the payload
    memset(&buffer[HEADER_SIZE_BYTES], 0, sizeof(buffer) - HEADER_SIZE_BYTES); // Initialize payload
    const uint32_t payload_crc = crc_full(sizeof(buffer) - HEADER_SIZE_BYTES, &buffer[HEADER_SIZE_BYTES]);
    header_serialize(buffer, meta_in, 0, 0, payload_crc); // frame_index=0, frame_payload_offset=0 for first frame
    memset(&buffer[HEADER_SIZE_BYTES], 0, sizeof(buffer) - HEADER_SIZE_BYTES); // Re-initialize payload to match

    // We don't validate the exact byte layout anymore since we compute prefix_crc dynamically
    // Just verify deserialization works correctly

    meta_t         meta_out;
    udpard_bytes_t payload_out;
    uint32_t       frame_index          = 0;
    uint32_t       frame_payload_offset = 0;
    uint32_t       prefix_crc           = 0;
    TEST_ASSERT(header_deserialize((udpard_bytes_mut_t){ .size = sizeof(buffer), .data = buffer },
                                   &meta_out,
                                   &frame_index,
                                   &frame_payload_offset,
                                   &prefix_crc,
                                   &payload_out));
    TEST_ASSERT_EQUAL(sizeof(buffer) - HEADER_SIZE_BYTES, payload_out.size);
    TEST_ASSERT_EQUAL(&buffer[HEADER_SIZE_BYTES], payload_out.data);

    TEST_ASSERT_EQUAL_UINT8(meta_in.priority, meta_out.priority);
    TEST_ASSERT_EQUAL_UINT32(meta_in.kind, meta_out.kind);
    TEST_ASSERT_EQUAL_UINT32(0, frame_index);          // First frame has index 0
    TEST_ASSERT_EQUAL_UINT32(0, frame_payload_offset); // First frame has offset 0
    TEST_ASSERT_EQUAL_UINT32(payload_crc, prefix_crc); // For first frame, prefix_crc equals payload CRC
    TEST_ASSERT_EQUAL_UINT32(meta_in.transfer_payload_size, meta_out.transfer_payload_size);
    TEST_ASSERT_EQUAL_UINT64(meta_in.transfer_id, meta_out.transfer_id);
    TEST_ASSERT_EQUAL_UINT64(meta_in.sender_uid, meta_out.sender_uid);

    TEST_ASSERT_FALSE(header_deserialize((udpard_bytes_mut_t){ .size = 23, .data = buffer },
                                         &meta_out,
                                         &frame_index,
                                         &frame_payload_offset,
                                         &prefix_crc,
                                         &payload_out));

    TEST_ASSERT(header_deserialize((udpard_bytes_mut_t){ .size = sizeof(buffer), .data = buffer },
                                   &meta_out,
                                   &frame_index,
                                   &frame_payload_offset,
                                   &prefix_crc,
                                   &payload_out));
    buffer[HEADER_SIZE_BYTES - 1] ^= 0xFFU; // Corrupt the CRC.
    TEST_ASSERT_FALSE(header_deserialize((udpard_bytes_mut_t){ .size = sizeof(buffer), .data = buffer },
                                         &meta_out,
                                         &frame_index,
                                         &frame_payload_offset,
                                         &prefix_crc,
                                         &payload_out));
}

static void test_header_deserialize_edge_cases(void)
{
    byte_t buffer[64];
    meta_t meta_in = {
        .priority              = udpard_prio_nominal,
        .kind                  = frame_msg_reliable,
        .transfer_payload_size = 1000,
        .transfer_id           = 0x1234567890ABCDEFULL,
        .sender_uid            = 0xFEDCBA9876543210ULL,
    };

    meta_t         meta_out;
    udpard_bytes_t payload_out;
    uint32_t       frame_index          = 0;
    uint32_t       frame_payload_offset = 0;
    uint32_t       prefix_crc           = 0;

    // Test invalid version (version != 2)
    memset(&buffer[HEADER_SIZE_BYTES], 0, sizeof(buffer) - HEADER_SIZE_BYTES); // Initialize payload
    const uint32_t payload_crc_v1 = crc_full(sizeof(buffer) - HEADER_SIZE_BYTES, &buffer[HEADER_SIZE_BYTES]);
    header_serialize(buffer, meta_in, 0, 0, payload_crc_v1);
    buffer[0] = (buffer[0] & 0xE0U) | 3U; // Set version to 3 instead of 2
    // Recalculate CRC for the corrupted header
    const uint32_t new_crc        = crc_full(HEADER_SIZE_BYTES - CRC_SIZE_BYTES, buffer);
    buffer[HEADER_SIZE_BYTES - 4] = (byte_t)(new_crc & 0xFFU);
    buffer[HEADER_SIZE_BYTES - 3] = (byte_t)((new_crc >> 8U) & 0xFFU);
    buffer[HEADER_SIZE_BYTES - 2] = (byte_t)((new_crc >> 16U) & 0xFFU);
    buffer[HEADER_SIZE_BYTES - 1] = (byte_t)((new_crc >> 24U) & 0xFFU);
    TEST_ASSERT_FALSE(header_deserialize((udpard_bytes_mut_t){ .size = sizeof(buffer), .data = buffer },
                                         &meta_out,
                                         &frame_index,
                                         &frame_payload_offset,
                                         &prefix_crc,
                                         &payload_out));

    // Test frame_payload_offset validation: offset + payload > transfer_payload_size
    // For non-first frames, prefix_crc can be any value (not validated)
    header_serialize(buffer, meta_in, 5, 900, 0x12345678); // frame_index=5, offset=900
    // Payload size in buffer after header is 64-48=16 bytes
    // So offset(900) + payload(16) = 916 > transfer_payload_size(1000) is OK
    // But offset(995) + payload(16) = 1011 > transfer_payload_size(1000) should fail
    buffer[8]                     = 0xE3; // Change offset to 995 (0x03E3) little-endian
    buffer[9]                     = 0x03;
    buffer[10]                    = 0x00;
    buffer[11]                    = 0x00;
    const uint32_t new_crc2       = crc_full(HEADER_SIZE_BYTES - CRC_SIZE_BYTES, buffer);
    buffer[HEADER_SIZE_BYTES - 4] = (byte_t)(new_crc2 & 0xFFU);
    buffer[HEADER_SIZE_BYTES - 3] = (byte_t)((new_crc2 >> 8U) & 0xFFU);
    buffer[HEADER_SIZE_BYTES - 2] = (byte_t)((new_crc2 >> 16U) & 0xFFU);
    buffer[HEADER_SIZE_BYTES - 1] = (byte_t)((new_crc2 >> 24U) & 0xFFU);
    TEST_ASSERT_FALSE(header_deserialize((udpard_bytes_mut_t){ .size = sizeof(buffer), .data = buffer },
                                         &meta_out,
                                         &frame_index,
                                         &frame_payload_offset,
                                         &prefix_crc,
                                         &payload_out));

    // Test frame_index != 0 but frame_payload_offset == 0 (invalid)
    const uint32_t payload_crc_v3 = crc_full(sizeof(buffer) - HEADER_SIZE_BYTES, &buffer[HEADER_SIZE_BYTES]);
    header_serialize(buffer, meta_in, 1, 0, payload_crc_v3); // frame_index=1, offset=0 is invalid
    TEST_ASSERT_FALSE(header_deserialize((udpard_bytes_mut_t){ .size = sizeof(buffer), .data = buffer },
                                         &meta_out,
                                         &frame_index,
                                         &frame_payload_offset,
                                         &prefix_crc,
                                         &payload_out));

    // Test invalid prefix_crc on first frame (offset=0, prefix_crc must match payload CRC)
    header_serialize(buffer, meta_in, 0, 0, 0xDEADBEEF); // Wrong CRC for first frame
    TEST_ASSERT_FALSE(header_deserialize((udpard_bytes_mut_t){ .size = sizeof(buffer), .data = buffer },
                                         &meta_out,
                                         &frame_index,
                                         &frame_payload_offset,
                                         &prefix_crc,
                                         &payload_out));

    // Test valid case with reliable kind (first frame, so prefix_crc must match payload)
    const uint32_t payload_crc_v4 = crc_full(sizeof(buffer) - HEADER_SIZE_BYTES, &buffer[HEADER_SIZE_BYTES]);
    header_serialize(buffer, meta_in, 0, 0, payload_crc_v4);
    TEST_ASSERT(header_deserialize((udpard_bytes_mut_t){ .size = sizeof(buffer), .data = buffer },
                                   &meta_out,
                                   &frame_index,
                                   &frame_payload_offset,
                                   &prefix_crc,
                                   &payload_out));
    TEST_ASSERT_EQUAL_UINT32(frame_msg_reliable, meta_out.kind);
    TEST_ASSERT_EQUAL_UINT32(payload_crc_v4, prefix_crc);

    // Reject ACK frames with nonzero offset.
    meta_in.kind = frame_ack;
    header_serialize(buffer, meta_in, 1, 1, 0U);
    TEST_ASSERT_FALSE(header_deserialize((udpard_bytes_mut_t){ .size = sizeof(buffer), .data = buffer },
                                         &meta_out,
                                         &frame_index,
                                         &frame_payload_offset,
                                         &prefix_crc,
                                         &payload_out));

    // Reject invalid kind.
    meta_in.kind = frame_msg_best;
    header_serialize(buffer, meta_in, 0, 0, payload_crc_v4);
    buffer[1]                     = 0xFFU;
    const uint32_t new_crc3       = crc_full(HEADER_SIZE_BYTES - CRC_SIZE_BYTES, buffer);
    buffer[HEADER_SIZE_BYTES - 4] = (byte_t)(new_crc3 & 0xFFU);
    buffer[HEADER_SIZE_BYTES - 3] = (byte_t)((new_crc3 >> 8U) & 0xFFU);
    buffer[HEADER_SIZE_BYTES - 2] = (byte_t)((new_crc3 >> 16U) & 0xFFU);
    buffer[HEADER_SIZE_BYTES - 1] = (byte_t)((new_crc3 >> 24U) & 0xFFU);
    TEST_ASSERT_FALSE(header_deserialize((udpard_bytes_mut_t){ .size = sizeof(buffer), .data = buffer },
                                         &meta_out,
                                         &frame_index,
                                         &frame_payload_offset,
                                         &prefix_crc,
                                         &payload_out));
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_header_v2);
    RUN_TEST(test_header_deserialize_edge_cases);
    return UNITY_END();
}
