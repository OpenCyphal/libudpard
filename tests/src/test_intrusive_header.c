/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c> // NOLINT(bugprone-suspicious-include)
#include <unity.h>

// Recomputes and stores the header CRC after local edits.
static void rewrite_header_crc(byte_t* const datagram)
{
    const uint32_t crc = crc_full(HEADER_SIZE_BYTES - CRC_SIZE_BYTES, datagram);
    (void)serialize_u32(&datagram[HEADER_SIZE_BYTES - CRC_SIZE_BYTES], crc);
}

static void test_header_roundtrip(void)
{
    byte_t dgram[64] = { 0 };
    for (size_t i = HEADER_SIZE_BYTES; i < sizeof(dgram); i++) {
        dgram[i] = (byte_t)i;
    }

    // Build and serialize a valid first frame.
    const meta_t meta_in = {
        .priority              = udpard_prio_fast,
        .transfer_payload_size = (uint32_t)(sizeof(dgram) - HEADER_SIZE_BYTES),
        .transfer_id           = 0xAABBCCDDEEFF0011ULL,
        .sender_uid            = 0x1122334455667788ULL,
    };
    const uint32_t payload_crc = crc_full(sizeof(dgram) - HEADER_SIZE_BYTES, &dgram[HEADER_SIZE_BYTES]);
    (void)header_serialize(dgram, meta_in, 0, payload_crc);

    // Deserialize and verify all fields.
    meta_t         meta_out = { 0 };
    uint32_t       offset   = 0;
    uint32_t       prefix   = 0;
    udpard_bytes_t payload  = { 0 };
    TEST_ASSERT_TRUE(header_deserialize(
      (udpard_bytes_mut_t){ .size = sizeof(dgram), .data = dgram }, &meta_out, &offset, &prefix, &payload));
    TEST_ASSERT_EQUAL_UINT32(0, offset);
    TEST_ASSERT_EQUAL_UINT32(payload_crc, prefix);
    TEST_ASSERT_EQUAL_UINT32(sizeof(dgram) - HEADER_SIZE_BYTES, payload.size);
    TEST_ASSERT_EQUAL_PTR(&dgram[HEADER_SIZE_BYTES], payload.data);
    TEST_ASSERT_EQUAL_UINT32(meta_in.priority, meta_out.priority);
    TEST_ASSERT_EQUAL_UINT32(meta_in.transfer_payload_size, meta_out.transfer_payload_size);
    TEST_ASSERT_EQUAL_UINT64(meta_in.transfer_id & UDPARD_TRANSFER_ID_MASK, meta_out.transfer_id);
    TEST_ASSERT_EQUAL_UINT64(meta_in.sender_uid, meta_out.sender_uid);
}

static void test_header_validation(void)
{
    byte_t dgram[64] = { 0 };
    for (size_t i = HEADER_SIZE_BYTES; i < sizeof(dgram); i++) {
        dgram[i] = (byte_t)(0x55U ^ (byte_t)i);
    }
    const meta_t meta = {
        .priority              = udpard_prio_nominal,
        .transfer_payload_size = (uint32_t)(sizeof(dgram) - HEADER_SIZE_BYTES),
        .transfer_id           = 123,
        .sender_uid            = 456,
    };
    const uint32_t payload_crc = crc_full(sizeof(dgram) - HEADER_SIZE_BYTES, &dgram[HEADER_SIZE_BYTES]);
    (void)header_serialize(dgram, meta, 0, payload_crc);

    // Baseline validity.
    meta_t         meta_out = { 0 };
    uint32_t       offset   = 0;
    uint32_t       prefix   = 0;
    udpard_bytes_t payload  = { 0 };
    TEST_ASSERT_TRUE(header_deserialize(
      (udpard_bytes_mut_t){ .size = sizeof(dgram), .data = dgram }, &meta_out, &offset, &prefix, &payload));

    // Reject malformed datagram length.
    TEST_ASSERT_FALSE(header_deserialize(
      (udpard_bytes_mut_t){ .size = HEADER_SIZE_BYTES - 1U, .data = dgram }, &meta_out, &offset, &prefix, &payload));

    // Reject bad CRC.
    dgram[HEADER_SIZE_BYTES - 1U] ^= 0xA5U;
    TEST_ASSERT_FALSE(header_deserialize(
      (udpard_bytes_mut_t){ .size = sizeof(dgram), .data = dgram }, &meta_out, &offset, &prefix, &payload));
    dgram[HEADER_SIZE_BYTES - 1U] ^= 0xA5U;
    rewrite_header_crc(dgram);

    // Reject unsupported version.
    dgram[0] = (byte_t)((dgram[0] & 0xE0U) | 3U);
    rewrite_header_crc(dgram);
    TEST_ASSERT_FALSE(header_deserialize(
      (udpard_bytes_mut_t){ .size = sizeof(dgram), .data = dgram }, &meta_out, &offset, &prefix, &payload));
    dgram[0] = (byte_t)((dgram[0] & 0xE0U) | HEADER_VERSION);
    rewrite_header_crc(dgram);

    // Reject unsupported incompatibility flags.
    dgram[1] = 0x20U;
    rewrite_header_crc(dgram);
    TEST_ASSERT_FALSE(header_deserialize(
      (udpard_bytes_mut_t){ .size = sizeof(dgram), .data = dgram }, &meta_out, &offset, &prefix, &payload));
    dgram[1] = 0x00U;
    rewrite_header_crc(dgram);

    // Reject offset that would exceed the declared transfer payload size.
    (void)serialize_u32(&dgram[16], 0xFFFFFFF0U);
    rewrite_header_crc(dgram);
    TEST_ASSERT_FALSE(header_deserialize(
      (udpard_bytes_mut_t){ .size = sizeof(dgram), .data = dgram }, &meta_out, &offset, &prefix, &payload));

    // Reject bad first-frame prefix CRC.
    (void)header_serialize(dgram, meta, 0, payload_crc ^ 0xFFFFFFFFU);
    TEST_ASSERT_FALSE(header_deserialize(
      (udpard_bytes_mut_t){ .size = sizeof(dgram), .data = dgram }, &meta_out, &offset, &prefix, &payload));
}

void setUp(void) {}
void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_header_roundtrip);
    RUN_TEST(test_header_validation);
    return UNITY_END();
}
