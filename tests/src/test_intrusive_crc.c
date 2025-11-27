/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c> // NOLINT(bugprone-suspicious-include)
#include <unity.h>

static void test_crc(void)
{
    uint32_t crc = crc_add(CRC_INITIAL, 3, "123");
    crc          = crc_add(crc, 6, "456789");
    TEST_ASSERT_EQUAL_UINT32(0x1CF96D7CUL, crc);
    TEST_ASSERT_EQUAL_UINT32(0xE3069283UL, crc ^ CRC_OUTPUT_XOR);
    crc = crc_add(crc, 4, "\x83\x92\x06\xE3"); // Least significant byte first.
    TEST_ASSERT_EQUAL_UINT32(CRC_RESIDUE_BEFORE_OUTPUT_XOR, crc);
    TEST_ASSERT_EQUAL_UINT32(CRC_RESIDUE_AFTER_OUTPUT_XOR, crc ^ CRC_OUTPUT_XOR);
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_crc);
    return UNITY_END();
}
