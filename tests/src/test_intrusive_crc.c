/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c>  // NOLINT(bugprone-suspicious-include)
#include <unity.h>

static void testHeaderCRC(void)
{
    TEST_ASSERT_EQUAL_UINT16(0x29B1U, headerCRCCompute(9, "123456789"));
}

static void testTransferCRC(void)
{
    uint32_t crc = transferCRCAdd(TRANSFER_CRC_INITIAL, 3, "123");
    crc          = transferCRCAdd(crc, 6, "456789");
    TEST_ASSERT_EQUAL_UINT32(0x1CF96D7CUL, crc);
    TEST_ASSERT_EQUAL_UINT32(0xE3069283UL, crc ^ TRANSFER_CRC_OUTPUT_XOR);
    crc = transferCRCAdd(crc,
                         4,
                         "\x83"  // Least significant byte first.
                         "\x92"
                         "\x06"
                         "\xE3");
    TEST_ASSERT_EQUAL_UINT32(0xB798B438UL, crc);
    TEST_ASSERT_EQUAL_UINT32(0x48674BC7UL, crc ^ TRANSFER_CRC_OUTPUT_XOR);
}

void setUp(void)
{
}

void tearDown(void)
{
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(testHeaderCRC);
    RUN_TEST(testTransferCRC);
    return UNITY_END();
}
