/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include "exposed.hpp"
#include <gtest/gtest.h>

TEST(CRC, Header)
{
    using exposed::headerCRCCompute;
    ASSERT_EQ(0x29B1U, headerCRCCompute(9, "123456789"));
}

TEST(CRC, Transfer)
{
    using exposed::transferCRCAdd;
    constexpr std::uint32_t OutputXOR = 0xFFFFFFFFU;
    auto                    crc       = transferCRCAdd(0xFFFFFFFFU, 3, "123");
    crc                               = transferCRCAdd(crc, 6, "456789");
    ASSERT_EQ(0x1CF96D7CUL, crc);
    ASSERT_EQ(0xE3069283UL, crc ^ OutputXOR);
    crc = transferCRCAdd(crc,
                         4,
                         "\x83"  // Least significant byte first.
                         "\x92"
                         "\x06"
                         "\xE3");
    ASSERT_EQ(0xB798B438UL, crc);
    ASSERT_EQ(0x48674BC7UL, crc ^ OutputXOR);
}
