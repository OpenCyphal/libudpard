// This software is distributed under the terms of the MIT License.
// Copyright (c) 2016-2020 OpenCyphal Development Team.
// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

#include "exposed.hpp"
#include "catch.hpp"

TEST_CASE("TransferCRC")
{
    using exposed::crcAdd;
    using exposed::crcValue;
    std::uint32_t crc = 0xFFFFFFFFU;

    crc = crcAdd(crc, 1, "1");
    REQUIRE(0x90F599E3U == crcValue(crc));
    crc = crcAdd(crc, 1, "2");
    REQUIRE(0x7355C460U == crcValue(crc));
    crc = crcAdd(crc, 1, "3");
    REQUIRE(0x107B2FB2U == crcValue(crc));

    crc = crcAdd(crc, 6, "456789");
    REQUIRE(0xE3069283U == crcValue(crc));
}

TEST_CASE("CyphalHeaderCRC")
{
    using exposed::cyphalHeaderCrcAdd;

    std::uint16_t crc = 0xFFFFU;
    const uint8_t* header = reinterpret_cast<const uint8_t*>("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21\x22\x23\x24");
    crc = cyphalHeaderCrcAdd(crc, 22, header);
    REQUIRE(0xB731 == crc);
}
