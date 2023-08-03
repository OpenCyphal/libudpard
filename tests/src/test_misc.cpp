/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.h>
#include "hexdump.hpp"
#include <unity.h>
#include <iostream>
#include <array>
#include <algorithm>

namespace
{
void testGather()
{
    const std::string_view payload =
        "It's very simple. The attacker must first transform themselves into life forms that can survive in a "
        "low-dimensional universe. For instance, a four-dimensional species can transform itself into "
        "three-dimensional creatures, or a three-dimensional species can transform itself into two-dimensional life. "
        "After the entire civilization has entered a lower dimension, they can initiate a dimensional strike against "
        "the enemy without concern for the consequences.";

    std::array<UdpardFragment, 4> frags{{}};
    frags.at(0).next = &frags.at(1);
    frags.at(1).next = &frags.at(2);
    frags.at(2).next = &frags.at(3);
    frags.at(3).next = nullptr;

    frags.at(0).view.data = payload.data();
    frags.at(0).view.size = 100;

    frags.at(1).view.data = payload.data() + frags.at(0).view.size;
    frags.at(1).view.size = 100;

    frags.at(2).view.data = payload.data() + frags.at(1).view.size + frags.at(0).view.size;
    frags.at(2).view.size = 0;  // Edge case.

    frags.at(3).view.data = payload.data() + frags.at(2).view.size + frags.at(1).view.size + frags.at(0).view.size;
    frags.at(3).view.size = payload.size() - frags.at(2).view.size - frags.at(1).view.size - frags.at(0).view.size;

    std::array<std::uint8_t, 1024> mono{};

    // Copy full size payload.
    std::generate(mono.begin(), mono.end(), [] { return std::rand() % 256; });
    TEST_ASSERT_EQUAL(payload.size(), udpardGather(frags.at(0), mono.size(), mono.data()));
    TEST_ASSERT_EQUAL_MEMORY(payload.data(), mono.data(), payload.size());

    // Truncation mid-fragment.
    std::generate(mono.begin(), mono.end(), [] { return std::rand() % 256; });
    TEST_ASSERT_EQUAL(150, udpardGather(frags.at(0), 150, mono.data()));
    TEST_ASSERT_EQUAL_MEMORY(payload.data(), mono.data(), 150);

    // Truncation at the fragment boundary.
    std::generate(mono.begin(), mono.end(), [] { return std::rand() % 256; });
    TEST_ASSERT_EQUAL(200, udpardGather(frags.at(0), 200, mono.data()));
    TEST_ASSERT_EQUAL_MEMORY(payload.data(), mono.data(), 200);

    // Empty destination.
    mono.fill(0xA5);
    TEST_ASSERT_EQUAL(0, udpardGather(frags.at(0), 0, mono.data()));
    TEST_ASSERT_EQUAL(0, std::count_if(mono.begin(), mono.end(), [](const auto x) { return x != 0xA5; }));

    // Edge cases.
    TEST_ASSERT_EQUAL(0, udpardGather(frags.at(0), 0, nullptr));
    TEST_ASSERT_EQUAL(0, udpardGather(frags.at(0), 100, nullptr));
}
}  // namespace

void setUp() {}

void tearDown() {}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(testGather);
    return UNITY_END();
}
