// This software is distributed under the terms of the MIT License.
// Copyright (c) 2016-2020 OpenCyphal Development Team.

#include "helpers.hpp"
#include <gtest/gtest.h>

TEST(TestAllocator, Basic)
{
    helpers::TestAllocator al;

    ASSERT_EQ(0, al.getNumAllocatedFragments());
    ASSERT_EQ(std::numeric_limits<std::size_t>::max(), al.getAllocationCeiling());

    auto* a = al.allocate(123);
    ASSERT_EQ(1, al.getNumAllocatedFragments());
    ASSERT_EQ(123, al.getTotalAllocatedAmount());

    auto* b = al.allocate(456);
    ASSERT_EQ(2, al.getNumAllocatedFragments());
    ASSERT_EQ(579, al.getTotalAllocatedAmount());

    al.setAllocationCeiling(600);

    ASSERT_EQ(nullptr, al.allocate(100));
    ASSERT_EQ(2, al.getNumAllocatedFragments());
    ASSERT_EQ(579, al.getTotalAllocatedAmount());

    auto* c = al.allocate(21);
    ASSERT_EQ(3, al.getNumAllocatedFragments());
    ASSERT_EQ(600, al.getTotalAllocatedAmount());

    al.free(123, a);
    ASSERT_EQ(2, al.getNumAllocatedFragments());
    ASSERT_EQ(477, al.getTotalAllocatedAmount());

    auto* d = al.allocate(100);
    ASSERT_EQ(3, al.getNumAllocatedFragments());
    ASSERT_EQ(577, al.getTotalAllocatedAmount());

    al.free(21, c);
    ASSERT_EQ(2, al.getNumAllocatedFragments());
    ASSERT_EQ(556, al.getTotalAllocatedAmount());

    al.free(100, d);
    ASSERT_EQ(1, al.getNumAllocatedFragments());
    ASSERT_EQ(456, al.getTotalAllocatedAmount());

    al.free(456, b);
    ASSERT_EQ(0, al.getNumAllocatedFragments());
    ASSERT_EQ(0, al.getTotalAllocatedAmount());
}
