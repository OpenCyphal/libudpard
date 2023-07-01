/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.h>
#include "helpers.hpp"
#include <gtest/gtest.h>

TEST(TxPublic, TxInit)
{
    std::monostate     user_referent;
    const UdpardNodeID node_id = 0;
    ASSERT_EQ(-UDPARD_ERROR_INVALID_ARGUMENT,
              udpardTxInit(nullptr,
                           &node_id,
                           0,
                           UdpardMemoryResource{
                               .allocate       = &helpers::dummy_allocator::allocate,
                               .free           = &helpers::dummy_allocator::free,
                               .user_reference = &user_referent,
                           }));
    UdpardTx tx{};
    ASSERT_EQ(-UDPARD_ERROR_INVALID_ARGUMENT,
              udpardTxInit(&tx,
                           nullptr,
                           0,
                           UdpardMemoryResource{
                               .allocate       = &helpers::dummy_allocator::allocate,
                               .free           = &helpers::dummy_allocator::free,
                               .user_reference = &user_referent,
                           }));
    ASSERT_EQ(-UDPARD_ERROR_INVALID_ARGUMENT,
              udpardTxInit(&tx,
                           &node_id,
                           0,
                           UdpardMemoryResource{
                               .allocate       = nullptr,
                               .free           = &helpers::dummy_allocator::free,
                               .user_reference = &user_referent,
                           }));
    ASSERT_EQ(-UDPARD_ERROR_INVALID_ARGUMENT,
              udpardTxInit(&tx,
                           &node_id,
                           0,
                           UdpardMemoryResource{
                               .allocate       = &helpers::dummy_allocator::allocate,
                               .free           = nullptr,
                               .user_reference = &user_referent,
                           }));
    ASSERT_EQ(0,
              udpardTxInit(&tx,
                           &node_id,
                           0,
                           UdpardMemoryResource{
                               .allocate       = &helpers::dummy_allocator::allocate,
                               .free           = &helpers::dummy_allocator::free,
                               .user_reference = &user_referent,
                           }));
    ASSERT_EQ(&user_referent, tx.memory.user_reference);
    ASSERT_EQ(UDPARD_MTU_DEFAULT, tx.mtu);
}
