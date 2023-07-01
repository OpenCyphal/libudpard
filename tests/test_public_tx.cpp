/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.h>
#include "helpers.hpp"
#include "hexdump.hpp"
#include <gtest/gtest.h>

namespace
{
constexpr std::string_view FleetingEvents =
    "What was the human world like in the eyes of the mountains? Perhaps just something they saw on a leisurely "
    "afternoon. First, a few small living beings appeared on the plain. After a while, they multiplied, and after "
    "another while they erected structures like anthills that quickly filled the region. The structures shone from the "
    "inside, and some of them let off smoke. After another while, the lights and smoke disappeared, and the small "
    "things vanished as well, and then their structures toppled and were buried in the sand. That was all. Among the "
    "countless things the mountains had witnessed, these fleeting events were not necessarily the most interesting.";
constexpr std::array<std::uint_least8_t, 4> FleetingEventsCRC{{26, 198, 18, 137}};
}  // namespace

TEST(TxPublic, TxInit)
{
    std::monostate     user_referent;
    const UdpardNodeID node_id = 0;
    {
        UdpardMemoryResource memory{
            .allocate       = &helpers::dummy_allocator::allocate,
            .free           = &helpers::dummy_allocator::free,
            .user_reference = &user_referent,
        };
        ASSERT_EQ(-UDPARD_ERROR_INVALID_ARGUMENT, udpardTxInit(nullptr, &node_id, 0, &memory));
    }
    {
        UdpardTx             tx{};
        UdpardMemoryResource memory{
            .allocate       = &helpers::dummy_allocator::allocate,
            .free           = &helpers::dummy_allocator::free,
            .user_reference = &user_referent,
        };
        ASSERT_EQ(-UDPARD_ERROR_INVALID_ARGUMENT, udpardTxInit(&tx, nullptr, 0, &memory));
    }
    {
        UdpardTx             tx{};
        UdpardMemoryResource memory{
            .allocate       = nullptr,
            .free           = &helpers::dummy_allocator::free,
            .user_reference = &user_referent,
        };
        ASSERT_EQ(-UDPARD_ERROR_INVALID_ARGUMENT, udpardTxInit(&tx, &node_id, 0, &memory));
    }
    {
        UdpardTx             tx{};
        UdpardMemoryResource memory{
            .allocate       = &helpers::dummy_allocator::allocate,
            .free           = nullptr,
            .user_reference = &user_referent,
        };
        ASSERT_EQ(-UDPARD_ERROR_INVALID_ARGUMENT, udpardTxInit(&tx, &node_id, 0, &memory));
    }
    {
        UdpardTx             tx{};
        UdpardMemoryResource memory{
            .allocate       = &helpers::dummy_allocator::allocate,
            .free           = &helpers::dummy_allocator::free,
            .user_reference = &user_referent,
        };
        ASSERT_EQ(0, udpardTxInit(&tx, &node_id, 0, &memory));
        ASSERT_EQ(&user_referent, tx.memory->user_reference);
        ASSERT_EQ(UDPARD_MTU_DEFAULT, tx.mtu);
    }
}

TEST(TxPublic, Publish)
{
    helpers::TestAllocator allocator;
    const UdpardNodeID     node_id = 1234;
    //
    UdpardTx tx{
        .local_node_id           = &node_id,
        .queue_capacity          = 1U,
        .mtu                     = UDPARD_MTU_DEFAULT,
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = &allocator,
        .queue_size              = 0,
        .root                    = nullptr,
    };
    std::monostate   user_transfer_referent;
    UdpardTransferID transfer_id = 0;
    ASSERT_EQ(1,
              udpardTxPublish(&tx,
                              1234567890,
                              UdpardPriorityNominal,
                              0x1432,
                              &transfer_id,
                              {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                              &user_transfer_referent));
    ASSERT_EQ(1, transfer_id);
    ASSERT_EQ(1, allocator.getNumAllocatedFragments());
    ASSERT_EQ(1, tx.queue_size);
    const auto* frame = udpardTxPeek(&tx);
    std::cout << hexdump::hexdump(frame->datagram_payload.data, frame->datagram_payload.size) << "\n\n";
    ASSERT_NE(nullptr, frame);
    ASSERT_EQ(nullptr, frame->next_in_transfer);
    ASSERT_EQ(1234567890, frame->deadline_usec);
    ASSERT_EQ(4, frame->dscp);
    ASSERT_EQ(0xEF00'1432UL, frame->destination.ip_address);
    ASSERT_EQ(UDPARD_UDP_PORT, frame->destination.udp_port);
    ASSERT_EQ(&user_transfer_referent, frame->user_transfer_reference);
    ASSERT_EQ(24 + FleetingEvents.size() + 4, frame->datagram_payload.size);
    ASSERT_EQ(0,
              memcmp(static_cast<const std::uint_least8_t*>(frame->datagram_payload.data) + 24,
                     FleetingEvents.data(),
                     FleetingEvents.size()));
    ASSERT_EQ(0,
              memcmp(static_cast<const std::uint_least8_t*>(frame->datagram_payload.data) + 24 + FleetingEvents.size(),
                     FleetingEventsCRC.data(),
                     FleetingEventsCRC.size()));
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));
    udpardTxFree(tx.memory, udpardTxPop(&tx, nullptr));  // No-op.

    // Out of queue; transfer-ID not incremented.
    ASSERT_EQ(-UDPARD_ERROR_CAPACITY_LIMIT,
              udpardTxPublish(&tx,
                              1234567890,
                              UdpardPriorityNominal,
                              0x1432,
                              &transfer_id,
                              {.size = tx.mtu * 2, .data = FleetingEvents.data()},
                              nullptr));
    ASSERT_EQ(1, transfer_id);

    // Invalid Tx.
    ASSERT_EQ(-UDPARD_ERROR_INVALID_ARGUMENT,
              udpardTxPublish(nullptr,
                              1234567890,
                              UdpardPriorityNominal,
                              0x1432,
                              &transfer_id,
                              {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                              nullptr));
    ASSERT_EQ(1, transfer_id);
    // Invalid local node-ID.
    auto tx_bad          = tx;
    tx_bad.local_node_id = nullptr;
    ASSERT_EQ(-UDPARD_ERROR_INVALID_ARGUMENT,
              udpardTxPublish(&tx_bad,
                              1234567890,
                              UdpardPriorityNominal,
                              0x1432,
                              &transfer_id,
                              {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                              nullptr));
    ASSERT_EQ(1, transfer_id);
    // Invalid priority.
    ASSERT_EQ(-UDPARD_ERROR_INVALID_ARGUMENT,
              udpardTxPublish(&tx,
                              1234567890,
                              (UdpardPriority) 255,
                              0x1432,
                              &transfer_id,
                              {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                              nullptr));
    ASSERT_EQ(1, transfer_id);
    // Invalid subject.
    ASSERT_EQ(-UDPARD_ERROR_INVALID_ARGUMENT,
              udpardTxPublish(&tx,
                              1234567890,
                              UdpardPriorityNominal,
                              0xFFFFU,
                              &transfer_id,
                              {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                              nullptr));
    ASSERT_EQ(1, transfer_id);
    // Invalid transfer-ID pointer.
    ASSERT_EQ(-UDPARD_ERROR_INVALID_ARGUMENT,
              udpardTxPublish(&tx,
                              1234567890,
                              UdpardPriorityNominal,
                              0x1432,
                              nullptr,
                              {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                              nullptr));
    // Invalid payload pointer.
    ASSERT_EQ(-UDPARD_ERROR_INVALID_ARGUMENT,
              udpardTxPublish(&tx,
                              1234567890,
                              UdpardPriorityNominal,
                              0x1432,
                              &transfer_id,
                              {.size = FleetingEvents.size(), .data = nullptr},
                              nullptr));
    ASSERT_EQ(1, transfer_id);
}

TEST(TxPublic, PeekPopFreeNULL)  // Just make sure we don't crash.
{
    ASSERT_EQ(nullptr, udpardTxPeek(nullptr));
    ASSERT_EQ(nullptr, udpardTxPop(nullptr, nullptr));
    udpardTxFree(nullptr, nullptr);
}
