/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.h>
#include "helpers.h"
#include "hexdump.hpp"
#include <unity.h>
#include <cstdint>
#include <variant>
#include <cstring>
#include <iostream>
#include <array>

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

void testInit()
{
    std::monostate     user_referent;
    const UdpardNodeID node_id = 0;
    {
        const UdpardMemoryResource mr{
            .user_reference = &user_referent,
            .deallocate     = &dummyAllocatorDeallocate,
            .allocate       = &dummyAllocatorAllocate,
        };
        const UdpardTxMemoryResources memory = {.fragment = mr, .payload = mr};
        TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT, udpardTxInit(nullptr, &node_id, 0, memory));
    }
    {
        UdpardTx                   tx{};
        const UdpardMemoryResource mr{
            .user_reference = &user_referent,
            .deallocate     = &dummyAllocatorDeallocate,
            .allocate       = &dummyAllocatorAllocate,
        };
        const UdpardTxMemoryResources memory = {.fragment = mr, .payload = mr};
        TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT, udpardTxInit(&tx, nullptr, 0, memory));
    }
    {
        UdpardTx                   tx{};
        const UdpardMemoryResource mr{
            .user_reference = &user_referent,
            .deallocate     = &dummyAllocatorDeallocate,
            .allocate       = nullptr,
        };
        const UdpardTxMemoryResources memory = {.fragment = mr, .payload = mr};
        TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT, udpardTxInit(&tx, &node_id, 0, memory));
    }
    {
        UdpardTx                   tx{};
        const UdpardMemoryResource mr{
            .user_reference = &user_referent,
            .deallocate     = nullptr,
            .allocate       = &dummyAllocatorAllocate,
        };
        const UdpardTxMemoryResources memory = {.fragment = mr, .payload = mr};
        TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT, udpardTxInit(&tx, &node_id, 0, memory));
    }
    {
        UdpardTx                   tx{};
        const UdpardMemoryResource mr{
            .user_reference = &user_referent,
            .deallocate     = &dummyAllocatorDeallocate,
            .allocate       = &dummyAllocatorAllocate,
        };
        const UdpardTxMemoryResources memory = {.fragment = mr, .payload = mr};
        TEST_ASSERT_EQUAL(0, udpardTxInit(&tx, &node_id, 0, memory));
        TEST_ASSERT_EQUAL(&user_referent, tx.memory.fragment.user_reference);
        TEST_ASSERT_EQUAL(&user_referent, tx.memory.payload.user_reference);
        TEST_ASSERT_EQUAL(UDPARD_MTU_DEFAULT, tx.mtu);
    }
}

void testPublish()
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    const UdpardNodeID node_id = 1234;
    //
    UdpardTx tx{
        .local_node_id           = &node_id,
        .queue_capacity          = 1U,
        .mtu                     = UDPARD_MTU_DEFAULT,
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = mem,
        .queue_size              = 0,
        .root                    = nullptr,
    };
    std::monostate   user_transfer_referent;
    UdpardTransferID transfer_id = 0;
    TEST_ASSERT_EQUAL(1,
                      udpardTxPublish(&tx,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0x1432,
                                      transfer_id++,
                                      {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                      &user_transfer_referent));
    TEST_ASSERT_EQUAL(1 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(1, tx.queue_size);
    const auto* frame = udpardTxPeek(&tx);
    std::cout << hexdump::hexdump(frame->datagram_payload.data, frame->datagram_payload.size) << "\n\n";
    TEST_ASSERT_NOT_EQUAL(nullptr, frame);
    TEST_ASSERT_EQUAL(nullptr, frame->next_in_transfer);
    TEST_ASSERT_EQUAL(1234567890, frame->deadline_usec);
    TEST_ASSERT_EQUAL(4, frame->dscp);
    TEST_ASSERT_EQUAL(0xEF00'1432UL, frame->destination.ip_address);
    TEST_ASSERT_EQUAL(9382, frame->destination.udp_port);
    TEST_ASSERT_EQUAL(&user_transfer_referent, frame->user_transfer_reference);
    TEST_ASSERT_EQUAL(24 + FleetingEvents.size() + 4, frame->datagram_payload.size);
    TEST_ASSERT_EQUAL(0,
                      std::memcmp(static_cast<const std::uint_least8_t*>(frame->datagram_payload.data) + 24,
                                  FleetingEvents.data(),
                                  FleetingEvents.size()));
    TEST_ASSERT_EQUAL(0,
                      std::memcmp(static_cast<const std::uint_least8_t*>(frame->datagram_payload.data) + 24 +
                                      FleetingEvents.size(),
                                  FleetingEventsCRC.data(),
                                  FleetingEventsCRC.size()));
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));
    udpardTxFree(tx.memory, udpardTxPop(&tx, nullptr));  // No-op.

    // Out of queue; transfer-ID not incremented.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_CAPACITY,
                      udpardTxPublish(&tx,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0x1432,
                                      transfer_id,
                                      {.size = tx.mtu * 2, .data = FleetingEvents.data()},
                                      nullptr));

    // Attempt to publish a multi-frame transfer with an anonymous local node.
    {
        auto               tx_bad            = tx;
        const UdpardNodeID anonymous_node_id = 0xFFFFU;
        tx_bad.queue_size                    = 1000;
        tx_bad.mtu                           = 10;  // Force multi-frame.
        tx_bad.local_node_id                 = &anonymous_node_id;
        TEST_ASSERT_EQUAL(-UDPARD_ERROR_ANONYMOUS,
                          udpardTxPublish(&tx_bad,
                                          1234567890,
                                          UdpardPriorityNominal,
                                          0x1432,
                                          transfer_id,
                                          {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                          nullptr));
    }

    // Invalid Tx.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardTxPublish(nullptr,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0x1432,
                                      transfer_id,
                                      {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                      nullptr));
    // Invalid local node-ID.
    {
        auto tx_bad          = tx;
        tx_bad.local_node_id = nullptr;
        TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                          udpardTxPublish(&tx_bad,
                                          1234567890,
                                          UdpardPriorityNominal,
                                          0x1432,
                                          transfer_id,
                                          {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                          nullptr));
    }
    // Invalid priority.
    {
        auto bad_priority = UdpardPriorityOptional;
        TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                          udpardTxPublish(&tx,
                                          1234567890,
                                          (UdpardPriority) (bad_priority + 1),
                                          0x1432,
                                          transfer_id,
                                          {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                          nullptr));
    }
    // Invalid subject.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardTxPublish(&tx,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0xFFFFU,
                                      transfer_id,
                                      {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                      nullptr));
    // Invalid payload pointer.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardTxPublish(&tx,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0x1432,
                                      transfer_id,
                                      {.size = FleetingEvents.size(), .data = nullptr},
                                      nullptr));
    TEST_ASSERT_EQUAL(1, transfer_id);
}

void testRequest()
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    const UdpardNodeID node_id = 1234;
    //
    UdpardTx tx{
        .local_node_id           = &node_id,
        .queue_capacity          = 1U,
        .mtu                     = UDPARD_MTU_DEFAULT,
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = mem,
        .queue_size              = 0,
        .root                    = nullptr,
    };
    std::monostate   user_transfer_referent;
    UdpardTransferID transfer_id = 0;
    TEST_ASSERT_EQUAL(1,
                      udpardTxRequest(&tx,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0x123,
                                      0x1538,
                                      transfer_id++,
                                      {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                      &user_transfer_referent));
    TEST_ASSERT_EQUAL(1 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(1, tx.queue_size);
    const auto* frame = udpardTxPeek(&tx);
    std::cout << hexdump::hexdump(frame->datagram_payload.data, frame->datagram_payload.size) << "\n\n";
    TEST_ASSERT_NOT_EQUAL(nullptr, frame);
    TEST_ASSERT_EQUAL(nullptr, frame->next_in_transfer);
    TEST_ASSERT_EQUAL(1234567890, frame->deadline_usec);
    TEST_ASSERT_EQUAL(4, frame->dscp);
    TEST_ASSERT_EQUAL(0xEF01'1538UL, frame->destination.ip_address);
    TEST_ASSERT_EQUAL(9382, frame->destination.udp_port);
    TEST_ASSERT_EQUAL(&user_transfer_referent, frame->user_transfer_reference);
    TEST_ASSERT_EQUAL(24 + FleetingEvents.size() + 4, frame->datagram_payload.size);
    TEST_ASSERT_EQUAL(0,
                      std::memcmp(static_cast<const std::uint_least8_t*>(frame->datagram_payload.data) + 24,
                                  FleetingEvents.data(),
                                  FleetingEvents.size()));
    TEST_ASSERT_EQUAL(0,
                      std::memcmp(static_cast<const std::uint_least8_t*>(frame->datagram_payload.data) + 24 +
                                      FleetingEvents.size(),
                                  FleetingEventsCRC.data(),
                                  FleetingEventsCRC.size()));
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));
    udpardTxFree(tx.memory, udpardTxPop(&tx, nullptr));  // No-op.

    // Out of queue; transfer-ID not incremented.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_CAPACITY,
                      udpardTxRequest(&tx,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0x123,
                                      0x1538,
                                      transfer_id,
                                      {.size = tx.mtu * 2, .data = FleetingEvents.data()},
                                      nullptr));

    // Attempt to send a service transfer from an anonymous node.
    {
        auto               tx_bad            = tx;
        const UdpardNodeID anonymous_node_id = 0xFFFFU;
        tx_bad.queue_size                    = 1000;
        tx_bad.mtu                           = 10;  // Force multi-frame.
        tx_bad.local_node_id                 = &anonymous_node_id;
        TEST_ASSERT_EQUAL(-UDPARD_ERROR_ANONYMOUS,
                          udpardTxRequest(&tx_bad,
                                          1234567890,
                                          UdpardPriorityNominal,
                                          0x123,
                                          0x1538,
                                          transfer_id,
                                          {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                          nullptr));
    }

    // Invalid Tx.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardTxRequest(nullptr,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0x123,
                                      0x1538,
                                      transfer_id,
                                      {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                      nullptr));
    // Invalid local node-ID.
    {
        auto tx_bad          = tx;
        tx_bad.local_node_id = nullptr;
        TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                          udpardTxRequest(&tx_bad,
                                          1234567890,
                                          UdpardPriorityNominal,
                                          0x123,
                                          0x1538,
                                          transfer_id,
                                          {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                          nullptr));
    }
    // Invalid priority.
    {
        auto bad_priority = UdpardPriorityOptional;
        TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                          udpardTxRequest(&tx,
                                          1234567890,
                                          (UdpardPriority) (bad_priority + 1),
                                          0x123,
                                          0x1538,
                                          transfer_id,
                                          {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                          nullptr));
    }
    // Invalid remote node-ID.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardTxRequest(&tx,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0x123,
                                      0xFFFF,
                                      transfer_id,
                                      {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                      nullptr));
    // Invalid service-ID.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardTxRequest(&tx,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0xFFFFU,
                                      0x1538,
                                      transfer_id,
                                      {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                      nullptr));
    // Invalid payload pointer.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardTxRequest(&tx,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0x123,
                                      0x1538,
                                      transfer_id,
                                      {.size = FleetingEvents.size(), .data = nullptr},
                                      nullptr));
    TEST_ASSERT_EQUAL(1, transfer_id);
}

void testRespond()
{
    InstrumentedAllocator alloc;
    instrumentedAllocatorNew(&alloc);
    const UdpardTxMemoryResources mem = {
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc),
    };
    const UdpardNodeID node_id = 1234;
    //
    UdpardTx tx{
        .local_node_id           = &node_id,
        .queue_capacity          = 1U,
        .mtu                     = UDPARD_MTU_DEFAULT,
        .dscp_value_per_priority = {0, 1, 2, 3, 4, 5, 6, 7},
        .memory                  = mem,
        .queue_size              = 0,
        .root                    = nullptr,
    };
    std::monostate user_transfer_referent;
    TEST_ASSERT_EQUAL(1,
                      udpardTxRespond(&tx,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0x123,
                                      0x1538,
                                      9876543210,
                                      {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                      &user_transfer_referent));
    TEST_ASSERT_EQUAL(1 * 2ULL, alloc.allocated_fragments);
    TEST_ASSERT_EQUAL(1, tx.queue_size);
    const auto* frame = udpardTxPeek(&tx);
    std::cout << hexdump::hexdump(frame->datagram_payload.data, frame->datagram_payload.size) << "\n\n";
    TEST_ASSERT_NOT_EQUAL(nullptr, frame);
    TEST_ASSERT_EQUAL(nullptr, frame->next_in_transfer);
    TEST_ASSERT_EQUAL(1234567890, frame->deadline_usec);
    TEST_ASSERT_EQUAL(4, frame->dscp);
    TEST_ASSERT_EQUAL(0xEF01'1538UL, frame->destination.ip_address);
    TEST_ASSERT_EQUAL(9382, frame->destination.udp_port);
    TEST_ASSERT_EQUAL(&user_transfer_referent, frame->user_transfer_reference);
    TEST_ASSERT_EQUAL(24 + FleetingEvents.size() + 4, frame->datagram_payload.size);
    TEST_ASSERT_EQUAL(0,
                      std::memcmp(static_cast<const std::uint_least8_t*>(frame->datagram_payload.data) + 24,
                                  FleetingEvents.data(),
                                  FleetingEvents.size()));
    TEST_ASSERT_EQUAL(0,
                      std::memcmp(static_cast<const std::uint_least8_t*>(frame->datagram_payload.data) + 24 +
                                      FleetingEvents.size(),
                                  FleetingEventsCRC.data(),
                                  FleetingEventsCRC.size()));
    udpardTxFree(tx.memory, udpardTxPop(&tx, frame));
    udpardTxFree(tx.memory, udpardTxPop(&tx, nullptr));  // No-op.

    // Out of queue; transfer-ID not incremented.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_CAPACITY,
                      udpardTxRespond(&tx,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0x123,
                                      0x1538,
                                      0,
                                      {.size = tx.mtu * 2, .data = FleetingEvents.data()},
                                      nullptr));

    // Attempt to send a service transfer from an anonymous node.
    {
        auto               tx_bad            = tx;
        const UdpardNodeID anonymous_node_id = 0xFFFFU;
        tx_bad.queue_size                    = 1000;
        tx_bad.mtu                           = 10;  // Force multi-frame.
        tx_bad.local_node_id                 = &anonymous_node_id;
        TEST_ASSERT_EQUAL(-UDPARD_ERROR_ANONYMOUS,
                          udpardTxRespond(&tx_bad,
                                          1234567890,
                                          UdpardPriorityNominal,
                                          0x123,
                                          0x1538,
                                          0,
                                          {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                          nullptr));
    }

    // Invalid Tx.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardTxRespond(nullptr,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0x123,
                                      0x1538,
                                      0,
                                      {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                      nullptr));
    // Invalid local node-ID.
    {
        auto tx_bad          = tx;
        tx_bad.local_node_id = nullptr;
        TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                          udpardTxRespond(&tx_bad,
                                          1234567890,
                                          UdpardPriorityNominal,
                                          0x123,
                                          0x1538,
                                          0,
                                          {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                          nullptr));
    }
    // Invalid priority.
    {
        auto bad_priority = UdpardPriorityOptional;
        TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                          udpardTxRespond(&tx,
                                          1234567890,
                                          (UdpardPriority) (bad_priority + 1),
                                          0x123,
                                          0x1538,
                                          0,
                                          {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                          nullptr));
    }
    // Invalid remote node-ID.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardTxRespond(&tx,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0x123,
                                      0xFFFF,
                                      0,
                                      {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                      nullptr));
    // Invalid service-ID.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardTxRespond(&tx,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0xFFFFU,
                                      0x1538,
                                      0,
                                      {.size = FleetingEvents.size(), .data = FleetingEvents.data()},
                                      nullptr));
    // Invalid payload pointer.
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ARGUMENT,
                      udpardTxRespond(&tx,
                                      1234567890,
                                      UdpardPriorityNominal,
                                      0x123,
                                      0x1538,
                                      0,
                                      {.size = FleetingEvents.size(), .data = nullptr},
                                      nullptr));
}

void testPeekPopFreeNULL()  // Just make sure we don't crash.
{
    TEST_ASSERT_EQUAL(nullptr, udpardTxPeek(nullptr));
    TEST_ASSERT_EQUAL(nullptr, udpardTxPop(nullptr, nullptr));
    udpardTxFree({}, nullptr);
}

}  // namespace

void setUp() {}

void tearDown() {}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(testInit);
    RUN_TEST(testPublish);
    RUN_TEST(testRequest);
    RUN_TEST(testRespond);
    RUN_TEST(testPeekPopFreeNULL);
    return UNITY_END();
}
