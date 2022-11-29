// This software is distributed under the terms of the MIT License.
// Copyright (c) 2016 OpenCyphal Development Team.
/// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

#include "exposed.hpp"
#include "helpers.hpp"
#include "catch/catch.hpp"
#include <cstring>

TEST_CASE("TxBasic0")
{
    using exposed::TxItem;

    helpers::Instance ins;
    helpers::TxQueue  que(200, UDPARD_MTU_UDP_IPV4);

    auto& alloc = ins.getAllocator();

    std::array<std::uint8_t, 1024> payload{};
    for (std::size_t i = 0; i < std::size(payload); i++)
    {
        payload.at(i) = static_cast<std::uint8_t>(i & 0xFFU);
    }

    REQUIRE(UDPARD_NODE_ID_UNSET == ins.getNodeID());
    ins.setNodeAddr(0xc0a80000);
    REQUIRE(0xc0a80000 == ins.getNodeAddr());
    REQUIRE(UDPARD_MTU_UDP_IPV4 == que.getMTU());
    REQUIRE(0 == que.getSize());
    REQUIRE(0 == alloc.getNumAllocatedFragments());

    alloc.setAllocationCeiling(4000);

    UdpardTransferMetadata meta{};

    // Single-frame with padding.
    meta.priority       = UdpardPriorityNominal;
    meta.transfer_kind  = UdpardTransferKindMessage;
    meta.port_id        = 321;
    meta.remote_node_id = UDPARD_NODE_ID_UNSET;
    meta.transfer_id    = 21;
    REQUIRE(1 == que.push(&ins.getInstance(), 1'000'000'000'000ULL, meta, 8, payload.data()));
    REQUIRE(1 == que.getSize());
    REQUIRE(1 == alloc.getNumAllocatedFragments());
    REQUIRE(10 < alloc.getTotalAllocatedAmount());
    REQUIRE(160 > alloc.getTotalAllocatedAmount());
    REQUIRE(que.peek()->tx_deadline_usec == 1'000'000'000'000ULL);
    REQUIRE(que.peek()->frame.payload_size == 32);  // 8 + 24 header
    REQUIRE(que.peek()->getPayloadByte(0) == 0);    // Payload start. (starts after header)
    REQUIRE(que.peek()->getPayloadByte(1) == 1);
    REQUIRE(que.peek()->getPayloadByte(2) == 2);
    REQUIRE(que.peek()->getPayloadByte(3) == 3);
    REQUIRE(que.peek()->getPayloadByte(4) == 4);
    REQUIRE(que.peek()->getPayloadByte(5) == 5);
    REQUIRE(que.peek()->getPayloadByte(6) == 6);
    REQUIRE(que.peek()->getPayloadByte(7) == 7);  // Payload end.
    REQUIRE(que.peek()->isStartOfTransfer());     // Tail byte at the end.
    REQUIRE(que.peek()->isEndOfTransfer());

    meta.priority    = UdpardPriorityLow;
    meta.transfer_id = 22;
    ins.setNodeID(42);
    REQUIRE(1 == que.push(&ins.getInstance(), 1'000'000'000'100ULL, meta, 8, payload.data()));  // 8 bytes --> 2 frames
    REQUIRE(2 == que.getSize());
    REQUIRE(2 == alloc.getNumAllocatedFragments());
    REQUIRE(20 < alloc.getTotalAllocatedAmount());
    REQUIRE(400 > alloc.getTotalAllocatedAmount());

    // Check the TX queue.
    {
        const auto q = que.linearize();
        REQUIRE(2 == q.size());
        REQUIRE(q.at(0)->tx_deadline_usec == 1'000'000'000'000ULL);
        REQUIRE(q.at(0)->frame.payload_size == 32);
        REQUIRE(q.at(0)->isStartOfTransfer());
        REQUIRE(q.at(0)->isEndOfTransfer());
        //
        REQUIRE(q.at(1)->tx_deadline_usec == 1'000'000'000'100ULL);
        REQUIRE(q.at(1)->frame.payload_size == 32);
        REQUIRE(q.at(1)->isStartOfTransfer());
        REQUIRE(q.at(1)->isEndOfTransfer());
    }

    // Single-frame, OOM.
    alloc.setAllocationCeiling(alloc.getTotalAllocatedAmount());  // Seal up the heap at this level.
    meta.priority    = UdpardPriorityLow;
    meta.transfer_id = 23;
    REQUIRE(-UDPARD_ERROR_OUT_OF_MEMORY == que.push(&ins.getInstance(), 1'000'000'000'200ULL, meta, 1, payload.data()));
    REQUIRE(2 == que.getSize());
    REQUIRE(2 == alloc.getNumAllocatedFragments());

    alloc.setAllocationCeiling(alloc.getTotalAllocatedAmount() + sizeof(TxItem) + 10U);
    meta.priority    = UdpardPriorityHigh;
    meta.transfer_id = 24;
    REQUIRE(-UDPARD_ERROR_OUT_OF_MEMORY ==
            que.push(&ins.getInstance(), 1'000'000'000'300ULL, meta, 100, payload.data()));
    REQUIRE(2 == que.getSize());
    REQUIRE(2 == alloc.getNumAllocatedFragments());
    REQUIRE(20 < alloc.getTotalAllocatedAmount());
    REQUIRE(400 > alloc.getTotalAllocatedAmount());

    // Pop the queue.
    const UdpardTxQueueItem* ti = que.peek();
    REQUIRE(nullptr != ti);
    REQUIRE(ti->frame.payload_size == 32);
    REQUIRE(0 == std::memcmp(reinterpret_cast<const std::uint8_t*>(ti->frame.payload) + 24, payload.data(), 8));
    REQUIRE(ti->tx_deadline_usec == 1'000'000'000'000ULL);
    ti = que.peek();
    REQUIRE(nullptr != ti);  // Make sure we get the same frame again.
    REQUIRE(ti->frame.payload_size == 32);
    REQUIRE(0 == std::memcmp(reinterpret_cast<const std::uint8_t*>(ti->frame.payload) + 24, payload.data(), 8));
    REQUIRE(ti->tx_deadline_usec == 1'000'000'000'000ULL);
    ins.getAllocator().deallocate(que.pop(ti));
    REQUIRE(1 == que.getSize());
    REQUIRE(1 == alloc.getNumAllocatedFragments());
    ti = que.peek();
    REQUIRE(nullptr != ti);
    REQUIRE(ti->frame.payload_size == 32);
    REQUIRE(ti->tx_deadline_usec == 1'000'000'000'100ULL);
    ins.getAllocator().deallocate(que.pop(ti));
    REQUIRE(0 == que.getSize());
    REQUIRE(0 == alloc.getNumAllocatedFragments());
    ti = que.peek();
    REQUIRE(nullptr == ti);
    REQUIRE(nullptr == que.pop(nullptr));
    REQUIRE(0 == que.getSize());
    REQUIRE(0 == alloc.getNumAllocatedFragments());
    ti = que.peek();
    REQUIRE(nullptr == ti);

    alloc.setAllocationCeiling(1000);
    // Single-frame empty.
    meta.transfer_id = 28;
    REQUIRE(1 == que.push(&ins.getInstance(), 1'000'000'004'000ULL, meta, 0, nullptr));
    REQUIRE(1 == que.getSize());
    REQUIRE(1 == alloc.getNumAllocatedFragments());
    REQUIRE(130 > alloc.getTotalAllocatedAmount());
    REQUIRE(que.peek()->tx_deadline_usec == 1'000'000'004'000ULL);
    REQUIRE(que.peek()->frame.payload_size == 24);
    REQUIRE(que.peek()->isStartOfTransfer());
    REQUIRE(que.peek()->isEndOfTransfer());
    ti = que.peek();
    REQUIRE(nullptr != ti);
    REQUIRE(ti->frame.payload_size == 24);
    REQUIRE(ti->tx_deadline_usec == 1'000'000'004'000ULL);
    ins.getAllocator().deallocate(que.pop(ti));
    REQUIRE(0 == que.getSize());
    REQUIRE(0 == alloc.getNumAllocatedFragments());

    // Nothing left to peek at.
    ti = que.peek();
    REQUIRE(nullptr == ti);

    // Invalid transfer.
    meta.transfer_kind  = UdpardTransferKindMessage;
    meta.remote_node_id = 42;
    meta.transfer_id    = 123;
    REQUIRE(-UDPARD_ERROR_INVALID_ARGUMENT ==
            que.push(&ins.getInstance(), 1'000'000'005'000ULL, meta, 8, payload.data()));
    ti = que.peek();
    REQUIRE(nullptr == ti);
    // Error handling.
    REQUIRE(-UDPARD_ERROR_INVALID_ARGUMENT == udpardTxPush(nullptr, nullptr, 0, nullptr, 0, nullptr));
    REQUIRE(-UDPARD_ERROR_INVALID_ARGUMENT == udpardTxPush(nullptr, nullptr, 0, &meta, 0, nullptr));
    REQUIRE(-UDPARD_ERROR_INVALID_ARGUMENT == udpardTxPush(nullptr, &ins.getInstance(), 0, &meta, 0, nullptr));
    REQUIRE(-UDPARD_ERROR_INVALID_ARGUMENT ==
            udpardTxPush(&que.getInstance(), &ins.getInstance(), 0, nullptr, 0, nullptr));
    REQUIRE(-UDPARD_ERROR_INVALID_ARGUMENT == que.push(&ins.getInstance(), 1'000'000'006'000ULL, meta, 1, nullptr));

    REQUIRE(nullptr == udpardTxPeek(nullptr));
    REQUIRE(nullptr == udpardTxPop(nullptr, nullptr));             // No effect.
    REQUIRE(nullptr == udpardTxPop(&que.getInstance(), nullptr));  // No effect.
}

TEST_CASE("TxBasic1")
{
    // Multiframe testing here
    // Multiframe transfers currently not implemented
}
