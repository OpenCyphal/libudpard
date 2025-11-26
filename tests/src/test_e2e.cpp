/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.h>
#include "helpers.h"
#include <unity.h>
#include <array>
#include <string_view>
#include <cstring>
#include <cstdint>

namespace
{

UdpardPayload makePayload(const std::string_view& payload)
{
    return {.size = payload.size(), .data = payload.data()};
}

/// A wrapper over udpardRxSubscriptionReceive() that copies the datagram payload into a newly allocated buffer.
[[nodiscard]] int_fast8_t rxSubscriptionReceive(UdpardRxSubscription* const self,
                                                InstrumentedAllocator&      payload_memory,
                                                const UdpardMicrosecond     timestamp_usec,
                                                const UdpardMutablePayload  datagram_payload,
                                                const uint_fast8_t          redundant_iface_index,
                                                UdpardRxTransfer* const     out_transfer)
{
    return udpardRxSubscriptionReceive(self,
                                       timestamp_usec,
                                       {
                                           .size = datagram_payload.size,
                                           .data = std::memmove(instrumentedAllocatorAllocate(&payload_memory,
                                                                                              datagram_payload.size),
                                                                datagram_payload.data,
                                                                datagram_payload.size),
                                       },
                                       redundant_iface_index,
                                       out_transfer);
}

void testPubSub()
{
    InstrumentedAllocator alloc_tx;
    InstrumentedAllocator alloc_rx_session;
    InstrumentedAllocator alloc_rx_fragment;
    InstrumentedAllocator alloc_rx_payload;
    instrumentedAllocatorNew(&alloc_tx);
    instrumentedAllocatorNew(&alloc_rx_session);
    instrumentedAllocatorNew(&alloc_rx_fragment);
    instrumentedAllocatorNew(&alloc_rx_payload);
    const UdpardTxMemoryResources mem_tx{
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc_tx),
        .payload  = instrumentedAllocatorMakeMemoryResource(&alloc_tx),
    };
    const UdpardRxMemoryResources mem_rx{
        .session  = instrumentedAllocatorMakeMemoryResource(&alloc_rx_session),
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc_rx_fragment),
        .payload  = instrumentedAllocatorMakeMemoryDeleter(&alloc_rx_payload),
    };
    // Initialize the TX pipeline. Set the MTU to a low value to ensure that we test multi-frame transfers.
    UdpardTx     tx{};
    UdpardNodeID node_id = UDPARD_NODE_ID_UNSET;
    TEST_ASSERT_EQUAL(0, udpardTxInit(&tx, &node_id, 7, mem_tx));
    tx.mtu = 100;
    for (auto i = 0U; i <= UDPARD_PRIORITY_MAX; i++)
    {
        tx.dscp_value_per_priority[i] = static_cast<std::uint_least8_t>(0xA0U + i);
    }
    // Initialize the subscriptions.
    std::array<UdpardRxSubscription, 3> sub{};
    TEST_ASSERT_EQUAL(0, udpardRxSubscriptionInit(&sub.at(0), 5000, 300, mem_rx));
    TEST_ASSERT_EQUAL(0, udpardRxSubscriptionInit(&sub.at(1), 5001, 200, mem_rx));
    TEST_ASSERT_EQUAL(0, udpardRxSubscriptionInit(&sub.at(2), 5002, 100, mem_rx));

    // Publish something on subject 5000.
    std::array<UdpardTransferID, 3> transfer_id{};
    TEST_ASSERT_EQUAL(1,  // Single-frame anonymous = success.
                      udpardTxPublish(&tx,
                                      10'000'000,
                                      UdpardPrioritySlow,
                                      5000,
                                      transfer_id.at(0)++,
                                      makePayload("Last night, I had a dream."),
                                      nullptr));
    const std::string_view Eden =
        "After speaking with Scott, Lan Xi halted his busy work amid chaotic feelings, and stopped to think, as the "
        "colonel had advised. Faster than he had imagined, Eden's cold, slippery vipers crawled into his "
        "consciousness. He found the fruit of knowledge and ate it, and the last rays of sunshine in his soul "
        "disappeared forever as everything plunged into darkness.";
    TEST_ASSERT_EQUAL(-UDPARD_ERROR_ANONYMOUS,
                      udpardTxPublish(&tx,
                                      10'001'000,
                                      UdpardPriorityNominal,
                                      5000,
                                      transfer_id.at(0),
                                      makePayload(Eden),
                                      nullptr));
    node_id = 42;  // Change the node-ID to allow multi-frame transfers, then try again.
    TEST_ASSERT_EQUAL(4,
                      udpardTxPublish(&tx,
                                      10'002'000,
                                      UdpardPriorityOptional,
                                      5000,
                                      transfer_id.at(0)++,
                                      makePayload(Eden),
                                      nullptr));
    TEST_ASSERT_EQUAL(5, tx.queue_size);

    // Publish something on subject 5001. The priority here is higher so it should be delivered earlier.
    node_id                      = 43;  // Change the node-ID.
    const std::string_view Later = "Two days later, the captain of Ultimate Law committed suicide.";
    TEST_ASSERT_EQUAL(1,
                      udpardTxPublish(&tx,
                                      10'003'000,
                                      UdpardPriorityNominal,
                                      5001,
                                      transfer_id.at(1)++,
                                      makePayload(Later),
                                      nullptr));
    TEST_ASSERT_EQUAL(6, tx.queue_size);

    // Publish something on subject 5002. The priority here is the same.
    const std::string_view Dark = "'Dark. It's so fucking dark,' the captain murmured, and then shot himself.";
    TEST_ASSERT_EQUAL(1,
                      udpardTxPublish(&tx,
                                      10'004'000,
                                      UdpardPriorityNominal,
                                      5002,
                                      transfer_id.at(2)++,
                                      makePayload(Dark),
                                      nullptr));
    TEST_ASSERT_EQUAL(7, tx.queue_size);
    TEST_ASSERT_EQUAL(7 * 2ULL, alloc_tx.allocated_fragments);

    // Transmit the enqueued frames by pushing them into the subscribers.
    // Here we pop the frames one by one ensuring that they come out in the correct order.
    UdpardRxTransfer transfer{};
    // First transfer.
    TEST_ASSERT_EQUAL(0, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_payload.allocated_fragments);
    UdpardTxItem* tx_item = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_NULL(tx_item);
    TEST_ASSERT_EQUAL(sub.at(1).udp_ip_endpoint.ip_address, tx_item->destination.ip_address);
    TEST_ASSERT_NULL(tx_item->next_in_transfer);
    TEST_ASSERT_EQUAL(10'003'000, tx_item->deadline_usec);
    TEST_ASSERT_EQUAL(0xA4, tx_item->dscp);
    TEST_ASSERT_EQUAL(1,
                      rxSubscriptionReceive(&sub.at(1),
                                            alloc_rx_payload,
                                            10'005'000,
                                            tx_item->datagram_payload,
                                            0,
                                            &transfer));
    TEST_ASSERT_EQUAL(1, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_rx_payload.allocated_fragments);
    // Check the received transfer.
    TEST_ASSERT_EQUAL(10'005'000, transfer.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPriorityNominal, transfer.priority);
    TEST_ASSERT_EQUAL(43, transfer.source_node_id);
    TEST_ASSERT_EQUAL(0, transfer.transfer_id);
    TEST_ASSERT_EQUAL(Later.size(), transfer.payload_size);
    TEST_ASSERT_EQUAL(Later.size(), transfer.payload.view.size);
    TEST_ASSERT_EQUAL_MEMORY(Later.data(), transfer.payload.view.data, transfer.payload.view.size);
    TEST_ASSERT_NULL(transfer.payload.next);
    // Free the transfer payload.
    udpardRxFragmentFree(transfer.payload, mem_rx.fragment, mem_rx.payload);
    TEST_ASSERT_EQUAL(1, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_payload.allocated_fragments);
    // Send duplicates.
    TEST_ASSERT_EQUAL(0,  // Duplicate on same iface.
                      rxSubscriptionReceive(&sub.at(1),
                                            alloc_rx_payload,
                                            10'005'100,
                                            tx_item->datagram_payload,
                                            0,
                                            &transfer));
    TEST_ASSERT_EQUAL(0,  // Duplicate on another iface.
                      rxSubscriptionReceive(&sub.at(1),
                                            alloc_rx_payload,
                                            10'005'200,
                                            tx_item->datagram_payload,
                                            1,
                                            &transfer));
    // Ensure the duplicates do no alter memory usage.
    TEST_ASSERT_EQUAL(1, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_payload.allocated_fragments);
    // Free the TX item.
    udpardTxFree(mem_tx, udpardTxPop(&tx, tx_item));
    TEST_ASSERT_EQUAL(6 * 2ULL, alloc_tx.allocated_fragments);

    // Second transfer.
    tx_item = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_NULL(tx_item);
    TEST_ASSERT_EQUAL(sub.at(2).udp_ip_endpoint.ip_address, tx_item->destination.ip_address);
    TEST_ASSERT_NULL(tx_item->next_in_transfer);
    TEST_ASSERT_EQUAL(10'004'000, tx_item->deadline_usec);
    TEST_ASSERT_EQUAL(0xA4, tx_item->dscp);
    TEST_ASSERT_EQUAL(1,
                      rxSubscriptionReceive(&sub.at(2),
                                            alloc_rx_payload,
                                            10'006'000,
                                            tx_item->datagram_payload,
                                            1,
                                            &transfer));
    TEST_ASSERT_EQUAL(2, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_rx_payload.allocated_fragments);
    // Check the received transfer.
    TEST_ASSERT_EQUAL(10'006'000, transfer.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPriorityNominal, transfer.priority);
    TEST_ASSERT_EQUAL(43, transfer.source_node_id);
    TEST_ASSERT_EQUAL(0, transfer.transfer_id);
    TEST_ASSERT_EQUAL(Dark.size(), transfer.payload_size);
    TEST_ASSERT_EQUAL(Dark.size(), transfer.payload.view.size);
    TEST_ASSERT_EQUAL_MEMORY(Dark.data(), transfer.payload.view.data, transfer.payload.view.size);
    TEST_ASSERT_NULL(transfer.payload.next);
    // Free the transfer payload.
    udpardRxFragmentFree(transfer.payload, mem_rx.fragment, mem_rx.payload);
    TEST_ASSERT_EQUAL(2, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_payload.allocated_fragments);
    // Free the TX item.
    udpardTxFree(mem_tx, udpardTxPop(&tx, tx_item));
    TEST_ASSERT_EQUAL(5 * 2ULL, alloc_tx.allocated_fragments);

    // Third transfer. This one is anonymous.
    tx_item = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_NULL(tx_item);
    TEST_ASSERT_EQUAL(sub.at(0).udp_ip_endpoint.ip_address, tx_item->destination.ip_address);
    TEST_ASSERT_NULL(tx_item->next_in_transfer);
    TEST_ASSERT_EQUAL(10'000'000, tx_item->deadline_usec);
    TEST_ASSERT_EQUAL(0xA6, tx_item->dscp);
    TEST_ASSERT_EQUAL(1,
                      rxSubscriptionReceive(&sub.at(0),
                                            alloc_rx_payload,
                                            10'007'000,
                                            tx_item->datagram_payload,
                                            2,
                                            &transfer));
    TEST_ASSERT_EQUAL(2, alloc_rx_session.allocated_fragments);  // No increment, anonymous transfers are stateless.
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_rx_payload.allocated_fragments);
    // Check the received transfer.
    TEST_ASSERT_EQUAL(10'007'000, transfer.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPrioritySlow, transfer.priority);
    TEST_ASSERT_EQUAL(UDPARD_NODE_ID_UNSET, transfer.source_node_id);
    TEST_ASSERT_EQUAL(0, transfer.transfer_id);
    TEST_ASSERT_EQUAL(26, transfer.payload_size);
    TEST_ASSERT_EQUAL(26, transfer.payload.view.size);
    TEST_ASSERT_EQUAL_MEMORY("Last night, I had a dream.", transfer.payload.view.data, transfer.payload.view.size);
    TEST_ASSERT_NULL(transfer.payload.next);
    // Free the transfer payload.
    udpardRxFragmentFree(transfer.payload, mem_rx.fragment, mem_rx.payload);
    TEST_ASSERT_EQUAL(2, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_payload.allocated_fragments);
    // Free the TX item.
    udpardTxFree(mem_tx, udpardTxPop(&tx, tx_item));
    TEST_ASSERT_EQUAL(4 * 2ULL, alloc_tx.allocated_fragments);

    // Fourth transfer. This one contains multiple frames. We process them one-by-one.
    // Frame #0.
    tx_item = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_NULL(tx_item);
    const UdpardTxItem* prev_next = tx_item->next_in_transfer;
    TEST_ASSERT_NOT_NULL(prev_next);
    TEST_ASSERT_EQUAL(sub.at(0).udp_ip_endpoint.ip_address, tx_item->destination.ip_address);
    TEST_ASSERT_EQUAL(10'002'000, tx_item->deadline_usec);
    TEST_ASSERT_EQUAL(0xA7, tx_item->dscp);
    TEST_ASSERT_EQUAL(0,
                      rxSubscriptionReceive(&sub.at(0),
                                            alloc_rx_payload,
                                            10'008'000,
                                            tx_item->datagram_payload,
                                            0,
                                            &transfer));
    TEST_ASSERT_EQUAL(3, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_rx_payload.allocated_fragments);
    // Free the TX item.
    udpardTxFree(mem_tx, udpardTxPop(&tx, tx_item));
    TEST_ASSERT_EQUAL(3 * 2ULL, alloc_tx.allocated_fragments);
    // Frame #1.
    tx_item = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_NULL(tx_item);
    TEST_ASSERT_EQUAL_PTR(prev_next, tx_item);
    prev_next = tx_item->next_in_transfer;
    TEST_ASSERT_NOT_NULL(prev_next);
    TEST_ASSERT_EQUAL(sub.at(0).udp_ip_endpoint.ip_address, tx_item->destination.ip_address);
    TEST_ASSERT_EQUAL(10'002'000, tx_item->deadline_usec);
    TEST_ASSERT_EQUAL(0xA7, tx_item->dscp);
    TEST_ASSERT_EQUAL(0,
                      rxSubscriptionReceive(&sub.at(0),
                                            alloc_rx_payload,
                                            10'008'001,
                                            tx_item->datagram_payload,
                                            0,
                                            &transfer));
    TEST_ASSERT_EQUAL(3, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(2, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(2, alloc_rx_payload.allocated_fragments);
    // Free the TX item.
    udpardTxFree(mem_tx, udpardTxPop(&tx, tx_item));
    TEST_ASSERT_EQUAL(2 * 2ULL, alloc_tx.allocated_fragments);
    // Frame #2.
    tx_item = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_NULL(tx_item);
    TEST_ASSERT_EQUAL_PTR(prev_next, tx_item);
    prev_next = tx_item->next_in_transfer;
    TEST_ASSERT_NOT_NULL(prev_next);
    TEST_ASSERT_EQUAL(sub.at(0).udp_ip_endpoint.ip_address, tx_item->destination.ip_address);
    TEST_ASSERT_EQUAL(10'002'000, tx_item->deadline_usec);
    TEST_ASSERT_EQUAL(0xA7, tx_item->dscp);
    TEST_ASSERT_EQUAL(0,
                      rxSubscriptionReceive(&sub.at(0),
                                            alloc_rx_payload,
                                            10'008'002,
                                            tx_item->datagram_payload,
                                            0,
                                            &transfer));
    TEST_ASSERT_EQUAL(3, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(3, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(3, alloc_rx_payload.allocated_fragments);
    // Free the TX item.
    udpardTxFree(mem_tx, udpardTxPop(&tx, tx_item));
    TEST_ASSERT_EQUAL(1 * 2ULL, alloc_tx.allocated_fragments);
    // Frame #3. This is the last frame of the transfer. The payload is truncated, see the extent.
    tx_item = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_NULL(tx_item);
    TEST_ASSERT_EQUAL_PTR(prev_next, tx_item);
    prev_next = tx_item->next_in_transfer;
    TEST_ASSERT_NULL(prev_next);
    TEST_ASSERT_EQUAL(sub.at(0).udp_ip_endpoint.ip_address, tx_item->destination.ip_address);
    TEST_ASSERT_EQUAL(10'002'000, tx_item->deadline_usec);
    TEST_ASSERT_EQUAL(0xA7, tx_item->dscp);
    TEST_ASSERT_EQUAL(1,
                      rxSubscriptionReceive(&sub.at(0),
                                            alloc_rx_payload,
                                            10'008'003,
                                            tx_item->datagram_payload,
                                            0,
                                            &transfer));
    TEST_ASSERT_EQUAL(3, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(2, alloc_rx_fragment.allocated_fragments);  // Extent truncation + head optimization.
    TEST_ASSERT_EQUAL(3, alloc_rx_payload.allocated_fragments);   // Extent truncation.
    // Check the received transfer.
    TEST_ASSERT_EQUAL(10'008'000, transfer.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPriorityOptional, transfer.priority);
    TEST_ASSERT_EQUAL(42, transfer.source_node_id);
    TEST_ASSERT_EQUAL(1, transfer.transfer_id);
    TEST_ASSERT_EQUAL(300, transfer.payload_size);       // Defined by the configured extent setting for this sub.
    TEST_ASSERT_EQUAL(100, transfer.payload.view.size);  // Defined by the MTU setting.
    std::array<std::uint_fast8_t, 500> rx_eden{};
    TEST_ASSERT_EQUAL(300, udpardGather(transfer.payload, rx_eden.size(), rx_eden.data()));
    TEST_ASSERT_EQUAL_MEMORY(Eden.data(), rx_eden.data(), 300);
    // Free the transfer payload.
    udpardRxFragmentFree(transfer.payload, mem_rx.fragment, mem_rx.payload);
    TEST_ASSERT_EQUAL(3, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_payload.allocated_fragments);
    // Free the TX item.
    udpardTxFree(mem_tx, udpardTxPop(&tx, tx_item));
    TEST_ASSERT_EQUAL(0, alloc_tx.allocated_fragments);

    // Close the subscriptions and ensure the memory is freed.
    udpardRxSubscriptionFree(&sub.at(0));
    udpardRxSubscriptionFree(&sub.at(1));
    udpardRxSubscriptionFree(&sub.at(2));

    // Final memory check.
    TEST_ASSERT_EQUAL(0, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_tx.allocated_fragments);
}

}  // namespace

void setUp() {}

void tearDown() {}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(testPubSub);
    return UNITY_END();
}
