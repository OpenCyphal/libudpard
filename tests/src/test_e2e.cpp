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

/// A wrapper over udpardRxRPCDispatcherReceive() that copies the datagram payload into a newly allocated buffer.
[[nodiscard]] int_fast8_t rxRPCDispatcherReceive(UdpardRxRPCDispatcher* const self,
                                                 InstrumentedAllocator&       payload_memory,
                                                 const UdpardMicrosecond      timestamp_usec,
                                                 const UdpardMutablePayload   datagram_payload,
                                                 const uint_fast8_t           redundant_iface_index,
                                                 UdpardRxRPCPort** const      out_port,
                                                 UdpardRxRPCTransfer* const   out_transfer)
{
    return udpardRxRPCDispatcherReceive(self,
                                        timestamp_usec,
                                        {
                                            .size = datagram_payload.size,
                                            .data = std::memmove(instrumentedAllocatorAllocate(&payload_memory,
                                                                                               datagram_payload.size),
                                                                 datagram_payload.data,
                                                                 datagram_payload.size),
                                        },
                                        redundant_iface_index,
                                        out_port,
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
        .payload = instrumentedAllocatorMakeMemoryResource(&alloc_tx),
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
    const UdpardTxItem* tx_item = udpardTxPeek(&tx);
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

void testRPC()
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
        .payload = instrumentedAllocatorMakeMemoryResource(&alloc_tx),
    };
    const UdpardRxMemoryResources mem_rx{
        .session  = instrumentedAllocatorMakeMemoryResource(&alloc_rx_session),
        .fragment = instrumentedAllocatorMakeMemoryResource(&alloc_rx_fragment),
        .payload  = instrumentedAllocatorMakeMemoryDeleter(&alloc_rx_payload),
    };
    // Initialize the TX pipeline.
    UdpardTx           tx{};
    const UdpardNodeID tx_node_id = 1234;
    TEST_ASSERT_EQUAL(0, udpardTxInit(&tx, &tx_node_id, 2, mem_tx));
    tx.mtu = 500;
    for (auto i = 0U; i <= UDPARD_PRIORITY_MAX; i++)
    {
        tx.dscp_value_per_priority[i] = static_cast<std::uint_least8_t>(0xA0U + i);
    }
    // Initialize the RPC dispatcher and the RPC services.
    UdpardRxRPCDispatcher dispatcher{};
    TEST_ASSERT_EQUAL(0, udpardRxRPCDispatcherInit(&dispatcher, mem_rx));
    UdpardUDPIPEndpoint udp_ip_endpoint{};
    TEST_ASSERT_EQUAL(0, udpardRxRPCDispatcherStart(&dispatcher, 4321, &udp_ip_endpoint));
    UdpardRxRPCPort port_foo_a{};
    UdpardRxRPCPort port_foo_q{};
    TEST_ASSERT_EQUAL(1, udpardRxRPCDispatcherListen(&dispatcher, &port_foo_a, 200, false, 500));
    TEST_ASSERT_EQUAL(1, udpardRxRPCDispatcherListen(&dispatcher, &port_foo_q, 200, true, 500));

    // Send a request.
    UdpardTransferID       transfer_id_shared = 0;
    const std::string_view Entry = "But this simple world held a perplexing riddle: The entire galaxy was a vast "
                                   "empty desert, but a highly intelligent civilization had appeared on the star "
                                   "nearest to us. In this mystery, his thoughts found an entry point.";
    TEST_ASSERT_EQUAL_INT32(1,
                            udpardTxRequest(&tx,
                                            10'000'000,
                                            UdpardPriorityFast,
                                            200,
                                            4321,
                                            transfer_id_shared++,
                                            makePayload(Entry),
                                            nullptr));
    TEST_ASSERT_EQUAL(1, tx.queue_size);
    TEST_ASSERT_EQUAL(1, transfer_id_shared);

    // Send a response.
    const std::string_view Forest = "In the dead, lonely, cold blackness, he saw the truth of the universe.";
    TEST_ASSERT_EQUAL_INT32(1,
                            udpardTxRespond(&tx,
                                            10'001'000,
                                            UdpardPriorityImmediate,
                                            200,
                                            4321,
                                            transfer_id_shared,
                                            makePayload(Forest),
                                            nullptr));
    TEST_ASSERT_EQUAL(2, tx.queue_size);

    // Transmit the enqueued frames by pushing them into the RPC dispatcher.
    UdpardRxRPCTransfer transfer{};
    UdpardRxRPCPort*    active_port = nullptr;
    // First transfer.
    TEST_ASSERT_EQUAL(0, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_payload.allocated_fragments);
    const UdpardTxItem* tx_item = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_NULL(tx_item);
    TEST_ASSERT_EQUAL(udp_ip_endpoint.ip_address, tx_item->destination.ip_address);
    TEST_ASSERT_NULL(tx_item->next_in_transfer);
    TEST_ASSERT_EQUAL(10'001'000, tx_item->deadline_usec);
    TEST_ASSERT_EQUAL(0xA1, tx_item->dscp);
    TEST_ASSERT_EQUAL(1,
                      rxRPCDispatcherReceive(&dispatcher,
                                             alloc_rx_payload,
                                             10'000'000,
                                             tx_item->datagram_payload,
                                             0,
                                             &active_port,
                                             &transfer));
    TEST_ASSERT_EQUAL(1, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_rx_payload.allocated_fragments);
    // Check the received transfer.
    TEST_ASSERT_EQUAL(&port_foo_a, active_port);
    TEST_ASSERT_EQUAL(200, transfer.service_id);
    TEST_ASSERT_EQUAL(false, transfer.is_request);
    TEST_ASSERT_EQUAL(10'000'000, transfer.base.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPriorityImmediate, transfer.base.priority);
    TEST_ASSERT_EQUAL(1234, transfer.base.source_node_id);
    TEST_ASSERT_EQUAL(1, transfer.base.transfer_id);
    TEST_ASSERT_EQUAL(Forest.size(), transfer.base.payload_size);
    TEST_ASSERT_EQUAL(Forest.size(), transfer.base.payload.view.size);
    TEST_ASSERT_EQUAL_MEMORY(Forest.data(), transfer.base.payload.view.data, transfer.base.payload.view.size);
    TEST_ASSERT_NULL(transfer.base.payload.next);
    // Free the transfer payload.
    udpardRxFragmentFree(transfer.base.payload, mem_rx.fragment, mem_rx.payload);
    TEST_ASSERT_EQUAL(1, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_payload.allocated_fragments);
    // Send duplicates.
    TEST_ASSERT_EQUAL(0,  // Duplicate on the same iface.
                      rxRPCDispatcherReceive(&dispatcher,
                                             alloc_rx_payload,
                                             10'000'100,
                                             tx_item->datagram_payload,
                                             0,
                                             &active_port,
                                             &transfer));
    TEST_ASSERT_EQUAL(0,  // Duplicate on another iface.
                      rxRPCDispatcherReceive(&dispatcher,
                                             alloc_rx_payload,
                                             10'000'200,
                                             tx_item->datagram_payload,
                                             2,
                                             &active_port,
                                             &transfer));
    // Ensure the duplicates do no alter memory usage.
    TEST_ASSERT_EQUAL(1, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_payload.allocated_fragments);
    // Free the TX item.
    udpardTxFree(mem_tx, udpardTxPop(&tx, tx_item));
    TEST_ASSERT_EQUAL(1 * 2ULL, alloc_tx.allocated_fragments);

    // Second transfer.
    tx_item = udpardTxPeek(&tx);
    TEST_ASSERT_NOT_NULL(tx_item);
    TEST_ASSERT_EQUAL(udp_ip_endpoint.ip_address, tx_item->destination.ip_address);
    TEST_ASSERT_NULL(tx_item->next_in_transfer);
    TEST_ASSERT_EQUAL(10'000'000, tx_item->deadline_usec);
    TEST_ASSERT_EQUAL(0xA2, tx_item->dscp);
    TEST_ASSERT_EQUAL(1,
                      rxRPCDispatcherReceive(&dispatcher,
                                             alloc_rx_payload,
                                             10'001'000,
                                             tx_item->datagram_payload,
                                             1,
                                             &active_port,
                                             &transfer));
    TEST_ASSERT_EQUAL(2, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_rx_payload.allocated_fragments);
    // Check the received transfer.
    TEST_ASSERT_EQUAL(&port_foo_q, active_port);
    TEST_ASSERT_EQUAL(200, transfer.service_id);
    TEST_ASSERT_EQUAL(true, transfer.is_request);
    TEST_ASSERT_EQUAL(10'001'000, transfer.base.timestamp_usec);
    TEST_ASSERT_EQUAL(UdpardPriorityFast, transfer.base.priority);
    TEST_ASSERT_EQUAL(1234, transfer.base.source_node_id);
    TEST_ASSERT_EQUAL(0, transfer.base.transfer_id);
    TEST_ASSERT_EQUAL(Entry.size(), transfer.base.payload_size);
    TEST_ASSERT_EQUAL(Entry.size(), transfer.base.payload.view.size);
    TEST_ASSERT_EQUAL_MEMORY(Entry.data(), transfer.base.payload.view.data, transfer.base.payload.view.size);
    TEST_ASSERT_NULL(transfer.base.payload.next);
    // Free the transfer payload.
    udpardRxFragmentFree(transfer.base.payload, mem_rx.fragment, mem_rx.payload);
    TEST_ASSERT_EQUAL(2, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_payload.allocated_fragments);
    // Send duplicates.
    TEST_ASSERT_EQUAL(0,  // Duplicate on the same iface.
                      rxRPCDispatcherReceive(&dispatcher,
                                             alloc_rx_payload,
                                             10'001'100,
                                             tx_item->datagram_payload,
                                             0,
                                             &active_port,
                                             &transfer));
    TEST_ASSERT_EQUAL(0,  // Duplicate on another iface.
                      rxRPCDispatcherReceive(&dispatcher,
                                             alloc_rx_payload,
                                             10'001'200,
                                             tx_item->datagram_payload,
                                             2,
                                             &active_port,
                                             &transfer));
    // Ensure the duplicates do no alter memory usage.
    TEST_ASSERT_EQUAL(2, alloc_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_fragment.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_rx_payload.allocated_fragments);
    // Free the TX item.
    udpardTxFree(mem_tx, udpardTxPop(&tx, tx_item));
    TEST_ASSERT_EQUAL(0, alloc_tx.allocated_fragments);

    // Destroy the ports.
    udpardRxRPCDispatcherCancel(&dispatcher, 200, false);
    udpardRxRPCDispatcherCancel(&dispatcher, 200, true);

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
    RUN_TEST(testRPC);
    return UNITY_END();
}
