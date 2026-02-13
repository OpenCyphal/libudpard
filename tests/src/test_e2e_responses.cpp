/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.h>
#include "helpers.h"
#include <unity.h>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

struct CapturedFrame
{
    std::vector<uint8_t> bytes;
    uint_fast8_t         iface_index = 0;
    udpard_udpip_ep_t    destination{};
};

struct RxState
{
    std::size_t          count;
    uint64_t             transfer_id;
    std::vector<uint8_t> payload;
    udpard_remote_t      remote;
};

// Captures TX ejections for manual RX delivery.
bool capture_tx(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection)
{
    auto* out = static_cast<std::vector<CapturedFrame>*>(tx->user);
    if (out == nullptr) {
        return false;
    }
    CapturedFrame frame{};
    frame.bytes.assign(static_cast<const uint8_t*>(ejection->datagram.data),
                       static_cast<const uint8_t*>(ejection->datagram.data) + ejection->datagram.size);
    frame.iface_index = ejection->iface_index;
    frame.destination = ejection->destination;
    out->push_back(frame);
    return true;
}

constexpr udpard_tx_vtable_t tx_vtable{ .eject = &capture_tx };

// Receives one transfer and frees its fragment tree.
void on_message(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    auto* st = static_cast<RxState*>(rx->user);
    TEST_ASSERT_NOT_NULL(st);
    st->count++;
    st->transfer_id = transfer.transfer_id;
    st->remote      = transfer.remote;
    st->payload.resize(transfer.payload_size_stored);
    const udpard_fragment_t* cursor = transfer.payload;
    (void)udpard_fragment_gather(&cursor, 0, transfer.payload_size_stored, st->payload.data());
    udpard_fragment_free_all(transfer.payload, udpard_make_deleter(port->memory.fragment));
}

constexpr udpard_rx_port_vtable_t rx_vtable{ .on_message = &on_message };

// Builds TX memory resources.
udpard_tx_mem_resources_t make_tx_mem(instrumented_allocator_t& transfer, instrumented_allocator_t& payload)
{
    udpard_tx_mem_resources_t out{};
    out.transfer = instrumented_allocator_make_resource(&transfer);
    for (auto& res : out.payload) {
        res = instrumented_allocator_make_resource(&payload);
    }
    return out;
}

// Builds RX memory resources.
udpard_rx_mem_resources_t make_rx_mem(instrumented_allocator_t& session, instrumented_allocator_t& fragment)
{
    return udpard_rx_mem_resources_t{
        .session  = instrumented_allocator_make_resource(&session),
        .slot     = instrumented_allocator_make_resource(&session),
        .fragment = instrumented_allocator_make_resource(&fragment),
    };
}

// Delivers a captured frame into RX.
void deliver(const CapturedFrame&    frame,
             const udpard_mem_t      mem,
             const udpard_deleter_t  del,
             udpard_rx_t* const      rx,
             udpard_rx_port_t* const port,
             const udpard_udpip_ep_t src)
{
    void* const dgram = mem_res_alloc(mem, frame.bytes.size());
    TEST_ASSERT_NOT_NULL(dgram);
    (void)std::memcpy(dgram, frame.bytes.data(), frame.bytes.size());
    TEST_ASSERT_TRUE(udpard_rx_port_push(
      rx, port, 5000, src, udpard_bytes_mut_t{ .size = frame.bytes.size(), .data = dgram }, del, frame.iface_index));
}

void test_p2p_response_roundtrip()
{
    seed_prng();

    // Configure B (sender) TX.
    instrumented_allocator_t b_tx_transfer{};
    instrumented_allocator_t b_tx_payload{};
    instrumented_allocator_new(&b_tx_transfer);
    instrumented_allocator_new(&b_tx_payload);
    udpard_tx_t                b_tx{};
    std::vector<CapturedFrame> b_frames;
    TEST_ASSERT_TRUE(
      udpard_tx_new(&b_tx, 0xBBBBBBBBBBBBBBBBULL, 10U, 16U, make_tx_mem(b_tx_transfer, b_tx_payload), &tx_vtable));
    b_tx.mtu[0] = 256U;
    b_tx.mtu[1] = 256U;
    b_tx.mtu[2] = 256U;
    b_tx.user   = &b_frames;

    // Configure A (receiver) RX P2P port.
    instrumented_allocator_t a_rx_session{};
    instrumented_allocator_t a_rx_fragment{};
    instrumented_allocator_new(&a_rx_session);
    instrumented_allocator_new(&a_rx_fragment);
    const auto             rx_mem = make_rx_mem(a_rx_session, a_rx_fragment);
    const udpard_deleter_t del    = instrumented_allocator_make_deleter(&a_rx_fragment);
    udpard_rx_t            a_rx{};
    udpard_rx_port_t       a_p2p{};
    RxState                a_state{};
    udpard_rx_new(&a_rx, nullptr);
    a_rx.user = &a_state;
    TEST_ASSERT_TRUE(udpard_rx_port_new_p2p(&a_p2p, 1024U, rx_mem, &rx_vtable));

    // Emit one P2P response from B to A on iface 0.
    const udpard_udpip_ep_t a_endpoint                        = { .ip = 0x0A0000A1U, .port = 9382U };
    udpard_udpip_ep_t       endpoints[UDPARD_IFACE_COUNT_MAX] = {};
    endpoints[0]                                              = a_endpoint;
    const std::vector<uint8_t> response_payload{ 0xDE, 0xAD, 0xBE, 0xEF };
    TEST_ASSERT_TRUE(udpard_tx_push_p2p_native(&b_tx,
                                               1000,
                                               100000,
                                               udpard_prio_high,
                                               endpoints,
                                               make_scattered(response_payload.data(), response_payload.size()),
                                               nullptr));
    udpard_tx_poll(&b_tx, 1001, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_EQUAL_size_t(1, b_frames.size());
    TEST_ASSERT_EQUAL_UINT32(a_endpoint.ip, b_frames[0].destination.ip);
    TEST_ASSERT_EQUAL_UINT16(a_endpoint.port, b_frames[0].destination.port);

    // Deliver and verify A has received the response.
    deliver(b_frames[0], rx_mem.fragment, del, &a_rx, &a_p2p, udpard_udpip_ep_t{ .ip = 0x0A0000B2U, .port = 9382U });
    udpard_rx_poll(&a_rx, 6000);
    TEST_ASSERT_EQUAL_size_t(1, a_state.count);
    TEST_ASSERT_EQUAL_size_t(response_payload.size(), a_state.payload.size());
    TEST_ASSERT_EQUAL_MEMORY(response_payload.data(), a_state.payload.data(), response_payload.size());
    TEST_ASSERT_EQUAL_UINT64(0xBBBBBBBBBBBBBBBBULL, a_state.remote.uid);

    // Release all resources.
    udpard_rx_port_free(&a_rx, &a_p2p);
    udpard_tx_free(&b_tx);
    TEST_ASSERT_EQUAL_size_t(0, b_tx_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, b_tx_payload.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, a_rx_session.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, a_rx_fragment.allocated_fragments);
    instrumented_allocator_reset(&b_tx_transfer);
    instrumented_allocator_reset(&b_tx_payload);
    instrumented_allocator_reset(&a_rx_session);
    instrumented_allocator_reset(&a_rx_fragment);
}

} // namespace

void setUp() {}
void tearDown() {}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_p2p_response_roundtrip);
    return UNITY_END();
}
