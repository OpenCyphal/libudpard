/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.h>
#include "helpers.h"
#include <unity.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

struct CapturedFrame
{
    std::vector<std::uint8_t> bytes;
    std::uint_fast8_t         iface_index = 0;
};

struct RxState
{
    std::size_t               count             = 0;
    std::size_t               payload_size_wire = 0;
    std::uint64_t             transfer_id       = 0;
    std::vector<std::uint8_t> payload;
};

// Captures each TX frame into a vector.
bool capture_tx(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection)
{
    auto* out = static_cast<std::vector<CapturedFrame>*>(tx->user);
    if (out == nullptr) {
        return false;
    }
    CapturedFrame frame{};
    frame.bytes.assign(static_cast<const std::uint8_t*>(ejection->datagram.data),
                       static_cast<const std::uint8_t*>(ejection->datagram.data) + ejection->datagram.size);
    frame.iface_index = ejection->iface_index;
    out->push_back(std::move(frame));
    return true;
}

constexpr udpard_tx_vtable_t tx_vtable{ .eject = &capture_tx };

// Stores one received transfer and frees its payload.
void on_message(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    auto* st = static_cast<RxState*>(rx->user);
    TEST_ASSERT_NOT_NULL(st);
    st->count++;
    st->payload_size_wire = transfer.payload_size_wire;
    st->transfer_id       = transfer.transfer_id;
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
    for (auto& r : out.payload) {
        r = instrumented_allocator_make_resource(&payload);
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

// Delivers one captured frame into RX.
void deliver(const CapturedFrame&    frame,
             const udpard_mem_t      mem,
             const udpard_deleter_t  del,
             udpard_rx_t* const      rx,
             udpard_rx_port_t* const port,
             const udpard_us_t       ts)
{
    void* const dgram = mem_res_alloc(mem, frame.bytes.size());
    TEST_ASSERT_NOT_NULL(dgram);
    (void)std::memcpy(dgram, frame.bytes.data(), frame.bytes.size());
    TEST_ASSERT_TRUE(udpard_rx_port_push(rx,
                                         port,
                                         ts,
                                         udpard_udpip_ep_t{ .ip = 0x0A000001U, .port = 9382U },
                                         udpard_bytes_mut_t{ .size = frame.bytes.size(), .data = dgram },
                                         del,
                                         frame.iface_index));
}

void test_zero_payload_transfer()
{
    seed_prng();

    // Configure TX and RX.
    instrumented_allocator_t tx_alloc_transfer{};
    instrumented_allocator_t tx_alloc_payload{};
    instrumented_allocator_t rx_alloc_session{};
    instrumented_allocator_t rx_alloc_fragment{};
    instrumented_allocator_new(&tx_alloc_transfer);
    instrumented_allocator_new(&tx_alloc_payload);
    instrumented_allocator_new(&rx_alloc_session);
    instrumented_allocator_new(&rx_alloc_fragment);

    udpard_tx_t                tx{};
    std::vector<CapturedFrame> frames;
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx, 0x1111222233334444ULL, 123U, 8U, make_tx_mem(tx_alloc_transfer, tx_alloc_payload), &tx_vtable));
    tx.mtu[0] = 128U;
    tx.mtu[1] = 128U;
    tx.mtu[2] = 128U;
    tx.user   = &frames;

    const auto             rx_mem = make_rx_mem(rx_alloc_session, rx_alloc_fragment);
    const udpard_deleter_t del    = instrumented_allocator_make_deleter(&rx_alloc_fragment);
    udpard_rx_t            rx{};
    udpard_rx_port_t       port{};
    RxState                state{};
    udpard_rx_new(&rx);
    rx.user = &state;
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 1024U, rx_mem, &rx_vtable));

    // Send a zero-size payload transfer.
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    100,
                                    10000,
                                    1U,
                                    udpard_prio_nominal,
                                    1U,
                                    udpard_make_subject_endpoint(1U),
                                    make_scattered(nullptr, 0U),
                                    nullptr));
    udpard_tx_poll(&tx, 200, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_EQUAL_size_t(1, frames.size());

    // Deliver and verify.
    deliver(frames.front(), rx_mem.fragment, del, &rx, &port, 300);
    udpard_rx_poll(&rx, 400);
    TEST_ASSERT_EQUAL_size_t(1, state.count);
    TEST_ASSERT_EQUAL_size_t(0, state.payload.size());
    TEST_ASSERT_EQUAL_size_t(0, state.payload_size_wire);

    // Release all resources.
    udpard_rx_port_free(&rx, &port);
    udpard_tx_free(&tx);
    TEST_ASSERT_EQUAL_size_t(0, tx_alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, tx_alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, rx_alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, rx_alloc_fragment.allocated_fragments);
    instrumented_allocator_reset(&tx_alloc_transfer);
    instrumented_allocator_reset(&tx_alloc_payload);
    instrumented_allocator_reset(&rx_alloc_session);
    instrumented_allocator_reset(&rx_alloc_fragment);
}

void test_out_of_order_multiframe_reassembly()
{
    seed_prng();

    // Configure TX and RX.
    instrumented_allocator_t tx_alloc_transfer{};
    instrumented_allocator_t tx_alloc_payload{};
    instrumented_allocator_t rx_alloc_session{};
    instrumented_allocator_t rx_alloc_fragment{};
    instrumented_allocator_new(&tx_alloc_transfer);
    instrumented_allocator_new(&tx_alloc_payload);
    instrumented_allocator_new(&rx_alloc_session);
    instrumented_allocator_new(&rx_alloc_fragment);

    udpard_tx_t                tx{};
    std::vector<CapturedFrame> frames;
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx, 0xAAAABBBBCCCCDDDDULL, 321U, 32U, make_tx_mem(tx_alloc_transfer, tx_alloc_payload), &tx_vtable));
    tx.mtu[0] = 96U;
    tx.mtu[1] = 96U;
    tx.mtu[2] = 96U;
    tx.user   = &frames;

    const auto             rx_mem = make_rx_mem(rx_alloc_session, rx_alloc_fragment);
    const udpard_deleter_t del    = instrumented_allocator_make_deleter(&rx_alloc_fragment);
    udpard_rx_t            rx{};
    udpard_rx_port_t       port{};
    RxState                state{};
    udpard_rx_new(&rx);
    rx.user = &state;
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 4096U, rx_mem, &rx_vtable));

    // Send a payload that spans multiple frames.
    std::vector<std::uint8_t> payload(280U);
    for (std::size_t i = 0; i < payload.size(); i++) {
        payload[i] = static_cast<std::uint8_t>(i ^ 0x5AU);
    }
    const std::uint64_t transfer_id = 0xABCDEF0123456789ULL;
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    1000,
                                    100000,
                                    1U,
                                    udpard_prio_fast,
                                    transfer_id,
                                    udpard_make_subject_endpoint(55U),
                                    make_scattered(payload.data(), payload.size()),
                                    nullptr));
    udpard_tx_poll(&tx, 1001, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_TRUE(!frames.empty());

    // Deliver frames in reverse order to exercise out-of-order reassembly.
    std::reverse(frames.begin(), frames.end());
    udpard_us_t ts = 2000;
    for (const auto& frame : frames) {
        deliver(frame, rx_mem.fragment, del, &rx, &port, ts++);
    }
    udpard_rx_poll(&rx, ts + 10);

    // Verify that transfer reassembled correctly.
    TEST_ASSERT_EQUAL_size_t(1, state.count);
    TEST_ASSERT_EQUAL_UINT64(transfer_id & UDPARD_TRANSFER_ID_MASK, state.transfer_id);
    TEST_ASSERT_EQUAL_size_t(payload.size(), state.payload.size());
    TEST_ASSERT_EQUAL_MEMORY(payload.data(), state.payload.data(), payload.size());

    // Release all resources.
    udpard_rx_port_free(&rx, &port);
    udpard_tx_free(&tx);
    TEST_ASSERT_EQUAL_size_t(0, tx_alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, tx_alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, rx_alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, rx_alloc_fragment.allocated_fragments);
    instrumented_allocator_reset(&tx_alloc_transfer);
    instrumented_allocator_reset(&tx_alloc_payload);
    instrumented_allocator_reset(&rx_alloc_session);
    instrumented_allocator_reset(&rx_alloc_fragment);
}

} // namespace

void setUp() {}
void tearDown() {}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_zero_payload_transfer);
    RUN_TEST(test_out_of_order_multiframe_reassembly);
    return UNITY_END();
}
