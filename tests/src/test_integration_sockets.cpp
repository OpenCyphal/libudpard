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
#include <random>
#include <vector>

namespace {

struct CapturedFrame
{
    std::vector<std::uint8_t> bytes;
    std::uint_fast8_t         iface_index = 0;
};

struct ReceivedTransfer
{
    std::uint64_t             transfer_id = 0;
    std::uint64_t             remote_uid  = 0;
    std::vector<std::uint8_t> payload;
};

struct RxContext
{
    std::vector<ReceivedTransfer> transfers;
};

// Captures TX frames into a test-owned vector.
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

// Stores each received transfer and frees the payload.
void on_message(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    auto* ctx = static_cast<RxContext*>(rx->user);
    TEST_ASSERT_NOT_NULL(ctx);
    ReceivedTransfer out{};
    out.transfer_id = transfer.transfer_id;
    out.remote_uid  = transfer.remote.uid;
    out.payload.resize(transfer.payload_size_stored);
    const udpard_fragment_t* cursor = transfer.payload;
    (void)udpard_fragment_gather(&cursor, 0, transfer.payload_size_stored, out.payload.data());
    ctx->transfers.push_back(std::move(out));
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
             const udpard_udpip_ep_t src,
             const udpard_us_t       ts)
{
    void* const dgram = mem_res_alloc(mem, frame.bytes.size());
    TEST_ASSERT_NOT_NULL(dgram);
    (void)std::memcpy(dgram, frame.bytes.data(), frame.bytes.size());
    TEST_ASSERT_TRUE(udpard_rx_port_push(
      rx, port, ts, src, udpard_bytes_mut_t{ .size = frame.bytes.size(), .data = dgram }, del, frame.iface_index));
}

void test_reordered_multiframe_delivery()
{
    seed_prng();

    // Configure one TX node.
    instrumented_allocator_t tx_alloc_transfer{};
    instrumented_allocator_t tx_alloc_payload{};
    instrumented_allocator_new(&tx_alloc_transfer);
    instrumented_allocator_new(&tx_alloc_payload);
    udpard_tx_t                tx{};
    std::vector<CapturedFrame> frames;
    TEST_ASSERT_TRUE(
      udpard_tx_new(&tx, 0xAAAAAAAABBBBBBBBULL, 1U, 32U, make_tx_mem(tx_alloc_transfer, tx_alloc_payload), &tx_vtable));
    tx.mtu[0] = 96U;
    tx.mtu[1] = 96U;
    tx.mtu[2] = 96U;
    tx.user   = &frames;

    // Configure one RX node.
    instrumented_allocator_t rx_alloc_session{};
    instrumented_allocator_t rx_alloc_fragment{};
    instrumented_allocator_new(&rx_alloc_session);
    instrumented_allocator_new(&rx_alloc_fragment);
    const auto             rx_mem = make_rx_mem(rx_alloc_session, rx_alloc_fragment);
    const udpard_deleter_t del    = instrumented_allocator_make_deleter(&rx_alloc_fragment);
    udpard_rx_t            rx{};
    udpard_rx_port_t       port{};
    RxContext              ctx{};
    udpard_rx_new(&rx);
    rx.user = &ctx;
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 4096U, rx_mem, &rx_vtable));

    // Emit one large transfer over two interfaces.
    std::vector<std::uint8_t> payload(260U);
    for (std::size_t i = 0; i < payload.size(); i++) {
        payload[i] = static_cast<std::uint8_t>(i);
    }
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    1000,
                                    100000,
                                    (1U << 0U) | (1U << 1U),
                                    udpard_prio_fast,
                                    44U,
                                    udpard_make_subject_endpoint(123U),
                                    make_scattered(payload.data(), payload.size()),
                                    nullptr));
    udpard_tx_poll(&tx, 1001, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_TRUE(!frames.empty());

    // Reorder arrivals and deliver all frames.
    std::mt19937 prng{ static_cast<std::uint32_t>(rand()) };
    std::shuffle(frames.begin(), frames.end(), prng);
    udpard_us_t ts = 2000;
    for (const auto& frame : frames) {
        deliver(frame, rx_mem.fragment, del, &rx, &port, udpard_udpip_ep_t{ .ip = 0x0A000001U, .port = 9382U }, ts++);
    }
    udpard_rx_poll(&rx, ts + 1);

    // Deduplication must keep exactly one delivered transfer.
    TEST_ASSERT_EQUAL_size_t(1, ctx.transfers.size());
    TEST_ASSERT_EQUAL_UINT64(44U, ctx.transfers[0].transfer_id);
    TEST_ASSERT_EQUAL_UINT64(0xAAAAAAAABBBBBBBBULL, ctx.transfers[0].remote_uid);
    TEST_ASSERT_EQUAL_size_t(payload.size(), ctx.transfers[0].payload.size());
    TEST_ASSERT_EQUAL_MEMORY(payload.data(), ctx.transfers[0].payload.data(), payload.size());

    // Release resources.
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

void test_two_publishers()
{
    seed_prng();

    // Configure two TX nodes.
    instrumented_allocator_t a_tx_transfer{};
    instrumented_allocator_t a_tx_payload{};
    instrumented_allocator_t b_tx_transfer{};
    instrumented_allocator_t b_tx_payload{};
    instrumented_allocator_new(&a_tx_transfer);
    instrumented_allocator_new(&a_tx_payload);
    instrumented_allocator_new(&b_tx_transfer);
    instrumented_allocator_new(&b_tx_payload);
    udpard_tx_t                a_tx{};
    udpard_tx_t                b_tx{};
    std::vector<CapturedFrame> a_frames;
    std::vector<CapturedFrame> b_frames;
    TEST_ASSERT_TRUE(
      udpard_tx_new(&a_tx, 0x1111111111111111ULL, 2U, 16U, make_tx_mem(a_tx_transfer, a_tx_payload), &tx_vtable));
    TEST_ASSERT_TRUE(
      udpard_tx_new(&b_tx, 0x2222222222222222ULL, 3U, 16U, make_tx_mem(b_tx_transfer, b_tx_payload), &tx_vtable));
    a_tx.mtu[0] = 128U;
    a_tx.mtu[1] = 128U;
    a_tx.mtu[2] = 128U;
    b_tx.mtu[0] = 128U;
    b_tx.mtu[1] = 128U;
    b_tx.mtu[2] = 128U;
    a_tx.user   = &a_frames;
    b_tx.user   = &b_frames;

    // Configure shared RX node.
    instrumented_allocator_t rx_alloc_session{};
    instrumented_allocator_t rx_alloc_fragment{};
    instrumented_allocator_new(&rx_alloc_session);
    instrumented_allocator_new(&rx_alloc_fragment);
    const auto             rx_mem = make_rx_mem(rx_alloc_session, rx_alloc_fragment);
    const udpard_deleter_t del    = instrumented_allocator_make_deleter(&rx_alloc_fragment);
    udpard_rx_t            rx{};
    udpard_rx_port_t       port{};
    RxContext              ctx{};
    udpard_rx_new(&rx);
    rx.user = &ctx;
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 1024U, rx_mem, &rx_vtable));

    // Emit one transfer per publisher.
    static const std::uint8_t a_payload[] = { 1, 3, 5 };
    static const std::uint8_t b_payload[] = { 2, 4, 6, 8 };
    TEST_ASSERT_TRUE(udpard_tx_push(&a_tx,
                                    100,
                                    10000,
                                    1U,
                                    udpard_prio_nominal,
                                    10U,
                                    udpard_make_subject_endpoint(5U),
                                    make_scattered(a_payload, sizeof(a_payload)),
                                    nullptr));
    TEST_ASSERT_TRUE(udpard_tx_push(&b_tx,
                                    100,
                                    10000,
                                    1U,
                                    udpard_prio_nominal,
                                    20U,
                                    udpard_make_subject_endpoint(5U),
                                    make_scattered(b_payload, sizeof(b_payload)),
                                    nullptr));
    udpard_tx_poll(&a_tx, 101, UDPARD_IFACE_BITMAP_ALL);
    udpard_tx_poll(&b_tx, 101, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_EQUAL_size_t(1, a_frames.size());
    TEST_ASSERT_EQUAL_size_t(1, b_frames.size());

    // Deliver frames and verify both senders are represented.
    deliver(a_frames[0], rx_mem.fragment, del, &rx, &port, udpard_udpip_ep_t{ .ip = 0x0A000011U, .port = 9382U }, 200);
    deliver(b_frames[0], rx_mem.fragment, del, &rx, &port, udpard_udpip_ep_t{ .ip = 0x0A000022U, .port = 9382U }, 201);
    udpard_rx_poll(&rx, 300);
    TEST_ASSERT_EQUAL_size_t(2, ctx.transfers.size());

    // Release resources.
    udpard_rx_port_free(&rx, &port);
    udpard_tx_free(&a_tx);
    udpard_tx_free(&b_tx);
    TEST_ASSERT_EQUAL_size_t(0, a_tx_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, a_tx_payload.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, b_tx_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, b_tx_payload.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, rx_alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, rx_alloc_fragment.allocated_fragments);
    instrumented_allocator_reset(&a_tx_transfer);
    instrumented_allocator_reset(&a_tx_payload);
    instrumented_allocator_reset(&b_tx_transfer);
    instrumented_allocator_reset(&b_tx_payload);
    instrumented_allocator_reset(&rx_alloc_session);
    instrumented_allocator_reset(&rx_alloc_fragment);
}

} // namespace

void setUp() {}
void tearDown() {}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_reordered_multiframe_delivery);
    RUN_TEST(test_two_publishers);
    return UNITY_END();
}
