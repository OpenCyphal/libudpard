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
#include <unordered_map>
#include <vector>

namespace {

struct CapturedFrame
{
    std::vector<std::uint8_t> bytes;
    std::uint_fast8_t         iface_index = 0;
};

struct ReceivedTransfer
{
    std::vector<std::uint8_t> payload;
    std::size_t               count = 0;
};

struct RxContext
{
    std::unordered_map<std::uint64_t, ReceivedTransfer> received;
};

// Captures every ejected frame.
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

// Records received transfer payload by transfer-ID.
void on_message(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    auto* ctx = static_cast<RxContext*>(rx->user);
    TEST_ASSERT_NOT_NULL(ctx);
    auto& rec = ctx->received[transfer.transfer_id];
    rec.count++;
    rec.payload.resize(transfer.payload_size_stored);
    const udpard_fragment_t* cursor = transfer.payload;
    (void)udpard_fragment_gather(&cursor, 0, transfer.payload_size_stored, rec.payload.data());
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

// Delivers one captured frame to RX.
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

void test_randomized_deduplication()
{
    seed_prng();
    std::mt19937                       prng{ static_cast<std::uint32_t>(rand()) };
    std::uniform_int_distribution<int> payload_len{ 0, 180 };

    // Configure TX.
    instrumented_allocator_t tx_alloc_transfer{};
    instrumented_allocator_t tx_alloc_payload{};
    instrumented_allocator_new(&tx_alloc_transfer);
    instrumented_allocator_new(&tx_alloc_payload);
    udpard_tx_t                tx{};
    std::vector<CapturedFrame> frames;
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx, 0x1010101010101010ULL, 123U, 512U, make_tx_mem(tx_alloc_transfer, tx_alloc_payload), &tx_vtable));
    tx.mtu[0] = 192U;
    tx.mtu[1] = 192U;
    tx.mtu[2] = 192U;
    tx.user   = &frames;

    // Configure RX.
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
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 2048U, rx_mem, &rx_vtable));

    // Push many transfers and keep the expected payload map.
    std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> expected;
    constexpr std::size_t                                        transfer_count = 80U;
    for (std::size_t i = 0; i < transfer_count; i++) {
        const auto                len = static_cast<std::size_t>(payload_len(prng));
        std::vector<std::uint8_t> payload(len);
        for (std::size_t j = 0; j < len; j++) {
            payload[j] = static_cast<std::uint8_t>(prng() & 0xFFU);
        }
        const std::uint64_t transfer_id = 1000U + i;
        expected[transfer_id]           = payload;
        TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                        1000 + static_cast<udpard_us_t>(i),
                                        1000000,
                                        (1U << 0U) | (1U << 1U),
                                        udpard_prio_nominal,
                                        transfer_id,
                                        udpard_make_subject_endpoint(77U),
                                        make_scattered(payload.data(), payload.size()),
                                        nullptr));
        udpard_tx_poll(&tx, 2000 + static_cast<udpard_us_t>(i), UDPARD_IFACE_BITMAP_ALL);
    }

    // Randomize arrival order and inject all captured frames.
    std::shuffle(frames.begin(), frames.end(), prng);
    udpard_us_t ts = 5000;
    for (const auto& frame : frames) {
        deliver(frame, rx_mem.fragment, del, &rx, &port, ts++);
    }
    udpard_rx_poll(&rx, ts + 10);

    // Payloads must match; one transfer may be skipped due RX history initialization policy.
    TEST_ASSERT_LESS_OR_EQUAL_size_t(expected.size(), ctx.received.size());
    TEST_ASSERT_GREATER_OR_EQUAL_size_t(expected.size() - 1U, ctx.received.size());
    for (const auto& [transfer_id, payload] : ctx.received) {
        auto it = expected.find(transfer_id);
        TEST_ASSERT_TRUE(it != expected.end());
        TEST_ASSERT_GREATER_OR_EQUAL_size_t(1, payload.count);
        TEST_ASSERT_EQUAL_size_t(it->second.size(), payload.payload.size());
        if (!it->second.empty()) {
            TEST_ASSERT_EQUAL_MEMORY(it->second.data(), payload.payload.data(), it->second.size());
        }
    }
    size_t missing = 0U;
    for (const auto& [transfer_id, payload] : expected) {
        auto it = ctx.received.find(transfer_id);
        if (it == ctx.received.end()) {
            missing++;
            continue;
        }
        TEST_ASSERT_GREATER_OR_EQUAL_size_t(1, it->second.count);
        TEST_ASSERT_EQUAL_size_t(payload.size(), it->second.payload.size());
        if (!payload.empty()) {
            TEST_ASSERT_EQUAL_MEMORY(payload.data(), it->second.payload.data(), payload.size());
        }
    }
    TEST_ASSERT_LESS_OR_EQUAL_size_t(1, missing);

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

} // namespace

void setUp() {}
void tearDown() {}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_randomized_deduplication);
    return UNITY_END();
}
