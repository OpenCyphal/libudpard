/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

// ReSharper disable CppPassValueParameterByConstReference

#include <udpard.h>
#include "helpers.h"
#include <unity.h>
#include <algorithm>
#include <array>
#include <unordered_map>
#include <vector>

namespace {

struct TransferKey
{
    uint64_t transfer_id;
    uint64_t topic_hash;
    bool     operator==(const TransferKey& other) const
    {
        return (transfer_id == other.transfer_id) && (topic_hash == other.topic_hash);
    }
};

struct TransferKeyHash
{
    size_t operator()(const TransferKey& key) const
    {
        return (std::hash<uint64_t>{}(key.transfer_id) << 1U) ^ std::hash<uint64_t>{}(key.topic_hash);
    }
};

struct ExpectedPayload
{
    std::vector<uint8_t> payload;
    size_t               payload_size_wire;
};

struct Context
{
    std::unordered_map<TransferKey, ExpectedPayload, TransferKeyHash> expected;
    size_t                                                            received         = 0;
    size_t                                                            collisions       = 0;
    size_t                                                            ack_mandates     = 0;
    size_t                                                            truncated        = 0;
    uint64_t                                                          remote_uid       = 0;
    std::array<udpard_udpip_ep_t, UDPARD_NETWORK_INTERFACE_COUNT_MAX> remote_endpoints = {};
};

struct Arrival
{
    udpard_bytes_mut_t datagram;
    uint_fast8_t       iface_index;
};

size_t random_range(const size_t min, const size_t max)
{
    const size_t span = max - min + 1U;
    return min + (static_cast<size_t>(rand()) % span);
}

void fill_random(std::vector<uint8_t>& data)
{
    for (auto& byte : data) {
        byte = static_cast<uint8_t>(random_range(0, UINT8_MAX));
    }
}

void shuffle_frames(std::vector<Arrival>& frames)
{
    for (size_t i = frames.size(); i > 1; i--) {
        const size_t j = random_range(0, i - 1);
        std::swap(frames[i - 1U], frames[j]);
    }
}

void on_message(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    auto* const ctx = static_cast<Context*>(rx->user);

    // Match the incoming transfer against the expected table keyed by topic hash and transfer-ID.
    const TransferKey key{ .transfer_id = transfer.transfer_id, .topic_hash = port->topic_hash };
    const auto        it = ctx->expected.find(key);
    TEST_ASSERT(it != ctx->expected.end());

    // Gather fragments into a contiguous buffer so we can compare the stored prefix (payload may be truncated).
    std::vector<uint8_t>  assembled(transfer.payload_size_stored);
    const udpard_fragment_t* payload_cursor = transfer.payload;
    const size_t gathered = udpard_fragment_gather(&payload_cursor, 0, transfer.payload_size_stored, assembled.data());
    TEST_ASSERT_EQUAL_size_t(transfer.payload_size_stored, gathered);
    TEST_ASSERT_TRUE(transfer.payload_size_stored <= it->second.payload.size());
    TEST_ASSERT_EQUAL_size_t(it->second.payload_size_wire, transfer.payload_size_wire);
    if (transfer.payload_size_stored > 0U) {
        TEST_ASSERT_EQUAL_MEMORY(it->second.payload.data(), assembled.data(), transfer.payload_size_stored);
    }

    // Verify remote and the return path discovery.
    TEST_ASSERT_EQUAL_UINT64(ctx->remote_uid, transfer.remote.uid);
    for (size_t i = 0; i < UDPARD_NETWORK_INTERFACE_COUNT_MAX; i++) {
        if ((transfer.remote.endpoints[i].ip != 0U) || (transfer.remote.endpoints[i].port != 0U)) {
            TEST_ASSERT_EQUAL_UINT32(ctx->remote_endpoints[i].ip, transfer.remote.endpoints[i].ip);
            TEST_ASSERT_EQUAL_UINT16(ctx->remote_endpoints[i].port, transfer.remote.endpoints[i].port);
        }
    }
    if (transfer.payload_size_stored < transfer.payload_size_wire) {
        ctx->truncated++;
    }

    // Clean up.
    udpard_fragment_free_all(transfer.payload, port->memory.fragment);
    ctx->expected.erase(it);
    ctx->received++;
}

void on_collision(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_remote_t remote)
{
    auto* ctx = static_cast<Context*>(rx->user);
    (void)port;
    (void)remote;
    ctx->collisions++;
}

void on_ack_mandate(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_ack_mandate_t mandate)
{
    auto* ctx = static_cast<Context*>(rx->user);
    (void)port;
    (void)mandate;
    ctx->ack_mandates++;
}

/// Randomized end-to-end TX/RX covering fragmentation, reordering, and extent-driven truncation.
void test_udpard_tx_rx_end_to_end()
{
    seed_prng();

    // TX allocator setup and pipeline initialization.
    instrumented_allocator_t tx_alloc_frag{};
    instrumented_allocator_new(&tx_alloc_frag);
    instrumented_allocator_t tx_alloc_payload{};
    instrumented_allocator_new(&tx_alloc_payload);
    const udpard_mem_deleter_t      tx_payload_deleter = instrumented_allocator_make_deleter(&tx_alloc_payload);
    const udpard_tx_mem_resources_t tx_mem{ .fragment = instrumented_allocator_make_resource(&tx_alloc_frag),
                                            .payload  = instrumented_allocator_make_resource(&tx_alloc_payload) };
    udpard_tx_t                     tx;
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x0A0B0C0D0E0F1011ULL, 256, tx_mem));

    // RX allocator setup and shared RX instance with callbacks.
    instrumented_allocator_t rx_alloc_frag{};
    instrumented_allocator_new(&rx_alloc_frag);
    instrumented_allocator_t rx_alloc_session{};
    instrumented_allocator_new(&rx_alloc_session);
    const udpard_rx_mem_resources_t rx_mem{ .session  = instrumented_allocator_make_resource(&rx_alloc_session),
                                            .fragment = instrumented_allocator_make_resource(&rx_alloc_frag) };
    udpard_rx_t                     rx;
    TEST_ASSERT_TRUE(udpard_rx_new(&rx, &on_message, &on_collision, &on_ack_mandate));

    // Test parameters.
    constexpr std::array<uint64_t, 3>    topic_hashes{ 0x123456789ABCDEF0ULL,
                                                    0x0FEDCBA987654321ULL,
                                                    0x00ACE00ACE00ACEULL };
    constexpr std::array<uint32_t, 3>    subject_ids{ 10U, 20U, 30U };
    constexpr std::array<udpard_us_t, 3> reorder_windows{ 2000, UDPARD_RX_REORDERING_WINDOW_UNORDERED, 5000 };
    constexpr std::array<size_t, 3>      extents{ 1000, 5000, SIZE_MAX };
    std::array<uint_fast8_t, 3>          iface_indices{ 0U, 1U, 2U };

    // Configure ports with varied extents and reordering windows to cover truncation and different RX modes.
    std::array<udpard_rx_port_t, 3> ports{};
    for (size_t i = 0; i < ports.size(); i++) {
        TEST_ASSERT_TRUE(udpard_rx_port_new(&ports[i], topic_hashes[i], extents[i], reorder_windows[i], rx_mem));
    }

    // Setup the context.
    Context ctx{};
    ctx.remote_uid = tx.local_uid;
    for (size_t i = 0; i < ports.size(); i++) {
        ctx.remote_endpoints[i] = { .ip   = static_cast<uint32_t>(0x0A000001U + i),
                                    .port = static_cast<uint16_t>(7400U + i) };
    }
    rx.user = &ctx;

    // Main test loop: generate transfers, push into TX, drain and shuffle frames, push into RX.
    std::array<uint64_t, 3> transfer_ids{ static_cast<uint64_t>(rand()),
                                          static_cast<uint64_t>(rand()),
                                          static_cast<uint64_t>(rand()) };
    udpard_us_t             now = 0;
    for (size_t transfer_index = 0; transfer_index < 1000; transfer_index++) {
        now += static_cast<udpard_us_t>(random_range(1000, 5000));

        // Pick a port, build a random payload, and remember what to expect on that topic.
        const size_t         port_index   = random_range(0, ports.size() - 1U);
        const uint64_t       transfer_id  = transfer_ids[port_index]++;
        const size_t         payload_size = random_range(0, 10000);
        std::vector<uint8_t> payload(payload_size);
        fill_random(payload);

        // Each transfer is sent on all redundant interfaces with different MTUs to exercise fragmentation variety.
        const udpard_bytes_t    payload_view{ .size = payload.size(), .data = payload.data() };
        const auto              priority = static_cast<udpard_prio_t>(random_range(0, UDPARD_PRIORITY_MAX));
        const udpard_udpip_ep_t dest     = udpard_make_subject_endpoint(subject_ids[port_index]);
        const TransferKey       key{ .transfer_id = transfer_id, .topic_hash = topic_hashes[port_index] };
        const bool              inserted =
          ctx.expected.emplace(key, ExpectedPayload{ .payload = payload, .payload_size_wire = payload.size() }).second;
        TEST_ASSERT_TRUE(inserted);

        // Generate MTUs per redundant interface.
        std::array<size_t, 3> mtu_values{};
        for (auto& x : mtu_values) {
            x = random_range(UDPARD_MTU_MIN, 3000U);
        }

        // Enqueue one transfer per interface with the per-interface MTU applied.
        const udpard_us_t deadline = now + 1000000;
        for (size_t iface = 0; iface < 3; iface++) {
            tx.mtu = mtu_values[iface];
            TEST_ASSERT_GREATER_THAN_UINT32(0U,
                                            udpard_tx_push(&tx,
                                                           now,
                                                           deadline,
                                                           priority,
                                                           topic_hashes[port_index],
                                                           dest,
                                                           transfer_id,
                                                           payload_view,
                                                           false,
                                                           &iface_indices[iface]));
        }

        // Drain TX queue into local frame list so we can shuffle before injecting into RX ports.
        std::vector<Arrival> frames;
        frames.reserve(tx.queue_size);
        while (udpard_tx_item_t* const item = udpard_tx_peek(&tx, now)) {
            udpard_tx_pop(&tx, item);
            frames.push_back({ .datagram    = item->datagram_payload,
                               .iface_index = *static_cast<uint_fast8_t*>(item->user_transfer_reference) });
            item->datagram_payload.data = nullptr;
            item->datagram_payload.size = 0;
            udpard_tx_free(tx.memory, item);
        }

        // Shuffle and push frames into the RX pipeline, simulating out-of-order redundant arrival.
        shuffle_frames(frames);
        for (const auto& [datagram, iface_index] : frames) {
            TEST_ASSERT_TRUE(udpard_rx_port_push(&rx,
                                                 &ports[port_index],
                                                 now,
                                                 ctx.remote_endpoints[iface_index],
                                                 datagram,
                                                 tx_payload_deleter,
                                                 iface_index));
            now += 1;
        }

        // Let the RX pipeline purge timeouts and deliver ready transfers.
        udpard_rx_poll(&rx, now);
        TEST_ASSERT_EQUAL_size_t(0, tx.queue_size);
    }

    // Final poll/validation and cleanup.
    udpard_rx_poll(&rx, now + 1000000);
    TEST_ASSERT_TRUE(ctx.expected.empty());
    TEST_ASSERT_EQUAL_size_t(1000, ctx.received);
    TEST_ASSERT_TRUE(ctx.truncated > 0);
    TEST_ASSERT_EQUAL_size_t(0, ctx.collisions);
    TEST_ASSERT_EQUAL_size_t(0, ctx.ack_mandates);
    for (auto& port : ports) {
        udpard_rx_port_free(&rx, &port);
    }
    TEST_ASSERT_EQUAL_size_t(0, rx_alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, rx_alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, tx_alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, tx_alloc_payload.allocated_fragments);
    instrumented_allocator_reset(&rx_alloc_frag);
    instrumented_allocator_reset(&rx_alloc_session);
    instrumented_allocator_reset(&tx_alloc_frag);
    instrumented_allocator_reset(&tx_alloc_payload);
}

} // namespace

extern "C" void setUp() {}

extern "C" void tearDown() {}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_udpard_tx_rx_end_to_end);
    return UNITY_END();
}
