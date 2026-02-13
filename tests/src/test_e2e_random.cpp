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
    bool     operator==(const TransferKey& other) const { return transfer_id == other.transfer_id; }
};

struct TransferKeyHash
{
    size_t operator()(const TransferKey& key) const { return std::hash<uint64_t>{}(key.transfer_id); }
};

struct ExpectedPayload
{
    std::vector<uint8_t> payload;
    size_t               payload_size_wire;
};

struct Context
{
    std::unordered_map<TransferKey, ExpectedPayload, TransferKeyHash> expected;
    size_t                                                            received                  = 0;
    size_t                                                            truncated                 = 0;
    uint64_t                                                          remote_uid                = 0;
    size_t                                                            reliable_feedback_success = 0;
    size_t                                                            reliable_feedback_failure = 0;
    std::array<udpard_udpip_ep_t, UDPARD_IFACE_COUNT_MAX>             remote_endpoints{};
};

struct Arrival
{
    udpard_bytes_mut_t datagram;
    uint_fast8_t       iface_index;
};

struct CapturedFrame
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

void tx_refcount_free(void* const user, const size_t size, void* const payload)
{
    (void)user;
    udpard_tx_refcount_dec(udpard_bytes_t{ .size = size, .data = payload });
}

// Shared deleter for captured TX frames.
constexpr udpard_deleter_vtable_t tx_refcount_deleter_vt{ .free = &tx_refcount_free };

bool capture_tx_frame_impl(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection)
{
    auto* frames = static_cast<std::vector<CapturedFrame>*>(tx->user);
    if (frames == nullptr) {
        return false;
    }
    udpard_tx_refcount_inc(ejection->datagram);
    void* const data = const_cast<void*>(ejection->datagram.data); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    frames->push_back(CapturedFrame{ .datagram    = { .size = ejection->datagram.size, .data = data },
                                     .iface_index = ejection->iface_index });
    return true;
}

bool capture_tx_frame_subject(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection)
{
    return capture_tx_frame_impl(tx, ejection);
}

bool capture_tx_frame_p2p(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection, udpard_udpip_ep_t /*dest*/)
{
    return capture_tx_frame_impl(tx, ejection);
}

constexpr udpard_tx_vtable_t tx_vtable{ .eject_subject = &capture_tx_frame_subject,
                                        .eject_p2p     = &capture_tx_frame_p2p };

void record_feedback(udpard_tx_t*, const udpard_tx_feedback_t fb)
{
    auto* ctx = static_cast<Context*>(fb.user.ptr[0]);
    if (ctx != nullptr) {
        if (fb.acknowledgements > 0U) {
            ctx->reliable_feedback_success++;
        } else {
            ctx->reliable_feedback_failure++;
        }
    }
}

void on_ack_response(udpard_rx_t*, udpard_rx_port_t* port, const udpard_rx_transfer_t tr)
{
    udpard_fragment_free_all(tr.payload, udpard_make_deleter(port->memory.fragment));
}
constexpr udpard_rx_port_vtable_t ack_callbacks{ .on_message = &on_ack_response };

void on_message(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    auto* const ctx = static_cast<Context*>(rx->user);

    // Match the incoming transfer against the expected table keyed by topic hash and transfer-ID.
    const TransferKey key{ .transfer_id = transfer.transfer_id };
    const auto        it = ctx->expected.find(key);
    if (it == ctx->expected.end()) {
        udpard_fragment_free_all(transfer.payload, udpard_make_deleter(port->memory.fragment));
        return;
    }

    // Gather fragments into a contiguous buffer so we can compare the stored prefix (payload may be truncated).
    std::vector<uint8_t>     assembled(transfer.payload_size_stored);
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
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        if ((transfer.remote.endpoints[i].ip != 0U) || (transfer.remote.endpoints[i].port != 0U)) {
            TEST_ASSERT_EQUAL_UINT32(ctx->remote_endpoints[i].ip, transfer.remote.endpoints[i].ip);
            TEST_ASSERT_EQUAL_UINT16(ctx->remote_endpoints[i].port, transfer.remote.endpoints[i].port);
        }
    }
    if (transfer.payload_size_stored < transfer.payload_size_wire) {
        ctx->truncated++;
    }

    // Clean up.
    udpard_fragment_free_all(transfer.payload, udpard_make_deleter(port->memory.fragment));
    ctx->expected.erase(it);
    ctx->received++;
}

constexpr udpard_rx_port_vtable_t callbacks{ .on_message = &on_message };

/// Randomized end-to-end TX/RX covering fragmentation, reordering, and extent-driven truncation.
void test_udpard_tx_rx_end_to_end()
{
    seed_prng();

    // TX allocator setup and pipeline initialization.
    instrumented_allocator_t tx_alloc_transfer{};
    instrumented_allocator_new(&tx_alloc_transfer);
    instrumented_allocator_t tx_alloc_payload{};
    instrumented_allocator_new(&tx_alloc_payload);
    udpard_tx_mem_resources_t tx_mem{};
    tx_mem.transfer = instrumented_allocator_make_resource(&tx_alloc_transfer);
    for (auto& res : tx_mem.payload) {
        res = instrumented_allocator_make_resource(&tx_alloc_payload);
    }
    udpard_tx_t tx{};
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x0A0B0C0D0E0F1011ULL, 123U, 256, tx_mem, &tx_vtable));
    instrumented_allocator_t ack_alloc_transfer{};
    instrumented_allocator_t ack_alloc_payload{};
    instrumented_allocator_new(&ack_alloc_transfer);
    instrumented_allocator_new(&ack_alloc_payload);
    udpard_tx_mem_resources_t ack_mem{};
    ack_mem.transfer = instrumented_allocator_make_resource(&ack_alloc_transfer);
    for (auto& res : ack_mem.payload) {
        res = instrumented_allocator_make_resource(&ack_alloc_payload);
    }
    udpard_tx_t ack_tx{};
    TEST_ASSERT_TRUE(udpard_tx_new(&ack_tx, 0x1020304050607080ULL, 321U, 256, ack_mem, &tx_vtable));

    // RX allocator setup and shared RX instance with callbacks.
    instrumented_allocator_t rx_alloc_frag{};
    instrumented_allocator_new(&rx_alloc_frag);
    instrumented_allocator_t rx_alloc_session{};
    instrumented_allocator_new(&rx_alloc_session);
    const udpard_rx_mem_resources_t rx_mem{ .session  = instrumented_allocator_make_resource(&rx_alloc_session),
                                            .slot     = instrumented_allocator_make_resource(&rx_alloc_session),
                                            .fragment = instrumented_allocator_make_resource(&rx_alloc_frag) };
    udpard_rx_t                     rx;
    udpard_rx_new(&rx, &ack_tx);
    instrumented_allocator_t ack_rx_alloc_frag{};
    instrumented_allocator_t ack_rx_alloc_session{};
    instrumented_allocator_new(&ack_rx_alloc_frag);
    instrumented_allocator_new(&ack_rx_alloc_session);
    const udpard_rx_mem_resources_t ack_rx_mem{ .session  = instrumented_allocator_make_resource(&ack_rx_alloc_session),
                                                .slot     = instrumented_allocator_make_resource(&ack_rx_alloc_session),
                                                .fragment = instrumented_allocator_make_resource(&ack_rx_alloc_frag) };
    udpard_rx_t                     ack_rx{};
    udpard_rx_port_t                ack_port{};
    udpard_rx_new(&ack_rx, &tx);

    // Test parameters.
    constexpr std::array<size_t, 3> extents{ 1000, 5000, SIZE_MAX };

    // Configure ports with varied extents and reordering windows to cover truncation and different RX modes.
    std::array<udpard_rx_port_t, 3> ports{};
    for (size_t i = 0; i < ports.size(); i++) {
        TEST_ASSERT_TRUE(udpard_rx_port_new(&ports[i], extents[i], rx_mem, &callbacks));
    }

    // Setup the context.
    Context ctx{};
    ctx.remote_uid = tx.local_uid;
    for (size_t i = 0; i < ports.size(); i++) {
        ctx.remote_endpoints[i] = { .ip   = static_cast<uint32_t>(0x0A000001U + i),
                                    .port = static_cast<uint16_t>(7400U + i) };
    }
    rx.user = &ctx;
    constexpr udpard_deleter_t tx_payload_deleter{ .vtable = &tx_refcount_deleter_vt, .context = nullptr };
    // Ack path wiring.
    std::vector<CapturedFrame> frames;
    tx.user = &frames;
    std::vector<CapturedFrame> ack_frames;
    ack_tx.user = &ack_frames;
    TEST_ASSERT_TRUE(udpard_rx_port_new_p2p(&ack_port, 16, ack_rx_mem, &ack_callbacks));
    std::array<udpard_udpip_ep_t, UDPARD_IFACE_COUNT_MAX> ack_sources{};
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        ack_sources[i] = { .ip = static_cast<uint32_t>(0x0A000020U + i), .port = static_cast<uint16_t>(7700U + i) };
    }

    // Main test loop: generate transfers, push into TX, drain and shuffle frames, push into RX.
    uint64_t    next_transfer_id = (static_cast<uint64_t>(rand()) << 32U) ^ static_cast<uint64_t>(rand());
    size_t      reliable_total   = 0;
    udpard_us_t now              = 0;
    for (size_t transfer_index = 0; transfer_index < 1000; transfer_index++) {
        now += static_cast<udpard_us_t>(random_range(1000, 5000));
        frames.clear();

        // Pick a port, build a random payload, and remember what to expect on that topic.
        const size_t         port_index   = random_range(0, ports.size() - 1U);
        const uint64_t       transfer_id  = next_transfer_id++;
        const size_t         payload_size = random_range(0, 10000);
        std::vector<uint8_t> payload(payload_size);
        fill_random(payload);
        const bool reliable = (random_range(0, 3) == 0); // About a quarter reliable.
        if (reliable) {
            reliable_total++;
        }

        // Each transfer is sent on all redundant interfaces with different MTUs to exercise fragmentation variety.
        const udpard_bytes_scattered_t payload_view = make_scattered(payload.data(), payload.size());
        const auto        priority = static_cast<udpard_prio_t>(random_range(0, UDPARD_PRIORITY_COUNT - 1U));
        const TransferKey key{ .transfer_id = transfer_id };
        const bool        inserted =
          ctx.expected.emplace(key, ExpectedPayload{ .payload = payload, .payload_size_wire = payload.size() }).second;
        TEST_ASSERT_TRUE(inserted);

        // Generate MTUs per redundant interface.
        std::array<size_t, UDPARD_IFACE_COUNT_MAX> mtu_values{};
        for (auto& x : mtu_values) {
            x = random_range(UDPARD_MTU_MIN, 3000U);
        }
        for (size_t iface = 0; iface < UDPARD_IFACE_COUNT_MAX; iface++) {
            tx.mtu[iface] = mtu_values[iface];
        }
        // Enqueue one transfer spanning all interfaces.
        const udpard_us_t deadline = now + 1000000;
        TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                        now,
                                        deadline,
                                        UDPARD_IFACE_BITMAP_ALL,
                                        priority,
                                        transfer_id,
                                        payload_view,
                                        reliable ? &record_feedback : nullptr,
                                        reliable ? make_user_context(&ctx) : UDPARD_USER_CONTEXT_NULL));
        udpard_tx_poll(&tx, now, UDPARD_IFACE_BITMAP_ALL);

        // Shuffle and push frames into the RX pipeline, simulating out-of-order redundant arrival.
        std::vector<Arrival> arrivals;
        arrivals.reserve(frames.size());
        for (const auto& [datagram, iface_index] : frames) {
            arrivals.push_back(Arrival{ .datagram = datagram, .iface_index = iface_index });
        }
        shuffle_frames(arrivals);
        const size_t keep_iface     = reliable ? random_range(0, UDPARD_IFACE_COUNT_MAX - 1U) : 0U;
        const size_t loss_iface     = reliable ? ((keep_iface + 1U) % UDPARD_IFACE_COUNT_MAX) : UDPARD_IFACE_COUNT_MAX;
        const size_t ack_loss_iface = loss_iface;
        for (const auto& [datagram, iface_index] : arrivals) {
            const bool drop = reliable && (iface_index == loss_iface) && ((rand() % 3) == 0);
            if (drop) {
                udpard_tx_refcount_dec(udpard_bytes_t{ .size = datagram.size, .data = datagram.data });
            } else {
                TEST_ASSERT_TRUE(udpard_rx_port_push(&rx,
                                                     &ports[port_index],
                                                     now,
                                                     ctx.remote_endpoints[iface_index],
                                                     datagram,
                                                     tx_payload_deleter,
                                                     iface_index));
            }
            now += 1;
        }

        // Let the RX pipeline purge timeouts and deliver ready transfers.
        udpard_rx_poll(&rx, now);
        ack_frames.clear();
        udpard_tx_poll(&ack_tx, now, UDPARD_IFACE_BITMAP_ALL);
        bool ack_delivered = false;
        for (const auto& [datagram, iface_index] : ack_frames) {
            const bool drop_ack = reliable && (iface_index == ack_loss_iface);
            if (drop_ack) {
                udpard_tx_refcount_dec(udpard_bytes_t{ .size = datagram.size, .data = datagram.data });
                continue;
            }
            ack_delivered = true;
            TEST_ASSERT_TRUE(udpard_rx_port_push(
              &ack_rx, &ack_port, now, ack_sources[iface_index], datagram, tx_payload_deleter, iface_index));
        }
        if (reliable && !ack_delivered && !ack_frames.empty()) {
            const auto& [datagram, iface_index] = ack_frames.front();
            TEST_ASSERT_TRUE(udpard_rx_port_push(
              &ack_rx, &ack_port, now, ack_sources[iface_index], datagram, tx_payload_deleter, iface_index));
        }
        udpard_rx_poll(&ack_rx, now);
    }

    // Final poll/validation and cleanup.
    udpard_rx_poll(&rx, now + 1000000);
    udpard_rx_poll(&ack_rx, now + 1000000);
    TEST_ASSERT_TRUE(ctx.expected.empty());
    TEST_ASSERT_EQUAL_size_t(1000, ctx.received);
    TEST_ASSERT_TRUE(ctx.truncated > 0);
    TEST_ASSERT_EQUAL_size_t(reliable_total, ctx.reliable_feedback_success);
    TEST_ASSERT_EQUAL_size_t(0, ctx.reliable_feedback_failure);
    for (auto& port : ports) {
        udpard_rx_port_free(&rx, &port);
    }
    udpard_rx_port_free(&ack_rx, &ack_port);
    udpard_tx_free(&tx);
    udpard_tx_free(&ack_tx);
    TEST_ASSERT_EQUAL_size_t(0, rx_alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, rx_alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, tx_alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, tx_alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, ack_alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, ack_alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, ack_rx_alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, ack_rx_alloc_session.allocated_fragments);
    instrumented_allocator_reset(&rx_alloc_frag);
    instrumented_allocator_reset(&rx_alloc_session);
    instrumented_allocator_reset(&tx_alloc_transfer);
    instrumented_allocator_reset(&tx_alloc_payload);
    instrumented_allocator_reset(&ack_alloc_transfer);
    instrumented_allocator_reset(&ack_alloc_payload);
    instrumented_allocator_reset(&ack_rx_alloc_frag);
    instrumented_allocator_reset(&ack_rx_alloc_session);
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
