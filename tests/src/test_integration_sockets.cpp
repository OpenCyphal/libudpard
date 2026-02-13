/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT
///
/// Integration test that verifies end-to-end behavior with frame capture/injection,
/// random packet loss, and reordering simulation.

#include <udpard.h>
#include "helpers.h"
#include <unity.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

namespace {

// Brief network simulator with loss/reorder support.
class NetworkSimulator
{
  public:
    NetworkSimulator(const double loss_rate, const bool enable_reorder, const uint32_t seed = 1U)
      : loss_rate_(std::clamp(loss_rate, 0.0, 1.0))
      , enable_reorder_(enable_reorder)
      , rng_(seed)
      , drop_(loss_rate_)
    {
    }

    // Shuffle frames to simulate reordering.
    template<typename T>
    void shuffle(std::vector<T>& items)
    {
        if (enable_reorder_ && (items.size() > 1U)) {
            std::shuffle(items.begin(), items.end(), rng_);
            reordered_ = true;
        }
    }

    // Decide whether to drop; guarantee at least one drop if loss is enabled.
    bool drop_next(const size_t frames_left)
    {
        bool drop = (loss_rate_ > 0.0) && drop_(rng_);
        if ((!drop) && (loss_rate_ > 0.0) && (frames_left == 1U) && (dropped_ == 0U)) {
            drop = true;
        }
        if (drop) {
            dropped_++;
        }
        return drop;
    }

    [[nodiscard]] size_t dropped() const { return dropped_; }
    [[nodiscard]] bool   reordered() const { return reordered_; }

  private:
    double                      loss_rate_;
    bool                        enable_reorder_;
    std::mt19937                rng_;
    std::bernoulli_distribution drop_;
    size_t                      dropped_   = 0;
    bool                        reordered_ = false;
};

// =====================================================================================================================
// Test context for tracking received transfers
// =====================================================================================================================

struct ReceivedTransfer
{
    std::vector<uint8_t> payload;
    uint64_t             transfer_id;
    uint64_t             remote_uid;
    size_t               payload_size_wire;
};

struct TestContext
{
    std::vector<ReceivedTransfer> received_transfers;
};

// =====================================================================================================================
// Captured frame for TX ejection
// =====================================================================================================================

struct CapturedFrame
{
    std::vector<uint8_t> data;
    uint_fast8_t         iface_index;
};

// =====================================================================================================================
// Callbacks
// =====================================================================================================================

bool capture_frame_impl(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection)
{
    auto* frames = static_cast<std::vector<CapturedFrame>*>(tx->user);
    if (frames == nullptr) {
        return false;
    }

    CapturedFrame frame{};
    frame.data.assign(static_cast<const uint8_t*>(ejection->datagram.data),
                      static_cast<const uint8_t*>(ejection->datagram.data) + ejection->datagram.size);
    frame.iface_index = ejection->iface_index;
    frames->push_back(frame);

    return true;
}
bool capture_frame_subject(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection)
{
    return capture_frame_impl(tx, ejection);
}
bool capture_frame_p2p(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection, udpard_udpip_ep_t /*dest*/)
{
    return capture_frame_impl(tx, ejection);
}

constexpr udpard_tx_vtable_t tx_vtable{ .eject_subject = &capture_frame_subject, .eject_p2p = &capture_frame_p2p };

void on_message(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    auto* ctx = static_cast<TestContext*>(rx->user);
    if (ctx != nullptr) {
        ReceivedTransfer rt{};
        rt.transfer_id       = transfer.transfer_id;
        rt.remote_uid        = transfer.remote.uid;
        rt.payload_size_wire = transfer.payload_size_wire;

        rt.payload.resize(transfer.payload_size_stored);
        const udpard_fragment_t* cursor = transfer.payload;
        (void)udpard_fragment_gather(&cursor, 0, transfer.payload_size_stored, rt.payload.data());

        ctx->received_transfers.push_back(std::move(rt));
    }

    udpard_fragment_free_all(transfer.payload, udpard_make_deleter(port->memory.fragment));
}

constexpr udpard_rx_port_vtable_t rx_port_vtable{ .on_message = &on_message };

// =====================================================================================================================
// Fixtures and helpers
// =====================================================================================================================

// Build a random payload of requested size.
std::vector<uint8_t> make_payload(const size_t size)
{
    std::vector<uint8_t> payload(size);
    for (auto& byte : payload) {
        byte = static_cast<uint8_t>(rand() % 256);
    }
    return payload;
}

// Simple TX owner that captures frames.
struct TxFixture
{
    instrumented_allocator_t   transfer{};
    instrumented_allocator_t   payload{};
    udpard_tx_mem_resources_t  mem{};
    udpard_tx_t                tx{};
    std::vector<CapturedFrame> frames;

    void init(const uint64_t uid, const uint64_t timeout, const uint16_t mtu)
    {
        instrumented_allocator_new(&transfer);
        instrumented_allocator_new(&payload);

        mem.transfer = instrumented_allocator_make_resource(&transfer);
        for (auto& res : mem.payload) {
            res = instrumented_allocator_make_resource(&payload);
        }

        TEST_ASSERT_TRUE(udpard_tx_new(&tx, uid, timeout, mtu, mem, &tx_vtable));
        tx.user = &frames;
    }

    void fini()
    {
        udpard_tx_free(&tx);
        TEST_ASSERT_EQUAL_size_t(0, transfer.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, payload.allocated_fragments);
    }
};

// Simple RX owner with context.
struct RxFixture
{
    instrumented_allocator_t  session{};
    instrumented_allocator_t  fragment{};
    udpard_rx_mem_resources_t mem{};
    udpard_rx_t               rx{};
    TestContext               ctx{};

    void init()
    {
        instrumented_allocator_new(&session);
        instrumented_allocator_new(&fragment);
        mem.session  = instrumented_allocator_make_resource(&session);
        mem.slot     = instrumented_allocator_make_resource(&session);
        mem.fragment = instrumented_allocator_make_resource(&fragment);
        udpard_rx_new(&rx, nullptr);
        rx.user = &ctx;
    }

    void fini() const
    {
        TEST_ASSERT_EQUAL_size_t(0, session.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, fragment.allocated_fragments);
    }
};

// Create a subject port.
udpard_rx_port_t make_subject_port(const size_t extent, RxFixture& rx)
{
    udpard_rx_port_t port{};
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, extent, rx.mem, &rx_port_vtable));
    return port;
}

// =====================================================================================================================
// Helper to deliver frames with optional loss/reorder.
void deliver_frames(std::vector<CapturedFrame>       frames,
                    udpard_rx_t*                     rx,
                    udpard_rx_port_t*                port,
                    const udpard_rx_mem_resources_t& rx_mem,
                    const udpard_udpip_ep_t&         src_ep,
                    udpard_us_t                      now,
                    NetworkSimulator*                sim = nullptr)
{
    if (sim != nullptr) {
        sim->shuffle(frames);
    }
    const size_t total = frames.size();
    for (size_t i = 0; i < total; i++) {
        if ((sim != nullptr) && sim->drop_next(total - i)) {
            now++;
            continue;
        }

        const auto&            frame = frames[i];
        const udpard_deleter_t deleter{ .vtable = &rx_mem.fragment.vtable->base, .context = rx_mem.fragment.context };
        void*                  dgram = mem_res_alloc(rx_mem.fragment, frame.data.size());
        TEST_ASSERT_NOT_NULL(dgram);
        std::memcpy(dgram, frame.data.data(), frame.data.size());

        const udpard_bytes_mut_t dgram_view{ frame.data.size(), dgram };

        TEST_ASSERT_TRUE(udpard_rx_port_push(rx, port, now, src_ep, dgram_view, deleter, frame.iface_index));
        now++;
    }
    udpard_rx_poll(rx, now);
}

// =====================================================================================================================
// Tests
// =====================================================================================================================

/// Basic single-frame transfer end-to-end
void test_single_frame_transfer()
{
    seed_prng();

    constexpr uint64_t publisher_uid = 0x1111222233334444ULL;
    constexpr uint64_t transfer_id   = 42U;

    // Set up publisher.
    TxFixture pub{};
    pub.init(publisher_uid, 100U, 256);

    // Set up subscriber.
    RxFixture sub{};
    sub.init();
    udpard_rx_port_t sub_port = make_subject_port(4096, sub);

    // Send a small payload.
    const std::vector<uint8_t>     payload      = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const udpard_bytes_scattered_t payload_view = make_scattered(payload.data(), payload.size());

    const udpard_us_t now      = 1000000;
    const udpard_us_t deadline = now + 1000000;

    TEST_ASSERT_TRUE(udpard_tx_push(&pub.tx,
                                    now,
                                    deadline,
                                    1U, // iface_bitmap: interface 0 only
                                    udpard_prio_nominal,
                                    transfer_id,
                                    payload_view,
                                    nullptr,
                                    UDPARD_USER_CONTEXT_NULL));

    udpard_tx_poll(&pub.tx, now, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_EQUAL_size_t(1, pub.frames.size());

    // Deliver frames to subscriber.
    const udpard_udpip_ep_t src_ep{ .ip = 0x7F000001, .port = 12345 };
    deliver_frames(pub.frames, &sub.rx, &sub_port, sub.mem, src_ep, now);

    // Verify transfer.
    TEST_ASSERT_EQUAL_size_t(1, sub.ctx.received_transfers.size());
    TEST_ASSERT_EQUAL_UINT64(transfer_id, sub.ctx.received_transfers[0].transfer_id);
    TEST_ASSERT_EQUAL_UINT64(publisher_uid, sub.ctx.received_transfers[0].remote_uid);
    TEST_ASSERT_EQUAL_size_t(payload.size(), sub.ctx.received_transfers[0].payload.size());
    TEST_ASSERT_EQUAL_MEMORY(payload.data(), sub.ctx.received_transfers[0].payload.data(), payload.size());

    // Cleanup.
    udpard_rx_port_free(&sub.rx, &sub_port);
    pub.fini();
    sub.fini();
}

/// Large multi-frame transfer end-to-end
void test_multi_frame_transfer()
{
    seed_prng();

    constexpr uint64_t publisher_uid = 0x5555666677778888ULL;
    constexpr size_t   payload_size  = 50000; // Large enough to require many frames

    // Set up publisher.
    TxFixture pub{};
    pub.init(publisher_uid, 200U, 512);

    // Set up subscriber.
    RxFixture sub{};
    sub.init();
    udpard_rx_port_t sub_port = make_subject_port(payload_size + 1024, sub);

    // Generate random payload.
    const std::vector<uint8_t>     payload      = make_payload(payload_size);
    const udpard_bytes_scattered_t payload_view = make_scattered(payload.data(), payload.size());

    const udpard_us_t now      = 1000000;
    const udpard_us_t deadline = now + 5000000;

    TEST_ASSERT_TRUE(udpard_tx_push(&pub.tx,
                                    now,
                                    deadline,
                                    1U, // iface_bitmap
                                    udpard_prio_nominal,
                                    100,
                                    payload_view,
                                    nullptr,
                                    UDPARD_USER_CONTEXT_NULL));

    udpard_tx_poll(&pub.tx, now, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_TRUE(pub.frames.size() > 1U);

    // Deliver frames to subscriber.
    const udpard_udpip_ep_t src_ep{ .ip = 0x7F000001, .port = 12345 };
    deliver_frames(pub.frames, &sub.rx, &sub_port, sub.mem, src_ep, now);

    // Verify full transfer.
    TEST_ASSERT_EQUAL_size_t(1, sub.ctx.received_transfers.size());
    TEST_ASSERT_EQUAL_size_t(payload_size, sub.ctx.received_transfers[0].payload.size());
    TEST_ASSERT_EQUAL_MEMORY(payload.data(), sub.ctx.received_transfers[0].payload.data(), payload_size);

    // Cleanup.
    udpard_rx_port_free(&sub.rx, &sub_port);
    pub.fini();
    sub.fini();
}

/// Multi-frame transfer with random reordering
void test_multi_frame_with_reordering()
{
    seed_prng();

    constexpr uint64_t publisher_uid = 0xABCDEF0123456789ULL;
    constexpr size_t   payload_size  = 20000;

    NetworkSimulator sim(0.0, true, static_cast<uint32_t>(rand())); // No loss, deterministic shuffle

    // Set up publisher.
    TxFixture pub{};
    pub.init(publisher_uid, 300U, 256);

    // Set up subscriber.
    RxFixture sub{};
    sub.init();
    udpard_rx_port_t sub_port = make_subject_port(payload_size + 1024, sub);

    // Generate random payload and send.
    const std::vector<uint8_t>     payload      = make_payload(payload_size);
    const udpard_bytes_scattered_t payload_view = make_scattered(payload.data(), payload.size());

    const udpard_us_t now = 1000000;
    TEST_ASSERT_TRUE(udpard_tx_push(&pub.tx,
                                    now,
                                    now + 5000000,
                                    1U, // iface_bitmap
                                    udpard_prio_nominal,
                                    50,
                                    payload_view,
                                    nullptr,
                                    UDPARD_USER_CONTEXT_NULL));

    udpard_tx_poll(&pub.tx, now, UDPARD_IFACE_BITMAP_ALL);

    // Deliver reordered frames.
    const udpard_udpip_ep_t src_ep{ .ip = 0x7F000001, .port = 12345 };
    deliver_frames(pub.frames, &sub.rx, &sub_port, sub.mem, src_ep, now, &sim);

    // Verify reordering recovery.
    TEST_ASSERT_EQUAL_size_t(1, sub.ctx.received_transfers.size());
    TEST_ASSERT_EQUAL_size_t(payload_size, sub.ctx.received_transfers[0].payload.size());
    TEST_ASSERT_EQUAL_MEMORY(payload.data(), sub.ctx.received_transfers[0].payload.data(), payload_size);
    TEST_ASSERT_TRUE((pub.frames.size() < 2U) || sim.reordered());

    // Cleanup.
    udpard_rx_port_free(&sub.rx, &sub_port);
    pub.fini();
    sub.fini();
}

/// Multiple publishers sending to single subscriber
void test_multiple_publishers()
{
    seed_prng();

    constexpr size_t num_publishers        = 3;
    constexpr size_t num_transfers_per_pub = 5;
    constexpr size_t payload_size          = 100;

    // Set up subscriber.
    RxFixture sub{};
    sub.init();
    udpard_rx_port_t sub_port = make_subject_port(1024, sub);

    // Set up publishers and send.
    std::array<TxFixture, num_publishers>                         publishers{};
    std::array<std::vector<std::vector<uint8_t>>, num_publishers> expected_payloads{};

    for (size_t i = 0; i < num_publishers; i++) {
        const uint64_t uid = 0x1000000000000000ULL + i;
        publishers[i].init(uid, static_cast<uint64_t>(rand()), 256);

        for (size_t tid = 0; tid < num_transfers_per_pub; tid++) {
            std::vector<uint8_t> payload = make_payload(payload_size);
            payload[0]                   = static_cast<uint8_t>(i);
            payload[1]                   = static_cast<uint8_t>(tid);
            expected_payloads[i].push_back(payload);

            const udpard_bytes_scattered_t payload_view = make_scattered(payload.data(), payload.size());
            const udpard_us_t              now =
              1000000LL + (static_cast<udpard_us_t>(i) * 10000LL) + (static_cast<udpard_us_t>(tid) * 100LL);
            const uint64_t transfer_id = (static_cast<uint64_t>(i) * 1000ULL) + static_cast<uint64_t>(tid);

            TEST_ASSERT_TRUE(udpard_tx_push(&publishers[i].tx,
                                            now,
                                            now + 1000000,
                                            1U, // iface_bitmap
                                            udpard_prio_nominal,
                                            transfer_id,
                                            payload_view,
                                            nullptr,
                                            UDPARD_USER_CONTEXT_NULL));

            udpard_tx_poll(&publishers[i].tx, now, UDPARD_IFACE_BITMAP_ALL);
        }
    }

    // Deliver all frames in publisher order.
    udpard_us_t now = 2000000;
    for (size_t pub = 0; pub < num_publishers; pub++) {
        const udpard_udpip_ep_t src_ep{ static_cast<uint32_t>(0x7F000001U + pub), static_cast<uint16_t>(12345U + pub) };
        deliver_frames(publishers[pub].frames, &sub.rx, &sub_port, sub.mem, src_ep, now);
        now += publishers[pub].frames.size();
    }

    // Verify every transfer and payload.
    const size_t expected_transfers = num_publishers * num_transfers_per_pub;
    TEST_ASSERT_EQUAL_size_t(expected_transfers, sub.ctx.received_transfers.size());
    for (size_t i = 0; i < num_publishers; i++) {
        const uint64_t uid = 0x1000000000000000ULL + i;
        for (size_t tid = 0; tid < num_transfers_per_pub; tid++) {
            const uint64_t transfer_id = (static_cast<uint64_t>(i) * 1000ULL) + static_cast<uint64_t>(tid);
            const auto     it          = std::find_if(
              sub.ctx.received_transfers.begin(), sub.ctx.received_transfers.end(), [=](const ReceivedTransfer& rt) {
                  return (rt.remote_uid == uid) && (rt.transfer_id == transfer_id);
              });
            TEST_ASSERT_TRUE(it != sub.ctx.received_transfers.end());
            TEST_ASSERT_EQUAL_size_t(payload_size, it->payload.size());
            TEST_ASSERT_EQUAL_MEMORY(expected_payloads[i][tid].data(), it->payload.data(), payload_size);
        }
    }

    // Cleanup.
    udpard_rx_port_free(&sub.rx, &sub_port);
    for (auto& pub : publishers) {
        pub.fini();
    }
    sub.fini();
}

/// Multi-frame transfer with simulated packet loss (all frames except one lost = incomplete transfer)
void test_partial_frame_loss()
{
    seed_prng();

    constexpr uint64_t publisher_uid = 0xDEADBEEFCAFEBABEULL;
    constexpr size_t   payload_size  = 5000; // Multi-frame transfer

    NetworkSimulator sim(0.35, false, static_cast<uint32_t>(rand())); // Ensure some loss

    // Set up publisher.
    TxFixture pub{};
    pub.init(publisher_uid, 300U, 256);

    // Set up subscriber.
    RxFixture sub{};
    sub.init();
    udpard_rx_port_t sub_port = make_subject_port(payload_size + 1024, sub);

    // Generate payload and send.
    const std::vector<uint8_t>     payload      = make_payload(payload_size);
    const udpard_bytes_scattered_t payload_view = make_scattered(payload.data(), payload.size());

    const udpard_us_t now = 1000000;
    TEST_ASSERT_TRUE(udpard_tx_push(&pub.tx,
                                    now,
                                    now + 5000000,
                                    1U, // iface_bitmap
                                    udpard_prio_nominal,
                                    50,
                                    payload_view,
                                    nullptr,
                                    UDPARD_USER_CONTEXT_NULL));

    udpard_tx_poll(&pub.tx, now, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_TRUE(pub.frames.size() > 1U);

    // Deliver with packet loss.
    const udpard_udpip_ep_t src_ep{ .ip = 0x7F000001, .port = 12345 };
    deliver_frames(pub.frames, &sub.rx, &sub_port, sub.mem, src_ep, now, &sim);

    // Verify incomplete transfer is dropped.
    TEST_ASSERT_TRUE(sim.dropped() > 0U);
    TEST_ASSERT_EQUAL_size_t(0, sub.ctx.received_transfers.size());

    // Cleanup.
    udpard_rx_port_free(&sub.rx, &sub_port);
    pub.fini();
    sub.fini();
}

/// Test with all frames delivered - no loss (baseline for loss tests)
void test_no_loss_baseline()
{
    seed_prng();

    constexpr uint64_t publisher_uid = 0xAAAABBBBCCCCDDDDULL;
    constexpr size_t   payload_size  = 10000;

    // Set up publisher.
    TxFixture pub{};
    pub.init(publisher_uid, 400U, 256);

    // Set up subscriber.
    RxFixture sub{};
    sub.init();
    udpard_rx_port_t sub_port = make_subject_port(payload_size + 1024, sub);

    // Generate payload and send.
    const std::vector<uint8_t>     payload      = make_payload(payload_size);
    const udpard_bytes_scattered_t payload_view = make_scattered(payload.data(), payload.size());

    const udpard_us_t now = 1000000;
    TEST_ASSERT_TRUE(udpard_tx_push(&pub.tx,
                                    now,
                                    now + 5000000,
                                    1U, // iface_bitmap
                                    udpard_prio_nominal,
                                    75,
                                    payload_view,
                                    nullptr,
                                    UDPARD_USER_CONTEXT_NULL));

    udpard_tx_poll(&pub.tx, now, UDPARD_IFACE_BITMAP_ALL);

    // Deliver all frames.
    const udpard_udpip_ep_t src_ep{ .ip = 0x7F000001, .port = 12345 };
    deliver_frames(pub.frames, &sub.rx, &sub_port, sub.mem, src_ep, now);

    // Verify success path.
    TEST_ASSERT_EQUAL_size_t(1, sub.ctx.received_transfers.size());
    TEST_ASSERT_EQUAL_size_t(payload_size, sub.ctx.received_transfers[0].payload.size());
    TEST_ASSERT_EQUAL_MEMORY(payload.data(), sub.ctx.received_transfers[0].payload.data(), payload_size);

    // Cleanup.
    udpard_rx_port_free(&sub.rx, &sub_port);
    pub.fini();
    sub.fini();
}

/// Test with extent-based truncation
void test_extent_truncation()
{
    seed_prng();

    constexpr uint64_t publisher_uid = 0x1234567890ABCDEFULL;
    constexpr size_t   payload_size  = 5000;
    constexpr size_t   extent        = 1000; // Less than payload_size

    // Set up publisher.
    TxFixture pub{};
    pub.init(publisher_uid, 500U, 256);

    // Set up subscriber with limited extent.
    RxFixture sub{};
    sub.init();
    udpard_rx_port_t sub_port = make_subject_port(extent, sub);

    // Generate payload and send.
    const std::vector<uint8_t>     payload      = make_payload(payload_size);
    const udpard_bytes_scattered_t payload_view = make_scattered(payload.data(), payload.size());

    const udpard_us_t now = 1000000;
    TEST_ASSERT_TRUE(udpard_tx_push(&pub.tx,
                                    now,
                                    now + 5000000,
                                    1U, // iface_bitmap
                                    udpard_prio_nominal,
                                    100,
                                    payload_view,
                                    nullptr,
                                    UDPARD_USER_CONTEXT_NULL));

    udpard_tx_poll(&pub.tx, now, UDPARD_IFACE_BITMAP_ALL);

    // Deliver all frames.
    const udpard_udpip_ep_t src_ep{ .ip = 0x7F000001, .port = 12345 };
    deliver_frames(pub.frames, &sub.rx, &sub_port, sub.mem, src_ep, now);

    // Verify truncation.
    TEST_ASSERT_EQUAL_size_t(1, sub.ctx.received_transfers.size());
    TEST_ASSERT_TRUE(sub.ctx.received_transfers[0].payload.size() <= extent + UDPARD_MTU_DEFAULT);
    TEST_ASSERT_EQUAL_size_t(payload_size, sub.ctx.received_transfers[0].payload_size_wire);
    TEST_ASSERT_EQUAL_MEMORY(
      payload.data(), sub.ctx.received_transfers[0].payload.data(), sub.ctx.received_transfers[0].payload.size());

    // Cleanup.
    udpard_rx_port_free(&sub.rx, &sub_port);
    pub.fini();
    sub.fini();
}

} // namespace

extern "C" void setUp() {}
extern "C" void tearDown() {}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_single_frame_transfer);
    RUN_TEST(test_multi_frame_transfer);
    RUN_TEST(test_multi_frame_with_reordering);
    RUN_TEST(test_multiple_publishers);
    RUN_TEST(test_partial_frame_loss);
    RUN_TEST(test_no_loss_baseline);
    RUN_TEST(test_extent_truncation);
    return UNITY_END();
}
