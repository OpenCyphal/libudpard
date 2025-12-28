/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

// ReSharper disable CppPassValueParameterByConstReference

#include <udpard.h>
#include "helpers.h"
#include <unity.h>
#include <array>
#include <vector>

namespace {

void                              on_message(udpard_rx_t* rx, udpard_rx_port_t* port, udpard_rx_transfer_t transfer);
void                              on_collision(udpard_rx_t* rx, udpard_rx_port_t* port, udpard_remote_t remote);
constexpr udpard_rx_port_vtable_t callbacks{ .on_message = &on_message, .on_collision = &on_collision };
void on_message_p2p(udpard_rx_t* rx, udpard_rx_port_p2p_t* port, udpard_rx_transfer_p2p_t transfer);
constexpr udpard_rx_port_p2p_vtable_t p2p_callbacks{ &on_message_p2p };

struct FbState
{
    size_t   count   = 0;
    bool     success = false;
    uint64_t tid     = 0;
};

struct CapturedFrame
{
    udpard_bytes_mut_t datagram;
    uint_fast8_t       iface_index;
};

void tx_refcount_free(void* const user, const size_t size, void* const payload)
{
    (void)user;
    udpard_tx_refcount_dec(udpard_bytes_t{ .size = size, .data = payload });
}

bool capture_tx_frame(udpard_tx_t* const tx, const udpard_tx_ejection_t ejection)
{
    auto* frames = static_cast<std::vector<CapturedFrame>*>(tx->user);
    if (frames == nullptr) {
        return false;
    }
    udpard_tx_refcount_inc(ejection.datagram);
    void* const data = const_cast<void*>(ejection.datagram.data); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    frames->push_back(CapturedFrame{ .datagram    = { .size = ejection.datagram.size, .data = data },
                                     .iface_index = ejection.iface_index });
    return true;
}

constexpr udpard_tx_vtable_t tx_vtable{ .eject = &capture_tx_frame };

void fb_record(udpard_tx_t*, const udpard_tx_feedback_t fb)
{
    auto* st = static_cast<FbState*>(fb.user_transfer_reference);
    if (st != nullptr) {
        st->count++;
        st->success = fb.success;
        st->tid     = fb.transfer_id;
    }
}

void release_frames(std::vector<CapturedFrame>& frames)
{
    for (const auto& [datagram, iface_index] : frames) {
        udpard_tx_refcount_dec(udpard_bytes_t{ .size = datagram.size, .data = datagram.data });
    }
    frames.clear();
}

struct Context
{
    std::vector<uint64_t> ids;
    size_t                collisions     = 0;
    uint64_t              expected_uid   = 0;
    uint64_t              expected_topic = 0;
    udpard_udpip_ep_t     source{};
};

struct Fixture
{
    instrumented_allocator_t   tx_alloc_transfer{};
    instrumented_allocator_t   tx_alloc_payload{};
    instrumented_allocator_t   rx_alloc_frag{};
    instrumented_allocator_t   rx_alloc_session{};
    udpard_tx_t                tx{};
    udpard_rx_t                rx{};
    udpard_rx_port_t           port{};
    udpard_mem_deleter_t       tx_payload_deleter{};
    std::vector<CapturedFrame> frames;
    Context                    ctx{};
    udpard_udpip_ep_t          dest{};
    udpard_udpip_ep_t          source{};
    uint64_t                   topic_hash{ 0x90AB12CD34EF5678ULL };

    Fixture(const Fixture&)            = delete;
    Fixture& operator=(const Fixture&) = delete;
    Fixture(Fixture&&)                 = delete;
    Fixture& operator=(Fixture&&)      = delete;

    explicit Fixture(const udpard_us_t reordering_window)
    {
        instrumented_allocator_new(&tx_alloc_transfer);
        instrumented_allocator_new(&tx_alloc_payload);
        instrumented_allocator_new(&rx_alloc_frag);
        instrumented_allocator_new(&rx_alloc_session);
        udpard_tx_mem_resources_t tx_mem{};
        tx_mem.transfer = instrumented_allocator_make_resource(&tx_alloc_transfer);
        for (auto& res : tx_mem.payload) {
            res = instrumented_allocator_make_resource(&tx_alloc_payload);
        }
        const udpard_rx_mem_resources_t rx_mem{ .session  = instrumented_allocator_make_resource(&rx_alloc_session),
                                                .fragment = instrumented_allocator_make_resource(&rx_alloc_frag) };
        tx_payload_deleter = udpard_mem_deleter_t{ .user = nullptr, .free = &tx_refcount_free };
        source             = { .ip = 0x0A000001U, .port = 7501U };
        dest               = udpard_make_subject_endpoint(222U);

        TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x0A0B0C0D0E0F1011ULL, 42U, 16, tx_mem, &tx_vtable));
        tx.user = &frames;
        udpard_rx_new(&rx, nullptr);
        ctx.expected_uid = tx.local_uid;
        ctx.source       = source;
        rx.user          = &ctx;
        TEST_ASSERT_TRUE(udpard_rx_port_new(&port, topic_hash, 1024, reordering_window, rx_mem, &callbacks));
    }

    ~Fixture()
    {
        udpard_rx_port_free(&rx, &port);
        udpard_tx_free(&tx);
        TEST_ASSERT_EQUAL_size_t(0, rx_alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, rx_alloc_session.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, tx_alloc_transfer.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, tx_alloc_payload.allocated_fragments);
        instrumented_allocator_reset(&rx_alloc_frag);
        instrumented_allocator_reset(&rx_alloc_session);
        instrumented_allocator_reset(&tx_alloc_transfer);
        instrumented_allocator_reset(&tx_alloc_payload);
    }

    void push_single(const udpard_us_t ts, const uint64_t transfer_id)
    {
        frames.clear();
        std::array<uint8_t, 8> payload_buf{};
        for (size_t i = 0; i < payload_buf.size(); i++) {
            payload_buf[i] = static_cast<uint8_t>(transfer_id >> (i * 8U));
        }
        const udpard_bytes_scattered_t payload  = make_scattered(payload_buf.data(), payload_buf.size());
        const udpard_us_t              deadline = ts + 1000000;
        for (auto& mtu_value : tx.mtu) {
            mtu_value = UDPARD_MTU_DEFAULT;
        }
        std::array<udpard_udpip_ep_t, UDPARD_IFACE_COUNT_MAX> dest_per_iface{};
        dest_per_iface.fill(udpard_udpip_ep_t{});
        dest_per_iface[0] = dest;
        TEST_ASSERT_GREATER_THAN_UINT32(0U,
                                        udpard_tx_push(&tx,
                                                       ts,
                                                       deadline,
                                                       udpard_prio_slow,
                                                       topic_hash,
                                                       dest_per_iface.data(),
                                                       transfer_id,
                                                       payload,
                                                       nullptr,
                                                       nullptr));
        udpard_tx_poll(&tx, ts, UDPARD_IFACE_MASK_ALL);
        TEST_ASSERT_GREATER_THAN_UINT32(0U, static_cast<uint32_t>(frames.size()));
        for (const auto& [datagram, iface_index] : frames) {
            TEST_ASSERT_TRUE(udpard_rx_port_push(&rx, &port, ts, source, datagram, tx_payload_deleter, iface_index));
        }
    }
};

/// Callbacks keep the payload memory under control.
void on_message(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    auto* const ctx = static_cast<Context*>(rx->user);
    ctx->ids.push_back(transfer.transfer_id);
    TEST_ASSERT_EQUAL_UINT64(ctx->expected_uid, transfer.remote.uid);
    TEST_ASSERT_EQUAL_UINT32(ctx->source.ip, transfer.remote.endpoints[0].ip);
    TEST_ASSERT_EQUAL_UINT16(ctx->source.port, transfer.remote.endpoints[0].port);
    udpard_fragment_free_all(transfer.payload, port->memory.fragment);
}

void on_collision(udpard_rx_t* const rx, udpard_rx_port_t* const /*port*/, const udpard_remote_t /*remote*/)
{
    auto* const ctx = static_cast<Context*>(rx->user);
    ctx->collisions++;
}

void on_message_p2p(udpard_rx_t* const rx, udpard_rx_port_p2p_t* const port, const udpard_rx_transfer_p2p_t transfer)
{
    auto* const ctx = static_cast<Context*>(rx->user);
    ctx->ids.push_back(transfer.base.transfer_id);
    if (ctx->expected_topic != 0) {
        TEST_ASSERT_EQUAL_UINT64(ctx->expected_topic, transfer.topic_hash);
    }
    TEST_ASSERT_EQUAL_UINT64(ctx->expected_uid, transfer.base.remote.uid);
    TEST_ASSERT_EQUAL_UINT32(ctx->source.ip, transfer.base.remote.endpoints[0].ip);
    TEST_ASSERT_EQUAL_UINT16(ctx->source.port, transfer.base.remote.endpoints[0].port);
    udpard_fragment_free_all(transfer.base.payload, port->base.memory.fragment);
}

/// UNORDERED mode should drop duplicates while keeping arrival order.
void test_udpard_rx_unordered_duplicates()
{
    Fixture     fix{ UDPARD_RX_REORDERING_WINDOW_UNORDERED };
    udpard_us_t now = 0;

    constexpr std::array<uint64_t, 6> ids{ 100, 20000, 10100, 5000, 20000, 100 };
    for (const auto id : ids) {
        fix.push_single(now, id);
        udpard_rx_poll(&fix.rx, now);
        now++;
    }
    udpard_rx_poll(&fix.rx, now + 100);

    constexpr std::array<uint64_t, 4> expected{ 100, 20000, 10100, 5000 };
    TEST_ASSERT_EQUAL_size_t(expected.size(), fix.ctx.ids.size());
    for (size_t i = 0; i < expected.size(); i++) {
        TEST_ASSERT_EQUAL_UINT64(expected[i], fix.ctx.ids[i]);
    }
    TEST_ASSERT_EQUAL_size_t(0, fix.ctx.collisions);
}

/// ORDERED mode waits for the window, then rejects late arrivals.
void test_udpard_rx_ordered_out_of_order()
{
    Fixture     fix{ 50 };
    udpard_us_t now = 0;

    // First batch builds the ordered baseline.
    fix.push_single(now, 100);
    udpard_rx_poll(&fix.rx, now);
    fix.push_single(++now, 300);
    udpard_rx_poll(&fix.rx, now);
    fix.push_single(++now, 200);
    udpard_rx_poll(&fix.rx, now);

    // Let the reordering window close for the early transfers.
    now = 60;
    udpard_rx_poll(&fix.rx, now);

    // Queue far-future IDs while keeping the head at 300.
    fix.push_single(now + 1, 10100);
    udpard_rx_poll(&fix.rx, now + 1);
    fix.push_single(now + 2, 10200);
    udpard_rx_poll(&fix.rx, now + 2);

    // Late arrivals inside the window shall be dropped.
    fix.push_single(now + 3, 250);
    udpard_rx_poll(&fix.rx, now + 3);
    fix.push_single(now + 4, 150);
    udpard_rx_poll(&fix.rx, now + 4);

    // Allow the window to expire so the remaining interned transfers eject.
    udpard_rx_poll(&fix.rx, now + 70);

    constexpr std::array<uint64_t, 5> expected{ 100, 200, 300, 10100, 10200 };
    TEST_ASSERT_EQUAL_size_t(expected.size(), fix.ctx.ids.size());
    for (size_t i = 0; i < expected.size(); i++) {
        TEST_ASSERT_EQUAL_UINT64(expected[i], fix.ctx.ids[i]);
    }
    TEST_ASSERT_EQUAL_size_t(0, fix.ctx.collisions);
}

/// ORDERED mode after head advance should reject late IDs arriving after window expiry.
void test_udpard_rx_ordered_head_advanced_late()
{
    Fixture     fix{ 50 };
    udpard_us_t now = 0;

    fix.push_single(now, 100);
    udpard_rx_poll(&fix.rx, now);
    fix.push_single(++now, 300);
    udpard_rx_poll(&fix.rx, now);
    fix.push_single(++now, 200);
    udpard_rx_poll(&fix.rx, now);
    now = 60;
    udpard_rx_poll(&fix.rx, now); // head -> 300

    fix.push_single(++now, 420);
    udpard_rx_poll(&fix.rx, now);
    fix.push_single(++now, 450);
    udpard_rx_poll(&fix.rx, now);
    now = 120;
    udpard_rx_poll(&fix.rx, now); // head -> 450

    fix.push_single(++now, 320);
    udpard_rx_poll(&fix.rx, now);
    fix.push_single(++now, 310);
    udpard_rx_poll(&fix.rx, now);

    constexpr std::array<uint64_t, 5> expected{ 100, 200, 300, 420, 450 };
    TEST_ASSERT_EQUAL_size_t(expected.size(), fix.ctx.ids.size());
    for (size_t i = 0; i < expected.size(); i++) {
        TEST_ASSERT_EQUAL_UINT64(expected[i], fix.ctx.ids[i]);
    }
    TEST_ASSERT_EQUAL_size_t(0, fix.ctx.collisions);
}

// Feedback must fire regardless of disposal path.
void test_udpard_tx_feedback_always_called()
{
    instrumented_allocator_t tx_alloc_transfer{};
    instrumented_allocator_t tx_alloc_payload{};
    instrumented_allocator_new(&tx_alloc_transfer);
    instrumented_allocator_new(&tx_alloc_payload);
    udpard_tx_mem_resources_t tx_mem{};
    tx_mem.transfer = instrumented_allocator_make_resource(&tx_alloc_transfer);
    for (auto& res : tx_mem.payload) {
        res = instrumented_allocator_make_resource(&tx_alloc_payload);
    }
    const udpard_udpip_ep_t endpoint = udpard_make_subject_endpoint(1);

    // Expiration path triggers feedback=false.
    {
        std::vector<CapturedFrame> frames;
        udpard_tx_t                tx{};
        TEST_ASSERT_TRUE(udpard_tx_new(&tx, 1U, 1U, 4, tx_mem, &tx_vtable));
        tx.user = &frames;
        FbState           fb{};
        udpard_udpip_ep_t dests[UDPARD_IFACE_COUNT_MAX] = { endpoint, {} };
        TEST_ASSERT_GREATER_THAN_UINT32(
          0, udpard_tx_push(&tx, 10, 10, udpard_prio_fast, 1, dests, 11, make_scattered(nullptr, 0), fb_record, &fb));
        udpard_tx_poll(&tx, 11, UDPARD_IFACE_MASK_ALL);
        TEST_ASSERT_EQUAL_size_t(1, fb.count);
        TEST_ASSERT_FALSE(fb.success);
        release_frames(frames);
        udpard_tx_free(&tx);
    }

    // Sacrifice path should also emit feedback.
    {
        std::vector<CapturedFrame> frames;
        udpard_tx_t                tx{};
        TEST_ASSERT_TRUE(udpard_tx_new(&tx, 2U, 1U, 1, tx_mem, &tx_vtable));
        tx.user = &frames;
        FbState           fb_old{};
        FbState           fb_new{};
        udpard_udpip_ep_t dests[UDPARD_IFACE_COUNT_MAX] = { endpoint, {} };
        TEST_ASSERT_GREATER_THAN_UINT32(
          0,
          udpard_tx_push(&tx, 0, 1000, udpard_prio_fast, 2, dests, 21, make_scattered(nullptr, 0), fb_record, &fb_old));
        (void)udpard_tx_push(
          &tx, 0, 1000, udpard_prio_fast, 3, dests, 22, make_scattered(nullptr, 0), fb_record, &fb_new);
        TEST_ASSERT_EQUAL_size_t(1, fb_old.count);
        TEST_ASSERT_FALSE(fb_old.success);
        TEST_ASSERT_GREATER_OR_EQUAL_UINT64(1, tx.errors_sacrifice);
        TEST_ASSERT_EQUAL_size_t(0, fb_new.count);
        release_frames(frames);
        udpard_tx_free(&tx);
    }

    // Destroying a TX with pending transfers still calls feedback.
    {
        std::vector<CapturedFrame> frames;
        udpard_tx_t                tx{};
        TEST_ASSERT_TRUE(udpard_tx_new(&tx, 3U, 1U, 4, tx_mem, &tx_vtable));
        tx.user = &frames;
        FbState           fb{};
        udpard_udpip_ep_t dests[UDPARD_IFACE_COUNT_MAX] = { endpoint, {} };
        TEST_ASSERT_GREATER_THAN_UINT32(
          0, udpard_tx_push(&tx, 0, 1000, udpard_prio_fast, 4, dests, 33, make_scattered(nullptr, 0), fb_record, &fb));
        udpard_tx_free(&tx);
        TEST_ASSERT_EQUAL_size_t(1, fb.count);
        TEST_ASSERT_FALSE(fb.success);
        release_frames(frames);
    }

    instrumented_allocator_reset(&tx_alloc_transfer);
    instrumented_allocator_reset(&tx_alloc_payload);
}

/// P2P helper should emit frames with auto transfer-ID and proper addressing.
void test_udpard_tx_push_p2p()
{
    instrumented_allocator_t tx_alloc_transfer{};
    instrumented_allocator_t tx_alloc_payload{};
    instrumented_allocator_t rx_alloc_frag{};
    instrumented_allocator_t rx_alloc_session{};
    instrumented_allocator_new(&tx_alloc_transfer);
    instrumented_allocator_new(&tx_alloc_payload);
    instrumented_allocator_new(&rx_alloc_frag);
    instrumented_allocator_new(&rx_alloc_session);
    udpard_tx_mem_resources_t tx_mem{};
    tx_mem.transfer = instrumented_allocator_make_resource(&tx_alloc_transfer);
    for (auto& res : tx_mem.payload) {
        res = instrumented_allocator_make_resource(&tx_alloc_payload);
    }
    udpard_tx_t tx{};
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x1122334455667788ULL, 5U, 8, tx_mem, &tx_vtable));
    std::vector<CapturedFrame> frames;
    tx.user = &frames;

    const udpard_rx_mem_resources_t rx_mem{ .session  = instrumented_allocator_make_resource(&rx_alloc_session),
                                            .fragment = instrumented_allocator_make_resource(&rx_alloc_frag) };
    udpard_rx_t                     rx{};
    udpard_rx_port_p2p_t            port{};
    Context                         ctx{};
    const udpard_udpip_ep_t         source{ .ip = 0x0A0000AAU, .port = 7600U };
    const udpard_udpip_ep_t         dest{ .ip = 0x0A000010U, .port = 7400U };
    const uint64_t                  local_uid  = 0xCAFEBABECAFED00DULL;
    const uint64_t                  topic_hash = 0xAABBCCDDEEFF1122ULL;
    ctx.expected_uid                           = tx.local_uid;
    ctx.expected_topic                         = topic_hash;
    ctx.source                                 = source;
    rx.user                                    = &ctx;
    TEST_ASSERT_TRUE(udpard_rx_port_new_p2p(&port, local_uid, 1024, rx_mem, &p2p_callbacks));

    udpard_remote_t remote{};
    remote.uid           = local_uid;
    remote.endpoints[0U] = dest;

    const uint64_t                 request_transfer_id = 55;
    const std::array<uint8_t, 3>   user_payload{ 0xAAU, 0xBBU, 0xCCU };
    const udpard_bytes_scattered_t payload = make_scattered(user_payload.data(), user_payload.size());
    const udpard_us_t              now     = 0;
    TEST_ASSERT_GREATER_THAN_UINT32(0U,
                                    udpard_tx_push_p2p(&tx,
                                                       now,
                                                       now + 1000000,
                                                       udpard_prio_nominal,
                                                       topic_hash,
                                                       request_transfer_id,
                                                       remote,
                                                       payload,
                                                       nullptr,
                                                       nullptr));
    udpard_tx_poll(&tx, now, UDPARD_IFACE_MASK_ALL);
    TEST_ASSERT_FALSE(frames.empty());

    const udpard_mem_deleter_t tx_payload_deleter{ .user = nullptr, .free = &tx_refcount_free };
    for (const auto& f : frames) {
        TEST_ASSERT_TRUE(udpard_rx_port_push(
          &rx, reinterpret_cast<udpard_rx_port_t*>(&port), now, source, f.datagram, tx_payload_deleter, f.iface_index));
    }
    udpard_rx_poll(&rx, now);
    TEST_ASSERT_EQUAL_size_t(1, ctx.ids.size());
    TEST_ASSERT_EQUAL_UINT64(request_transfer_id, ctx.ids[0]);
    TEST_ASSERT_EQUAL_size_t(0, ctx.collisions);

    udpard_rx_port_free(&rx, reinterpret_cast<udpard_rx_port_t*>(&port));
    udpard_tx_free(&tx);
    TEST_ASSERT_EQUAL(0, tx_alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL(0, tx_alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, rx_alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(0, rx_alloc_session.allocated_fragments);
    instrumented_allocator_reset(&tx_alloc_transfer);
    instrumented_allocator_reset(&tx_alloc_payload);
    instrumented_allocator_reset(&rx_alloc_frag);
    instrumented_allocator_reset(&rx_alloc_session);
}

/// P2P messages with invalid kind byte should be silently dropped.
/// This tests the malformed branch in rx_p2p_on_message.
void test_udpard_rx_p2p_malformed_kind()
{
    instrumented_allocator_t tx_alloc_transfer{};
    instrumented_allocator_t tx_alloc_payload{};
    instrumented_allocator_t rx_alloc_frag{};
    instrumented_allocator_t rx_alloc_session{};
    instrumented_allocator_new(&tx_alloc_transfer);
    instrumented_allocator_new(&tx_alloc_payload);
    instrumented_allocator_new(&rx_alloc_frag);
    instrumented_allocator_new(&rx_alloc_session);

    udpard_tx_mem_resources_t tx_mem{};
    tx_mem.transfer = instrumented_allocator_make_resource(&tx_alloc_transfer);
    for (auto& res : tx_mem.payload) {
        res = instrumented_allocator_make_resource(&tx_alloc_payload);
    }
    udpard_tx_t tx{};
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x1122334455667788ULL, 5U, 8, tx_mem, &tx_vtable));
    std::vector<CapturedFrame> frames;
    tx.user = &frames;

    const udpard_rx_mem_resources_t rx_mem{ .session  = instrumented_allocator_make_resource(&rx_alloc_session),
                                            .fragment = instrumented_allocator_make_resource(&rx_alloc_frag) };
    udpard_rx_t                     rx{};
    udpard_rx_port_p2p_t            port{};
    Context                         ctx{};
    const udpard_udpip_ep_t         source{ .ip = 0x0A0000BBU, .port = 7700U };
    const uint64_t                  local_uid = 0xDEADBEEFCAFEBABEULL;
    ctx.expected_uid                          = tx.local_uid;
    ctx.source                                = source;
    udpard_rx_new(&rx, nullptr);
    rx.user = &ctx;
    TEST_ASSERT_TRUE(udpard_rx_port_new_p2p(&port, local_uid, 1024, rx_mem, &p2p_callbacks));

    // Construct a P2P payload with an invalid kind byte.
    // P2P header format: kind (1 byte) + reserved (7 bytes) + topic_hash (8 bytes) + transfer_id (8 bytes) = 24 bytes
    // Valid kinds are 0 (P2P_KIND_RESPONSE) and 1 (P2P_KIND_ACK). Use 0xFF as invalid.
    std::array<uint8_t, UDPARD_P2P_HEADER_BYTES + 4> p2p_payload{};
    p2p_payload[0] = 0xFFU; // Invalid kind
    // Rest of P2P header (reserved, topic_hash, transfer_id) can be zeros - doesn't matter for this test.
    // Add some user payload bytes.
    p2p_payload[UDPARD_P2P_HEADER_BYTES + 0] = 0x11U;
    p2p_payload[UDPARD_P2P_HEADER_BYTES + 1] = 0x22U;
    p2p_payload[UDPARD_P2P_HEADER_BYTES + 2] = 0x33U;
    p2p_payload[UDPARD_P2P_HEADER_BYTES + 3] = 0x44U;

    // Send using regular udpard_tx_push - the library handles all CRC calculations.
    const udpard_us_t              now     = 0;
    const udpard_bytes_scattered_t payload = make_scattered(p2p_payload.data(), p2p_payload.size());
    std::array<udpard_udpip_ep_t, UDPARD_IFACE_COUNT_MAX> dest{};
    dest[0] = { .ip = 0x0A000010U, .port = 7400U };
    TEST_ASSERT_GREATER_THAN_UINT32(0U,
                                    udpard_tx_push(&tx,
                                                   now,
                                                   now + 1000000,
                                                   udpard_prio_nominal,
                                                   local_uid, // topic_hash = local_uid for P2P port matching
                                                   dest.data(),
                                                   42U,
                                                   payload,
                                                   nullptr,
                                                   nullptr));
    udpard_tx_poll(&tx, now, UDPARD_IFACE_MASK_ALL);
    TEST_ASSERT_FALSE(frames.empty());

    // Push the frame to RX P2P port.
    TEST_ASSERT_EQUAL_UINT64(0, rx.errors_transfer_malformed);
    const udpard_mem_deleter_t tx_payload_deleter{ .user = nullptr, .free = &tx_refcount_free };
    for (const auto& f : frames) {
        TEST_ASSERT_TRUE(udpard_rx_port_push(
          &rx, reinterpret_cast<udpard_rx_port_t*>(&port), now, source, f.datagram, tx_payload_deleter, f.iface_index));
    }
    udpard_rx_poll(&rx, now);

    // The malformed message should be dropped - no callback invoked, error counter incremented.
    TEST_ASSERT_EQUAL_size_t(0, ctx.ids.size());
    TEST_ASSERT_EQUAL_size_t(0, ctx.collisions);
    TEST_ASSERT_EQUAL_UINT64(1, rx.errors_transfer_malformed);

    // Cleanup - verify no memory leaks.
    udpard_rx_port_free(&rx, reinterpret_cast<udpard_rx_port_t*>(&port));
    udpard_tx_free(&tx);
    TEST_ASSERT_EQUAL(0, tx_alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL(0, tx_alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(0, rx_alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(0, rx_alloc_session.allocated_fragments);
    instrumented_allocator_reset(&tx_alloc_transfer);
    instrumented_allocator_reset(&tx_alloc_payload);
    instrumented_allocator_reset(&rx_alloc_frag);
    instrumented_allocator_reset(&rx_alloc_session);
}

} // namespace

extern "C" void setUp() {}

extern "C" void tearDown() {}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_udpard_rx_unordered_duplicates);
    RUN_TEST(test_udpard_rx_ordered_out_of_order);
    RUN_TEST(test_udpard_rx_ordered_head_advanced_late);
    RUN_TEST(test_udpard_tx_feedback_always_called);
    RUN_TEST(test_udpard_tx_push_p2p);
    RUN_TEST(test_udpard_rx_p2p_malformed_kind);
    return UNITY_END();
}
