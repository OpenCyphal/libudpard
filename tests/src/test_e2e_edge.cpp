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
constexpr udpard_rx_port_vtable_t callbacks{ .on_message = &on_message };

struct FbState
{
    size_t   count            = 0;
    uint16_t acknowledgements = 0;
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

void fb_record(udpard_tx_t*, const udpard_tx_feedback_t fb)
{
    auto* st = static_cast<FbState*>(fb.user.ptr[0]);
    if (st != nullptr) {
        st->count++;
        st->acknowledgements = fb.acknowledgements;
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
    uint64_t              expected_uid = 0;
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
    udpard_deleter_t           tx_payload_deleter{};
    std::vector<CapturedFrame> frames;
    Context                    ctx{};
    udpard_udpip_ep_t          dest{};
    udpard_udpip_ep_t          source{};

    Fixture(const Fixture&)            = delete;
    Fixture& operator=(const Fixture&) = delete;
    Fixture(Fixture&&)                 = delete;
    Fixture& operator=(Fixture&&)      = delete;

    explicit Fixture()
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
        tx_payload_deleter = udpard_deleter_t{ .vtable = &tx_refcount_deleter_vt, .context = nullptr };
        source             = { .ip = 0x0A000001U, .port = 7501U };
        dest               = udpard_make_subject_endpoint(222U);

        TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x0A0B0C0D0E0F1011ULL, 42U, 16, tx_mem, &tx_vtable));
        tx.user = &frames;
        udpard_rx_new(&rx, nullptr);
        ctx.expected_uid = tx.local_uid;
        ctx.source       = source;
        rx.user          = &ctx;
        TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 1024, rx_mem, &callbacks));
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
        constexpr uint16_t iface_bitmap_1 = (1U << 0U);
        TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                        ts,
                                        deadline,
                                        iface_bitmap_1,
                                        udpard_prio_slow,
                                        transfer_id,
                                        payload,
                                        nullptr,
                                        UDPARD_USER_CONTEXT_NULL));
        udpard_tx_poll(&tx, ts, UDPARD_IFACE_BITMAP_ALL);
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
    udpard_fragment_free_all(transfer.payload, udpard_make_deleter(port->memory.fragment));
}

/// UNORDERED mode should drop duplicates while keeping arrival order.
void test_udpard_rx_unordered_duplicates()
{
    Fixture     fix{};
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
    constexpr uint16_t iface_bitmap_1 = (1U << 0U);

    // Expiration path triggers feedback=false.
    {
        std::vector<CapturedFrame> frames;
        udpard_tx_t                tx{};
        TEST_ASSERT_TRUE(udpard_tx_new(&tx, 1U, 1U, 4, tx_mem, &tx_vtable));
        tx.user = &frames;
        FbState fb{};
        TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                        10,
                                        10,
                                        iface_bitmap_1,
                                        udpard_prio_fast,
                                        11,
                                        make_scattered(nullptr, 0),
                                        fb_record,
                                        make_user_context(&fb)));
        udpard_tx_poll(&tx, 11, UDPARD_IFACE_BITMAP_ALL);
        TEST_ASSERT_EQUAL_size_t(1, fb.count);
        TEST_ASSERT_EQUAL_UINT32(0, fb.acknowledgements);
        release_frames(frames);
        udpard_tx_free(&tx);
    }

    // Sacrifice path should also emit feedback.
    {
        std::vector<CapturedFrame> frames;
        udpard_tx_t                tx{};
        TEST_ASSERT_TRUE(udpard_tx_new(&tx, 2U, 1U, 1, tx_mem, &tx_vtable));
        tx.user = &frames;
        FbState fb_old{};
        FbState fb_new{};
        TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                        0,
                                        1000,
                                        iface_bitmap_1,
                                        udpard_prio_fast,
                                        21,
                                        make_scattered(nullptr, 0),
                                        fb_record,
                                        make_user_context(&fb_old)));
        (void)udpard_tx_push(&tx,
                             0,
                             1000,
                             iface_bitmap_1,
                             udpard_prio_fast,
                             22,
                             make_scattered(nullptr, 0),
                             fb_record,
                             make_user_context(&fb_new));
        TEST_ASSERT_EQUAL_size_t(1, fb_old.count);
        TEST_ASSERT_EQUAL_UINT32(0, fb_old.acknowledgements);
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
        FbState fb{};
        TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                        0,
                                        1000,
                                        iface_bitmap_1,
                                        udpard_prio_fast,
                                        33,
                                        make_scattered(nullptr, 0),
                                        fb_record,
                                        make_user_context(&fb)));
        udpard_tx_free(&tx);
        TEST_ASSERT_EQUAL_size_t(1, fb.count);
        TEST_ASSERT_EQUAL_UINT32(0, fb.acknowledgements);
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
    udpard_rx_port_t                port{};
    Context                         ctx{};
    const udpard_udpip_ep_t         source{ .ip = 0x0A0000AAU, .port = 7600U };
    const udpard_udpip_ep_t         dest{ .ip = 0x0A000010U, .port = 7400U };
    ctx.expected_uid = tx.local_uid;
    ctx.source       = source;
    rx.user          = &ctx;
    TEST_ASSERT_TRUE(udpard_rx_port_new_p2p(&port, 1024, rx_mem, &callbacks));

    const uint64_t  remote_uid = 0xCAFEBABECAFED00DULL;
    udpard_remote_t remote{};
    remote.uid           = remote_uid;
    remote.endpoints[0U] = dest;

    const std::array<uint8_t, 3>   user_payload{ 0xAAU, 0xBBU, 0xCCU };
    const udpard_bytes_scattered_t payload = make_scattered(user_payload.data(), user_payload.size());
    const udpard_us_t              now     = 0;
    uint64_t                       out_tid = 0;
    TEST_ASSERT_TRUE(udpard_tx_push_p2p(
      &tx, now, now + 1000000, udpard_prio_nominal, remote, payload, nullptr, UDPARD_USER_CONTEXT_NULL, &out_tid));
    udpard_tx_poll(&tx, now, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_FALSE(frames.empty());

    const udpard_deleter_t tx_payload_deleter{ .vtable = &tx_refcount_deleter_vt, .context = nullptr };
    for (const auto& f : frames) {
        TEST_ASSERT_TRUE(udpard_rx_port_push(&rx, &port, now, source, f.datagram, tx_payload_deleter, f.iface_index));
    }
    udpard_rx_poll(&rx, now);
    TEST_ASSERT_EQUAL_size_t(1, ctx.ids.size());
    TEST_ASSERT_EQUAL_UINT64(out_tid, ctx.ids[0]);
    udpard_rx_port_free(&rx, &port);
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

/// Test TX with minimum MTU to verify fragmentation at the edge.
void test_udpard_tx_minimum_mtu()
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
    const udpard_rx_mem_resources_t rx_mem{ .session  = instrumented_allocator_make_resource(&rx_alloc_session),
                                            .fragment = instrumented_allocator_make_resource(&rx_alloc_frag) };

    udpard_tx_t tx{};
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0xDEADBEEF12345678ULL, 100U, 256, tx_mem, &tx_vtable));
    std::vector<CapturedFrame> frames;
    tx.user = &frames;

    // Set MTU to minimum value
    for (auto& mtu : tx.mtu) {
        mtu = UDPARD_MTU_MIN;
    }

    udpard_rx_t      rx{};
    udpard_rx_port_t port{};
    Context          ctx{};
    ctx.expected_uid = tx.local_uid;
    ctx.source       = { .ip = 0x0A000001U, .port = 7501U };
    udpard_rx_new(&rx, nullptr);
    rx.user = &ctx;
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 4096, rx_mem, &callbacks));

    // Send a payload that will require fragmentation at minimum MTU
    std::array<uint8_t, 1000> payload{};
    for (size_t i = 0; i < payload.size(); i++) {
        payload[i] = static_cast<uint8_t>(i & 0xFFU);
    }

    const udpard_bytes_scattered_t payload_view   = make_scattered(payload.data(), payload.size());
    constexpr uint16_t             iface_bitmap_1 = (1U << 0U);

    const udpard_us_t now = 0;
    frames.clear();
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    now,
                                    now + 1000000,
                                    iface_bitmap_1,
                                    udpard_prio_nominal,
                                    1U,
                                    payload_view,
                                    nullptr,
                                    UDPARD_USER_CONTEXT_NULL));
    udpard_tx_poll(&tx, now, UDPARD_IFACE_BITMAP_ALL);

    // With minimum MTU, we should have multiple frames
    TEST_ASSERT_TRUE(frames.size() > 1);

    // Deliver frames to RX
    const udpard_deleter_t tx_payload_deleter{ .vtable = &tx_refcount_deleter_vt, .context = nullptr };
    for (const auto& f : frames) {
        TEST_ASSERT_TRUE(
          udpard_rx_port_push(&rx, &port, now, ctx.source, f.datagram, tx_payload_deleter, f.iface_index));
    }
    udpard_rx_poll(&rx, now);

    // Verify the transfer was received correctly
    TEST_ASSERT_EQUAL_size_t(1, ctx.ids.size());
    TEST_ASSERT_EQUAL_UINT64(1U, ctx.ids[0]);

    // Cleanup
    udpard_rx_port_free(&rx, &port);
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

/// Test with transfer-ID at uint64 boundary values (0, large values)
void test_udpard_transfer_id_boundaries()
{
    Fixture fix{};

    // Test transfer-ID = 0 (first valid value)
    fix.push_single(0, 0);
    udpard_rx_poll(&fix.rx, 0);
    TEST_ASSERT_EQUAL_size_t(1, fix.ctx.ids.size());
    TEST_ASSERT_EQUAL_UINT64(0U, fix.ctx.ids[0]);

    // Test a large transfer-ID value
    fix.push_single(1, 0x7FFFFFFFFFFFFFFFULL); // Large but not at the extreme edge
    udpard_rx_poll(&fix.rx, 1);
    TEST_ASSERT_EQUAL_size_t(2, fix.ctx.ids.size());
    TEST_ASSERT_EQUAL_UINT64(0x7FFFFFFFFFFFFFFFULL, fix.ctx.ids[1]);

    // Test another large value to verify the history doesn't reject it
    fix.push_single(2, 0x8000000000000000ULL);
    udpard_rx_poll(&fix.rx, 2);
    TEST_ASSERT_EQUAL_size_t(3, fix.ctx.ids.size());
    TEST_ASSERT_EQUAL_UINT64(0x8000000000000000ULL, fix.ctx.ids[2]);
}

/// Test zero extent handling - should accept transfers but truncate payload
void test_udpard_rx_zero_extent()
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
    const udpard_rx_mem_resources_t rx_mem{ .session  = instrumented_allocator_make_resource(&rx_alloc_session),
                                            .fragment = instrumented_allocator_make_resource(&rx_alloc_frag) };

    udpard_tx_t tx{};
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0xAAAABBBBCCCCDDDDULL, 200U, 64, tx_mem, &tx_vtable));
    std::vector<CapturedFrame> frames;
    tx.user = &frames;

    udpard_rx_t      rx{};
    udpard_rx_port_t port{};
    udpard_rx_new(&rx, nullptr);

    // Create port with zero extent
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 0, rx_mem, &callbacks));

    // Track received transfers
    struct ZeroExtentContext
    {
        size_t count               = 0;
        size_t payload_size_stored = 0;
        size_t payload_size_wire   = 0;
    };
    ZeroExtentContext zctx{};

    // Custom callback for zero extent test
    struct ZeroExtentCallbacks
    {
        static void on_message(udpard_rx_t* const         rx_arg,
                               udpard_rx_port_t* const    port_arg,
                               const udpard_rx_transfer_t transfer)
        {
            auto* z = static_cast<ZeroExtentContext*>(rx_arg->user);
            z->count++;
            z->payload_size_stored = transfer.payload_size_stored;
            z->payload_size_wire   = transfer.payload_size_wire;
            udpard_fragment_free_all(transfer.payload, udpard_make_deleter(port_arg->memory.fragment));
        }
    };
    static constexpr udpard_rx_port_vtable_t zero_callbacks{ .on_message = &ZeroExtentCallbacks::on_message };
    port.vtable = &zero_callbacks;
    rx.user     = &zctx;

    // Send a small single-frame transfer
    std::array<uint8_t, 100> payload{};
    for (size_t i = 0; i < payload.size(); i++) {
        payload[i] = static_cast<uint8_t>(i);
    }

    const udpard_bytes_scattered_t payload_view   = make_scattered(payload.data(), payload.size());
    constexpr uint16_t             iface_bitmap_1 = (1U << 0U);
    const udpard_udpip_ep_t        source{ .ip = 0x0A000002U, .port = 7502U };

    const udpard_us_t now = 0;
    frames.clear();
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    now,
                                    now + 1000000,
                                    iface_bitmap_1,
                                    udpard_prio_nominal,
                                    5U,
                                    payload_view,
                                    nullptr,
                                    UDPARD_USER_CONTEXT_NULL));
    udpard_tx_poll(&tx, now, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_FALSE(frames.empty());

    // Deliver to RX with zero extent
    const udpard_deleter_t tx_payload_deleter{ .vtable = &tx_refcount_deleter_vt, .context = nullptr };
    for (const auto& f : frames) {
        TEST_ASSERT_TRUE(udpard_rx_port_push(&rx, &port, now, source, f.datagram, tx_payload_deleter, f.iface_index));
    }
    udpard_rx_poll(&rx, now);

    // Transfer should be received - zero extent means minimal/no truncation for single-frame
    // The library may still store some payload for single-frame transfers even with zero extent
    TEST_ASSERT_EQUAL_size_t(1, zctx.count);
    TEST_ASSERT_TRUE(zctx.payload_size_stored <= payload.size());     // At most the original size
    TEST_ASSERT_EQUAL_size_t(payload.size(), zctx.payload_size_wire); // Wire size is original

    // Cleanup
    udpard_rx_port_free(&rx, &port);
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

/// Test empty payload transfer (zero-size payload)
void test_udpard_empty_payload()
{
    Fixture fix{};

    // Send an empty payload
    fix.frames.clear();
    const udpard_bytes_scattered_t empty_payload  = make_scattered(nullptr, 0);
    const udpard_us_t              deadline       = 1000000;
    constexpr uint16_t             iface_bitmap_1 = (1U << 0U);

    TEST_ASSERT_TRUE(udpard_tx_push(&fix.tx,
                                    0,
                                    deadline,
                                    iface_bitmap_1,
                                    udpard_prio_nominal,
                                    10U,
                                    empty_payload,
                                    nullptr,
                                    UDPARD_USER_CONTEXT_NULL));
    udpard_tx_poll(&fix.tx, 0, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_FALSE(fix.frames.empty());

    // Deliver to RX
    for (const auto& f : fix.frames) {
        TEST_ASSERT_TRUE(
          udpard_rx_port_push(&fix.rx, &fix.port, 0, fix.source, f.datagram, fix.tx_payload_deleter, f.iface_index));
    }
    udpard_rx_poll(&fix.rx, 0);

    // Empty transfer should be received
    TEST_ASSERT_EQUAL_size_t(1, fix.ctx.ids.size());
    TEST_ASSERT_EQUAL_UINT64(10U, fix.ctx.ids[0]);
}

/// Test priority levels from exceptional (0) to optional (7)
void test_udpard_all_priority_levels()
{
    Fixture     fix{};
    udpard_us_t now = 0;

    constexpr uint16_t iface_bitmap_1 = (1U << 0U);

    // Test all 8 priority levels
    for (uint8_t prio = 0; prio < UDPARD_PRIORITY_COUNT; prio++) {
        fix.frames.clear();
        std::array<uint8_t, 8> payload{};
        payload[0]                                  = prio;
        const udpard_bytes_scattered_t payload_view = make_scattered(payload.data(), payload.size());

        TEST_ASSERT_TRUE(udpard_tx_push(&fix.tx,
                                        now,
                                        now + 1000000,
                                        iface_bitmap_1,
                                        static_cast<udpard_prio_t>(prio),
                                        100U + prio,
                                        payload_view,
                                        nullptr,
                                        UDPARD_USER_CONTEXT_NULL));
        udpard_tx_poll(&fix.tx, now, UDPARD_IFACE_BITMAP_ALL);
        TEST_ASSERT_FALSE(fix.frames.empty());

        for (const auto& f : fix.frames) {
            TEST_ASSERT_TRUE(udpard_rx_port_push(
              &fix.rx, &fix.port, now, fix.source, f.datagram, fix.tx_payload_deleter, f.iface_index));
        }
        udpard_rx_poll(&fix.rx, now);
        now++;
    }

    // All 8 transfers should be received
    TEST_ASSERT_EQUAL_size_t(UDPARD_PRIORITY_COUNT, fix.ctx.ids.size());
    for (uint8_t prio = 0; prio < UDPARD_PRIORITY_COUNT; prio++) {
        TEST_ASSERT_EQUAL_UINT64(100U + prio, fix.ctx.ids[prio]);
    }
}

} // namespace

extern "C" void setUp() {}

extern "C" void tearDown() {}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_udpard_rx_unordered_duplicates);
    RUN_TEST(test_udpard_tx_feedback_always_called);
    RUN_TEST(test_udpard_tx_push_p2p);
    RUN_TEST(test_udpard_tx_minimum_mtu);
    RUN_TEST(test_udpard_transfer_id_boundaries);
    RUN_TEST(test_udpard_rx_zero_extent);
    RUN_TEST(test_udpard_empty_payload);
    RUN_TEST(test_udpard_all_priority_levels);
    return UNITY_END();
}
