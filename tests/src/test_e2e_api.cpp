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

struct CapturedFrame
{
    udpard_bytes_mut_t datagram;
    uint_fast8_t       iface_index;
};

struct FeedbackState
{
    size_t   count       = 0;
    bool     success     = false;
    uint64_t transfer_id = 0;
};

struct RxContext
{
    std::vector<uint8_t>                                  expected;
    std::array<udpard_udpip_ep_t, UDPARD_IFACE_COUNT_MAX> sources{};
    uint64_t                                              remote_uid = 0;
    size_t                                                received   = 0;
    size_t                                                collisions = 0;
};

// Refcount helpers keep captured datagrams alive.
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

void drop_frame(const CapturedFrame& frame)
{
    udpard_tx_refcount_dec(udpard_bytes_t{ .size = frame.datagram.size, .data = frame.datagram.data });
}

void fill_random(std::vector<uint8_t>& data)
{
    for (auto& byte : data) {
        byte = static_cast<uint8_t>(rand()) & 0xFFU;
    }
}

constexpr udpard_tx_vtable_t tx_vtable{ .eject = &capture_tx_frame };

// Feedback callback records completion.
void record_feedback(udpard_tx_t*, const udpard_tx_feedback_t fb)
{
    auto* st = static_cast<FeedbackState*>(fb.user_transfer_reference);
    if (st != nullptr) {
        st->count++;
        st->success     = fb.success;
        st->transfer_id = fb.transfer_id;
    }
}

// RX callbacks validate payload and sender.
void on_message(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    auto* ctx = static_cast<RxContext*>(rx->user);
    TEST_ASSERT_EQUAL_UINT64(ctx->remote_uid, transfer.remote.uid);
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        if ((transfer.remote.endpoints[i].ip != 0U) || (transfer.remote.endpoints[i].port != 0U)) {
            TEST_ASSERT_EQUAL_UINT32(ctx->sources[i].ip, transfer.remote.endpoints[i].ip);
            TEST_ASSERT_EQUAL_UINT16(ctx->sources[i].port, transfer.remote.endpoints[i].port);
        }
    }
    std::vector<uint8_t>     assembled(transfer.payload_size_stored);
    const udpard_fragment_t* cursor = transfer.payload;
    const size_t gathered = udpard_fragment_gather(&cursor, 0, transfer.payload_size_stored, assembled.data());
    TEST_ASSERT_EQUAL_size_t(transfer.payload_size_stored, gathered);
    TEST_ASSERT_EQUAL_size_t(ctx->expected.size(), transfer.payload_size_wire);
    if (!ctx->expected.empty()) {
        TEST_ASSERT_EQUAL_MEMORY(ctx->expected.data(), assembled.data(), transfer.payload_size_stored);
    }
    udpard_fragment_free_all(transfer.payload, port->memory.fragment);
    ctx->received++;
}

void on_collision(udpard_rx_t* const rx, udpard_rx_port_t* const /*port*/, const udpard_remote_t /*remote*/)
{
    auto* ctx = static_cast<RxContext*>(rx->user);
    ctx->collisions++;
}
constexpr udpard_rx_port_vtable_t callbacks{ .on_message = &on_message, .on_collision = &on_collision };

// Ack port frees responses.
void on_ack_response(udpard_rx_t*, udpard_rx_port_p2p_t* port, const udpard_rx_transfer_p2p_t tr)
{
    udpard_fragment_free_all(tr.base.payload, port->base.memory.fragment);
}
constexpr udpard_rx_port_p2p_vtable_t ack_callbacks{ &on_ack_response };

// Reliable delivery must survive data and ack loss.
void test_reliable_delivery_under_losses()
{
    seed_prng();

    // Allocators.
    instrumented_allocator_t pub_alloc_transfer{};
    instrumented_allocator_t pub_alloc_payload{};
    instrumented_allocator_t sub_alloc_frag{};
    instrumented_allocator_t sub_alloc_session{};
    instrumented_allocator_t acktx_alloc_transfer{};
    instrumented_allocator_t acktx_alloc_payload{};
    instrumented_allocator_t ackrx_alloc_frag{};
    instrumented_allocator_t ackrx_alloc_session{};
    instrumented_allocator_new(&pub_alloc_transfer);
    instrumented_allocator_new(&pub_alloc_payload);
    instrumented_allocator_new(&sub_alloc_frag);
    instrumented_allocator_new(&sub_alloc_session);
    instrumented_allocator_new(&acktx_alloc_transfer);
    instrumented_allocator_new(&acktx_alloc_payload);
    instrumented_allocator_new(&ackrx_alloc_frag);
    instrumented_allocator_new(&ackrx_alloc_session);

    // Memory views.
    udpard_tx_mem_resources_t pub_mem{};
    pub_mem.transfer = instrumented_allocator_make_resource(&pub_alloc_transfer);
    for (auto& res : pub_mem.payload) {
        res = instrumented_allocator_make_resource(&pub_alloc_payload);
    }
    udpard_tx_mem_resources_t ack_mem{};
    ack_mem.transfer = instrumented_allocator_make_resource(&acktx_alloc_transfer);
    for (auto& res : ack_mem.payload) {
        res = instrumented_allocator_make_resource(&acktx_alloc_payload);
    }
    const udpard_rx_mem_resources_t sub_mem{ .session  = instrumented_allocator_make_resource(&sub_alloc_session),
                                             .fragment = instrumented_allocator_make_resource(&sub_alloc_frag) };
    const udpard_rx_mem_resources_t ack_rx_mem{ .session  = instrumented_allocator_make_resource(&ackrx_alloc_session),
                                                .fragment = instrumented_allocator_make_resource(&ackrx_alloc_frag) };

    // Pipelines.
    udpard_tx_t                pub_tx{};
    std::vector<CapturedFrame> pub_frames;
    TEST_ASSERT_TRUE(udpard_tx_new(&pub_tx, 0x1111222233334444ULL, 10U, 64, pub_mem, &tx_vtable));
    pub_tx.user                 = &pub_frames;
    pub_tx.ack_baseline_timeout = 8000;
    udpard_tx_t                ack_tx{};
    std::vector<CapturedFrame> ack_frames;
    TEST_ASSERT_TRUE(udpard_tx_new(&ack_tx, 0xABCDEF0012345678ULL, 77U, 8, ack_mem, &tx_vtable));
    ack_tx.user = &ack_frames;

    udpard_rx_t sub_rx{};
    udpard_rx_new(&sub_rx, &ack_tx);
    udpard_rx_port_t sub_port{};
    const uint64_t   topic_hash = 0x0123456789ABCDEFULL;
    TEST_ASSERT_TRUE(
      udpard_rx_port_new(&sub_port, topic_hash, 6000, UDPARD_RX_REORDERING_WINDOW_UNORDERED, sub_mem, &callbacks));
    udpard_rx_t          ack_rx{};
    udpard_rx_port_p2p_t ack_port{};
    udpard_rx_new(&ack_rx, &pub_tx);
    TEST_ASSERT_TRUE(
      udpard_rx_port_new_p2p(&ack_port, pub_tx.local_uid, UDPARD_P2P_HEADER_BYTES, ack_rx_mem, &ack_callbacks));

    // Endpoints.
    const std::array<udpard_udpip_ep_t, UDPARD_IFACE_COUNT_MAX> publisher_sources{
        udpard_udpip_ep_t{ .ip = 0x0A000001U, .port = 7400U },
        udpard_udpip_ep_t{ .ip = 0x0A000002U, .port = 7401U },
        udpard_udpip_ep_t{ .ip = 0x0A000003U, .port = 7402U },
    };
    const std::array<udpard_udpip_ep_t, UDPARD_IFACE_COUNT_MAX> subscriber_endpoints{
        udpard_make_subject_endpoint(111U),
        udpard_udpip_ep_t{ .ip = 0x0A00000BU, .port = 7501U },
        udpard_udpip_ep_t{ .ip = 0x0A00000CU, .port = 7502U },
    };
    const std::array<udpard_udpip_ep_t, UDPARD_IFACE_COUNT_MAX> ack_sources{
        udpard_udpip_ep_t{ .ip = 0x0A000010U, .port = 7600U },
        udpard_udpip_ep_t{ .ip = 0x0A000011U, .port = 7601U },
        udpard_udpip_ep_t{ .ip = 0x0A000012U, .port = 7602U },
    };

    // Payload and context.
    std::vector<uint8_t> payload(4096);
    fill_random(payload);
    RxContext ctx{};
    ctx.expected   = payload;
    ctx.sources    = publisher_sources;
    ctx.remote_uid = pub_tx.local_uid;
    sub_rx.user    = &ctx;

    // Reliable transfer with staged losses.
    FeedbackState        fb{};
    const udpard_bytes_t payload_view{ .size = payload.size(), .data = payload.data() };
    std::array<udpard_udpip_ep_t, UDPARD_IFACE_COUNT_MAX> dest_per_iface = subscriber_endpoints;
    pub_tx.mtu[0]                                                        = 600;
    pub_tx.mtu[1]                                                        = 900;
    pub_tx.mtu[2]                                                        = 500;
    const udpard_us_t          start                                     = 0;
    const udpard_us_t          deadline                                  = start + 200000;
    const udpard_mem_deleter_t tx_payload_deleter{ .user = nullptr, .free = &tx_refcount_free };
    TEST_ASSERT_GREATER_THAN_UINT32(0U,
                                    udpard_tx_push(&pub_tx,
                                                   start,
                                                   deadline,
                                                   udpard_prio_fast,
                                                   topic_hash,
                                                   dest_per_iface.data(),
                                                   1U,
                                                   payload_view,
                                                   &record_feedback,
                                                   &fb));

    // Send until acked; drop first data frame and first ack.
    bool         first_round = true;
    udpard_us_t  now         = start;
    size_t       attempts    = 0;
    const size_t attempt_cap = 6;
    while ((fb.count == 0) && (attempts < attempt_cap)) {
        pub_frames.clear();
        udpard_tx_poll(&pub_tx, now, UDPARD_IFACE_MASK_ALL);
        bool data_loss_done = false;
        for (const auto& frame : pub_frames) {
            const bool drop = first_round && !data_loss_done && (frame.iface_index == 1U);
            if (drop) {
                drop_frame(frame);
                data_loss_done = true;
                continue;
            }
            TEST_ASSERT_TRUE(udpard_rx_port_push(&sub_rx,
                                                 &sub_port,
                                                 now,
                                                 publisher_sources[frame.iface_index],
                                                 frame.datagram,
                                                 tx_payload_deleter,
                                                 frame.iface_index));
        }
        udpard_rx_poll(&sub_rx, now);

        ack_frames.clear();
        udpard_tx_poll(&ack_tx, now, UDPARD_IFACE_MASK_ALL);
        bool ack_sent = false;
        for (const auto& ack : ack_frames) {
            const bool drop_ack = first_round && !ack_sent;
            if (drop_ack) {
                drop_frame(ack);
                continue;
            }
            ack_sent = true;
            TEST_ASSERT_TRUE(udpard_rx_port_push(&ack_rx,
                                                 reinterpret_cast<udpard_rx_port_t*>(&ack_port),
                                                 now,
                                                 ack_sources[ack.iface_index],
                                                 ack.datagram,
                                                 tx_payload_deleter,
                                                 ack.iface_index));
        }
        udpard_rx_poll(&ack_rx, now);
        first_round = false;
        attempts++;
        now += pub_tx.ack_baseline_timeout + 5000;
    }

    TEST_ASSERT_EQUAL_size_t(1, fb.count);
    TEST_ASSERT_TRUE(fb.success);
    TEST_ASSERT_EQUAL_size_t(1, ctx.received);
    TEST_ASSERT_EQUAL_size_t(0, ctx.collisions);

    // Cleanup.
    udpard_rx_port_free(&sub_rx, &sub_port);
    udpard_rx_port_free(&ack_rx, reinterpret_cast<udpard_rx_port_t*>(&ack_port));
    udpard_tx_free(&pub_tx);
    udpard_tx_free(&ack_tx);
    TEST_ASSERT_EQUAL_size_t(0, sub_alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, sub_alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, pub_alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, pub_alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, acktx_alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, acktx_alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, ackrx_alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, ackrx_alloc_session.allocated_fragments);
    instrumented_allocator_reset(&sub_alloc_frag);
    instrumented_allocator_reset(&sub_alloc_session);
    instrumented_allocator_reset(&pub_alloc_transfer);
    instrumented_allocator_reset(&pub_alloc_payload);
    instrumented_allocator_reset(&acktx_alloc_transfer);
    instrumented_allocator_reset(&acktx_alloc_payload);
    instrumented_allocator_reset(&ackrx_alloc_frag);
    instrumented_allocator_reset(&ackrx_alloc_session);
}

// Counters must reflect expired deliveries and ack failures.
void test_reliable_stats_and_failures()
{
    seed_prng();

    // Expiration path.
    instrumented_allocator_t exp_alloc_transfer{};
    instrumented_allocator_t exp_alloc_payload{};
    instrumented_allocator_new(&exp_alloc_transfer);
    instrumented_allocator_new(&exp_alloc_payload);
    udpard_tx_mem_resources_t exp_mem{};
    exp_mem.transfer = instrumented_allocator_make_resource(&exp_alloc_transfer);
    for (auto& res : exp_mem.payload) {
        res = instrumented_allocator_make_resource(&exp_alloc_payload);
    }
    udpard_tx_t                exp_tx{};
    std::vector<CapturedFrame> exp_frames;
    TEST_ASSERT_TRUE(udpard_tx_new(&exp_tx, 0x9999000011112222ULL, 2U, 4, exp_mem, &tx_vtable));
    exp_tx.user = &exp_frames;
    FeedbackState           fb_fail{};
    const udpard_udpip_ep_t exp_dest[UDPARD_IFACE_COUNT_MAX] = { udpard_make_subject_endpoint(99U), {}, {} };
    const udpard_bytes_t    exp_payload{ .size = 4, .data = "ping" };
    TEST_ASSERT_GREATER_THAN_UINT32(
      0U,
      udpard_tx_push(
        &exp_tx, 0, 10, udpard_prio_fast, 0xABCULL, exp_dest, 5U, exp_payload, &record_feedback, &fb_fail));
    udpard_tx_poll(&exp_tx, 0, UDPARD_IFACE_MASK_ALL);
    for (const auto& f : exp_frames) {
        drop_frame(f);
    }
    exp_frames.clear();
    udpard_tx_poll(&exp_tx, 20, UDPARD_IFACE_MASK_ALL);
    TEST_ASSERT_EQUAL_size_t(1, fb_fail.count);
    TEST_ASSERT_FALSE(fb_fail.success);
    TEST_ASSERT_GREATER_THAN_UINT64(0, exp_tx.errors_expiration);
    udpard_tx_free(&exp_tx);
    TEST_ASSERT_EQUAL_size_t(0, exp_alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, exp_alloc_payload.allocated_fragments);
    instrumented_allocator_reset(&exp_alloc_transfer);
    instrumented_allocator_reset(&exp_alloc_payload);

    // Ack push failure increments counters.
    instrumented_allocator_t rx_alloc_frag{};
    instrumented_allocator_t rx_alloc_session{};
    instrumented_allocator_t src_alloc_transfer{};
    instrumented_allocator_t src_alloc_payload{};
    instrumented_allocator_new(&rx_alloc_frag);
    instrumented_allocator_new(&rx_alloc_session);
    instrumented_allocator_new(&src_alloc_transfer);
    instrumented_allocator_new(&src_alloc_payload);
    const udpard_rx_mem_resources_t rx_mem{ .session  = instrumented_allocator_make_resource(&rx_alloc_session),
                                            .fragment = instrumented_allocator_make_resource(&rx_alloc_frag) };
    udpard_tx_mem_resources_t       src_mem{};
    src_mem.transfer = instrumented_allocator_make_resource(&src_alloc_transfer);
    for (auto& res : src_mem.payload) {
        res = instrumented_allocator_make_resource(&src_alloc_payload);
    }

    udpard_tx_t                src_tx{};
    std::vector<CapturedFrame> src_frames;
    TEST_ASSERT_TRUE(udpard_tx_new(&src_tx, 0x5555AAAABBBBCCCCULL, 3U, 4, src_mem, &tx_vtable));
    src_tx.user = &src_frames;
    udpard_rx_t      rx{};
    udpard_rx_port_t port{};
    RxContext        ctx{};
    ctx.remote_uid = src_tx.local_uid;
    ctx.sources = { udpard_udpip_ep_t{ .ip = 0x0A000021U, .port = 7700U }, udpard_udpip_ep_t{}, udpard_udpip_ep_t{} };
    ctx.expected.assign({ 1U, 2U, 3U, 4U });
    udpard_rx_new(&rx, nullptr);
    rx.user = &ctx;
    TEST_ASSERT_TRUE(
      udpard_rx_port_new(&port, 0x12340000ULL, 64, UDPARD_RX_REORDERING_WINDOW_UNORDERED, rx_mem, &callbacks));

    const udpard_udpip_ep_t src_dest[UDPARD_IFACE_COUNT_MAX] = { udpard_make_subject_endpoint(12U), {}, {} };
    const udpard_bytes_t    src_payload{ .size = ctx.expected.size(), .data = ctx.expected.data() };
    FeedbackState           fb_ignore{};
    TEST_ASSERT_GREATER_THAN_UINT32(
      0U,
      udpard_tx_push(
        &src_tx, 0, 1000, udpard_prio_fast, port.topic_hash, src_dest, 7U, src_payload, &record_feedback, &fb_ignore));
    udpard_tx_poll(&src_tx, 0, UDPARD_IFACE_MASK_ALL);
    const udpard_mem_deleter_t tx_payload_deleter{ .user = nullptr, .free = &tx_refcount_free };
    for (const auto& f : src_frames) {
        TEST_ASSERT_TRUE(udpard_rx_port_push(
          &rx, &port, 0, ctx.sources[f.iface_index], f.datagram, tx_payload_deleter, f.iface_index));
    }
    udpard_rx_poll(&rx, 0);
    TEST_ASSERT_GREATER_THAN_UINT64(0, rx.errors_ack_tx);
    TEST_ASSERT_EQUAL_size_t(1, ctx.received);

    udpard_rx_port_free(&rx, &port);
    udpard_tx_free(&src_tx);
    TEST_ASSERT_EQUAL_size_t(0, rx_alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, rx_alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, src_alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, src_alloc_payload.allocated_fragments);
    instrumented_allocator_reset(&rx_alloc_frag);
    instrumented_allocator_reset(&rx_alloc_session);
    instrumented_allocator_reset(&src_alloc_transfer);
    instrumented_allocator_reset(&src_alloc_payload);
}

} // namespace

extern "C" void setUp() {}

extern "C" void tearDown() {}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_reliable_delivery_under_losses);
    RUN_TEST(test_reliable_stats_and_failures);
    return UNITY_END();
}
