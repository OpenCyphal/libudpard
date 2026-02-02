/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.h>
#include "helpers.h"
#include <unity.h>
#include <array>
#include <vector>
#include <cstring>

namespace {

// --------------------------------------------------------------------------------------------------------------------
// COMMON INFRASTRUCTURE
// --------------------------------------------------------------------------------------------------------------------

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

bool capture_tx_frame_impl(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection)
{
    auto* frames = static_cast<std::vector<CapturedFrame>*>(tx->user);
    if (frames == nullptr) {
        return false;
    }
    udpard_tx_refcount_inc(ejection->datagram);
    void* const data = const_cast<void*>(ejection->datagram.data); // NOLINT
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

void drop_frame(const CapturedFrame& frame)
{
    udpard_tx_refcount_dec(udpard_bytes_t{ .size = frame.datagram.size, .data = frame.datagram.data });
}

constexpr udpard_tx_vtable_t tx_vtable{ .eject_subject = &capture_tx_frame_subject,
                                        .eject_p2p     = &capture_tx_frame_p2p };
// Shared deleter for captured TX frames.
constexpr udpard_deleter_vtable_t tx_refcount_deleter_vt{ .free = &tx_refcount_free };
constexpr udpard_deleter_t        tx_payload_deleter{ .vtable = &tx_refcount_deleter_vt, .context = nullptr };

// Check the ACK flag in the Cyphal/UDP header.
constexpr size_t HeaderSizeBytes = 40U;
bool             is_ack_frame(const udpard_bytes_mut_t& datagram)
{
    if (datagram.size < HeaderSizeBytes) {
        return false;
    }
    const auto* p = static_cast<const uint8_t*>(datagram.data);
    return p[1] == 2U;
}

// --------------------------------------------------------------------------------------------------------------------
// FEEDBACK AND CONTEXT STRUCTURES
// --------------------------------------------------------------------------------------------------------------------

struct FeedbackState
{
    size_t   count            = 0;
    uint16_t acknowledgements = 0;
};

void record_feedback(udpard_tx_t*, const udpard_tx_feedback_t fb)
{
    auto* st = static_cast<FeedbackState*>(fb.user.ptr[0]);
    if (st != nullptr) {
        st->count++;
        st->acknowledgements = fb.acknowledgements;
    }
}

struct NodeBTopicContext
{
    std::vector<uint8_t>                                  received_payload;
    std::array<udpard_udpip_ep_t, UDPARD_IFACE_COUNT_MAX> sender_sources{};
    uint64_t                                              sender_uid    = 0;
    uint64_t                                              received_tid  = 0;
    size_t                                                message_count = 0;
};

struct NodeAResponseContext
{
    std::vector<uint8_t> received_response;
    uint64_t             transfer_id    = 0;
    size_t               response_count = 0;
};

// Combined context for a node's RX instance
struct NodeContext
{
    NodeBTopicContext*    topic_ctx    = nullptr;
    NodeAResponseContext* response_ctx = nullptr;
};

// --------------------------------------------------------------------------------------------------------------------
// CALLBACK IMPLEMENTATIONS
// --------------------------------------------------------------------------------------------------------------------

// Node B's message reception callback - receives the topic message from A
void node_b_on_topic_message(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    auto* node_ctx = static_cast<NodeContext*>(rx->user);
    auto* ctx      = node_ctx->topic_ctx;
    if (ctx == nullptr) {
        udpard_fragment_free_all(transfer.payload, udpard_make_deleter(port->memory.fragment));
        return;
    }
    ctx->message_count++;
    ctx->sender_uid     = transfer.remote.uid;
    ctx->sender_sources = {};
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        ctx->sender_sources[i] = transfer.remote.endpoints[i];
    }
    ctx->received_tid = transfer.transfer_id;

    ctx->received_payload.resize(transfer.payload_size_stored);
    const udpard_fragment_t* cursor = transfer.payload;
    (void)udpard_fragment_gather(&cursor, 0, transfer.payload_size_stored, ctx->received_payload.data());

    udpard_fragment_free_all(transfer.payload, udpard_make_deleter(port->memory.fragment));
}

constexpr udpard_rx_port_vtable_t topic_callbacks{ .on_message = &node_b_on_topic_message };

// Node A's P2P response reception callback - receives the response from B
void node_a_on_p2p_response(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    auto* node_ctx = static_cast<NodeContext*>(rx->user);
    auto* ctx      = node_ctx->response_ctx;
    if (ctx == nullptr) {
        udpard_fragment_free_all(transfer.payload, udpard_make_deleter(port->memory.fragment));
        return;
    }
    ctx->response_count++;
    ctx->transfer_id = transfer.transfer_id;

    ctx->received_response.resize(transfer.payload_size_stored);
    const udpard_fragment_t* cursor = transfer.payload;
    (void)udpard_fragment_gather(&cursor, 0, transfer.payload_size_stored, ctx->received_response.data());

    udpard_fragment_free_all(transfer.payload, udpard_make_deleter(port->memory.fragment));
}

constexpr udpard_rx_port_vtable_t p2p_response_callbacks{ .on_message = &node_a_on_p2p_response };

// ACK-only P2P port callback (for receiving ACKs, which have no user payload)
void on_ack_only(udpard_rx_t*, udpard_rx_port_t* port, const udpard_rx_transfer_t tr)
{
    udpard_fragment_free_all(tr.payload, udpard_make_deleter(port->memory.fragment));
}

constexpr udpard_rx_port_vtable_t ack_only_callbacks{ .on_message = &on_ack_only };

// --------------------------------------------------------------------------------------------------------------------
// TEST: Basic topic message with P2P response flow
// --------------------------------------------------------------------------------------------------------------------

/// Node A publishes a reliable topic message, Node B receives it and sends a reliable P2P response.
/// Both nodes verify that their delivery callbacks are correctly invoked.
/// Each node uses exactly one TX and one RX instance.
void test_topic_with_p2p_response()
{
    seed_prng();

    // ================================================================================================================
    // ALLOCATORS - One TX and one RX per node
    // ================================================================================================================
    instrumented_allocator_t a_tx_alloc_transfer{};
    instrumented_allocator_t a_tx_alloc_payload{};
    instrumented_allocator_t a_rx_alloc_frag{};
    instrumented_allocator_t a_rx_alloc_session{};
    instrumented_allocator_new(&a_tx_alloc_transfer);
    instrumented_allocator_new(&a_tx_alloc_payload);
    instrumented_allocator_new(&a_rx_alloc_frag);
    instrumented_allocator_new(&a_rx_alloc_session);

    instrumented_allocator_t b_tx_alloc_transfer{};
    instrumented_allocator_t b_tx_alloc_payload{};
    instrumented_allocator_t b_rx_alloc_frag{};
    instrumented_allocator_t b_rx_alloc_session{};
    instrumented_allocator_new(&b_tx_alloc_transfer);
    instrumented_allocator_new(&b_tx_alloc_payload);
    instrumented_allocator_new(&b_rx_alloc_frag);
    instrumented_allocator_new(&b_rx_alloc_session);

    // ================================================================================================================
    // MEMORY RESOURCES
    // ================================================================================================================
    udpard_tx_mem_resources_t a_tx_mem{};
    a_tx_mem.transfer = instrumented_allocator_make_resource(&a_tx_alloc_transfer);
    for (auto& res : a_tx_mem.payload) {
        res = instrumented_allocator_make_resource(&a_tx_alloc_payload);
    }
    const udpard_rx_mem_resources_t a_rx_mem{ .session  = instrumented_allocator_make_resource(&a_rx_alloc_session),
                                              .fragment = instrumented_allocator_make_resource(&a_rx_alloc_frag) };

    udpard_tx_mem_resources_t b_tx_mem{};
    b_tx_mem.transfer = instrumented_allocator_make_resource(&b_tx_alloc_transfer);
    for (auto& res : b_tx_mem.payload) {
        res = instrumented_allocator_make_resource(&b_tx_alloc_payload);
    }
    const udpard_rx_mem_resources_t b_rx_mem{ .session  = instrumented_allocator_make_resource(&b_rx_alloc_session),
                                              .fragment = instrumented_allocator_make_resource(&b_rx_alloc_frag) };

    // ================================================================================================================
    // NODE UIDs AND ENDPOINTS
    // ================================================================================================================
    constexpr uint64_t node_a_uid = 0xAAAA1111BBBB2222ULL;
    constexpr uint64_t node_b_uid = 0xCCCC3333DDDD4444ULL;

    const std::array<udpard_udpip_ep_t, UDPARD_IFACE_COUNT_MAX> node_a_sources{
        udpard_udpip_ep_t{ .ip = 0x0A000001U, .port = 7400U },
        udpard_udpip_ep_t{ .ip = 0x0A000002U, .port = 7401U },
        udpard_udpip_ep_t{ .ip = 0x0A000003U, .port = 7402U },
    };
    const std::array<udpard_udpip_ep_t, UDPARD_IFACE_COUNT_MAX> node_b_sources{
        udpard_udpip_ep_t{ .ip = 0x0A000011U, .port = 7500U },
        udpard_udpip_ep_t{ .ip = 0x0A000012U, .port = 7501U },
        udpard_udpip_ep_t{ .ip = 0x0A000013U, .port = 7502U },
    };

    constexpr uint64_t transfer_id = 42;

    // ================================================================================================================
    // TX/RX PIPELINES - One TX and one RX per node
    // ================================================================================================================
    // Node A: single TX, single RX (linked to TX for ACK processing)
    udpard_tx_t                a_tx{};
    std::vector<CapturedFrame> a_frames;
    TEST_ASSERT_TRUE(udpard_tx_new(&a_tx, node_a_uid, 100, 64, a_tx_mem, &tx_vtable));
    a_tx.user                 = &a_frames;
    a_tx.ack_baseline_timeout = 10000;

    udpard_rx_t a_rx{};
    udpard_rx_new(&a_rx, &a_tx);
    NodeAResponseContext a_response_ctx{};
    NodeContext          a_node_ctx{ .topic_ctx = nullptr, .response_ctx = &a_response_ctx };
    a_rx.user = &a_node_ctx;

    // A's P2P port for receiving responses and ACKs
    udpard_rx_port_t a_p2p_port{};
    TEST_ASSERT_TRUE(udpard_rx_port_new_p2p(&a_p2p_port, 4096, a_rx_mem, &p2p_response_callbacks));

    // Node B: single TX, single RX (linked to TX for ACK processing)
    udpard_tx_t                b_tx{};
    std::vector<CapturedFrame> b_frames;
    TEST_ASSERT_TRUE(udpard_tx_new(&b_tx, node_b_uid, 200, 64, b_tx_mem, &tx_vtable));
    b_tx.user                 = &b_frames;
    b_tx.ack_baseline_timeout = 10000;

    udpard_rx_t b_rx{};
    udpard_rx_new(&b_rx, &b_tx);
    NodeBTopicContext b_topic_ctx{};
    NodeContext       b_node_ctx{ .topic_ctx = &b_topic_ctx, .response_ctx = nullptr };
    b_rx.user = &b_node_ctx;

    // B's topic subscription port
    udpard_rx_port_t b_topic_port{};
    TEST_ASSERT_TRUE(udpard_rx_port_new(&b_topic_port, 4096, b_rx_mem, &topic_callbacks));

    // B's P2P port for receiving response ACKs
    udpard_rx_port_t b_p2p_port{};
    TEST_ASSERT_TRUE(udpard_rx_port_new_p2p(&b_p2p_port, 16, b_rx_mem, &ack_only_callbacks));

    // ================================================================================================================
    // PAYLOADS AND FEEDBACK STATES
    // ================================================================================================================
    const std::vector<uint8_t>     topic_payload      = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    const std::vector<uint8_t>     response_payload   = { 0xAA, 0xBB, 0xCC, 0xDD };
    const udpard_bytes_scattered_t topic_payload_scat = make_scattered(topic_payload.data(), topic_payload.size());

    FeedbackState a_topic_fb{};
    FeedbackState b_response_fb{};

    // ================================================================================================================
    // STEP 1: Node A publishes a reliable topic message
    // ================================================================================================================
    udpard_us_t        now            = 0;
    constexpr uint16_t iface_bitmap_1 = (1U << 0U);
    TEST_ASSERT_TRUE(udpard_tx_push(&a_tx,
                                    now,
                                    now + 1000000,
                                    iface_bitmap_1,
                                    udpard_prio_nominal,
                                    transfer_id,
                                    topic_payload_scat,
                                    &record_feedback,
                                    make_user_context(&a_topic_fb)));
    a_frames.clear();
    udpard_tx_poll(&a_tx, now, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_FALSE(a_frames.empty());

    // ================================================================================================================
    // STEP 2: Deliver topic message to Node B
    // ================================================================================================================
    for (const auto& frame : a_frames) {
        TEST_ASSERT_TRUE(udpard_rx_port_push(&b_rx,
                                             &b_topic_port,
                                             now,
                                             node_a_sources[frame.iface_index],
                                             frame.datagram,
                                             tx_payload_deleter,
                                             frame.iface_index));
    }
    udpard_rx_poll(&b_rx, now);
    a_frames.clear();

    // Verify B received the message
    TEST_ASSERT_EQUAL_size_t(1, b_topic_ctx.message_count);
    TEST_ASSERT_EQUAL_UINT64(node_a_uid, b_topic_ctx.sender_uid);
    TEST_ASSERT_EQUAL_size_t(topic_payload.size(), b_topic_ctx.received_payload.size());
    TEST_ASSERT_EQUAL_MEMORY(topic_payload.data(), b_topic_ctx.received_payload.data(), topic_payload.size());

    // ================================================================================================================
    // STEP 3: Node B sends ACK back to A (for the topic message) - via b_tx since b_rx is linked to it
    // ================================================================================================================
    b_frames.clear();
    udpard_tx_poll(&b_tx, now, UDPARD_IFACE_BITMAP_ALL);

    // Deliver ACK frames to A
    for (const auto& frame : b_frames) {
        TEST_ASSERT_TRUE(udpard_rx_port_push(&a_rx,
                                             &a_p2p_port,
                                             now,
                                             node_b_sources[frame.iface_index],
                                             frame.datagram,
                                             tx_payload_deleter,
                                             frame.iface_index));
    }
    udpard_rx_poll(&a_rx, now);
    b_frames.clear();

    // Now A should have received the ACK - poll to process feedback
    now += 100;
    udpard_tx_poll(&a_tx, now, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_EQUAL_size_t(1, a_topic_fb.count);
    TEST_ASSERT_EQUAL_UINT32(1, a_topic_fb.acknowledgements);

    // ================================================================================================================
    // STEP 4: Node B sends a reliable P2P response to A
    // ================================================================================================================
    udpard_remote_t remote_a{};
    remote_a.uid = b_topic_ctx.sender_uid;
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        remote_a.endpoints[i] = node_a_sources[i];
    }

    const udpard_bytes_scattered_t response_scat  = make_scattered(response_payload.data(), response_payload.size());
    uint64_t                       b_response_tid = 0;
    TEST_ASSERT_TRUE(udpard_tx_push_p2p(&b_tx,
                                        now,
                                        now + 1000000,
                                        udpard_prio_nominal,
                                        remote_a,
                                        response_scat,
                                        &record_feedback,
                                        make_user_context(&b_response_fb),
                                        &b_response_tid));

    b_frames.clear();
    udpard_tx_poll(&b_tx, now, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_FALSE(b_frames.empty());

    // Deliver response frames to A
    for (const auto& frame : b_frames) {
        TEST_ASSERT_TRUE(udpard_rx_port_push(&a_rx,
                                             &a_p2p_port,
                                             now,
                                             node_b_sources[frame.iface_index],
                                             frame.datagram,
                                             tx_payload_deleter,
                                             frame.iface_index));
    }
    udpard_rx_poll(&a_rx, now);
    b_frames.clear();

    // Verify A received the response
    TEST_ASSERT_EQUAL_size_t(1, a_response_ctx.response_count);
    TEST_ASSERT_EQUAL_UINT64(b_response_tid, a_response_ctx.transfer_id);
    TEST_ASSERT_EQUAL_size_t(response_payload.size(), a_response_ctx.received_response.size());
    TEST_ASSERT_EQUAL_MEMORY(response_payload.data(), a_response_ctx.received_response.data(), response_payload.size());

    // ================================================================================================================
    // STEP 5: A sends ACK for the response back to B - via a_tx since a_rx is linked to it
    // ================================================================================================================
    a_frames.clear();
    udpard_tx_poll(&a_tx, now, UDPARD_IFACE_BITMAP_ALL);

    // Deliver ACK frames to B
    for (const auto& frame : a_frames) {
        TEST_ASSERT_TRUE(udpard_rx_port_push(&b_rx,
                                             &b_p2p_port,
                                             now,
                                             node_a_sources[frame.iface_index],
                                             frame.datagram,
                                             tx_payload_deleter,
                                             frame.iface_index));
    }
    udpard_rx_poll(&b_rx, now);
    a_frames.clear();

    // Now B should have received the ACK for the response
    now += 100;
    udpard_tx_poll(&b_tx, now, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_EQUAL_size_t(1, b_response_fb.count);
    TEST_ASSERT_EQUAL_UINT32(1, b_response_fb.acknowledgements);

    // ================================================================================================================
    // CLEANUP
    // ================================================================================================================
    udpard_rx_port_free(&b_rx, &b_topic_port);
    udpard_rx_port_free(&b_rx, &b_p2p_port);
    udpard_rx_port_free(&a_rx, &a_p2p_port);
    udpard_tx_free(&a_tx);
    udpard_tx_free(&b_tx);

    TEST_ASSERT_EQUAL_size_t(0, a_tx_alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, a_tx_alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, a_rx_alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, a_rx_alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, b_tx_alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, b_tx_alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, b_rx_alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, b_rx_alloc_session.allocated_fragments);

    instrumented_allocator_reset(&a_tx_alloc_transfer);
    instrumented_allocator_reset(&a_tx_alloc_payload);
    instrumented_allocator_reset(&a_rx_alloc_frag);
    instrumented_allocator_reset(&a_rx_alloc_session);
    instrumented_allocator_reset(&b_tx_alloc_transfer);
    instrumented_allocator_reset(&b_tx_alloc_payload);
    instrumented_allocator_reset(&b_rx_alloc_frag);
    instrumented_allocator_reset(&b_rx_alloc_session);
}

// --------------------------------------------------------------------------------------------------------------------
// TEST: Topic message and response with simulated losses
// --------------------------------------------------------------------------------------------------------------------

/// Same as above, but with simulated packet loss on both the response and the response ACK.
/// Tests that reliable delivery works correctly with retransmissions.
/// Each node uses exactly one TX and one RX instance.
void test_topic_with_p2p_response_under_loss()
{
    seed_prng();

    // ================================================================================================================
    // ALLOCATORS - One TX and one RX per node
    // ================================================================================================================
    instrumented_allocator_t a_tx_alloc_transfer{};
    instrumented_allocator_t a_tx_alloc_payload{};
    instrumented_allocator_t a_rx_alloc_frag{};
    instrumented_allocator_t a_rx_alloc_session{};
    instrumented_allocator_new(&a_tx_alloc_transfer);
    instrumented_allocator_new(&a_tx_alloc_payload);
    instrumented_allocator_new(&a_rx_alloc_frag);
    instrumented_allocator_new(&a_rx_alloc_session);

    instrumented_allocator_t b_tx_alloc_transfer{};
    instrumented_allocator_t b_tx_alloc_payload{};
    instrumented_allocator_t b_rx_alloc_frag{};
    instrumented_allocator_t b_rx_alloc_session{};
    instrumented_allocator_new(&b_tx_alloc_transfer);
    instrumented_allocator_new(&b_tx_alloc_payload);
    instrumented_allocator_new(&b_rx_alloc_frag);
    instrumented_allocator_new(&b_rx_alloc_session);

    // ================================================================================================================
    // MEMORY RESOURCES
    // ================================================================================================================
    udpard_tx_mem_resources_t a_tx_mem{};
    a_tx_mem.transfer = instrumented_allocator_make_resource(&a_tx_alloc_transfer);
    for (auto& res : a_tx_mem.payload) {
        res = instrumented_allocator_make_resource(&a_tx_alloc_payload);
    }
    const udpard_rx_mem_resources_t a_rx_mem{ .session  = instrumented_allocator_make_resource(&a_rx_alloc_session),
                                              .fragment = instrumented_allocator_make_resource(&a_rx_alloc_frag) };

    udpard_tx_mem_resources_t b_tx_mem{};
    b_tx_mem.transfer = instrumented_allocator_make_resource(&b_tx_alloc_transfer);
    for (auto& res : b_tx_mem.payload) {
        res = instrumented_allocator_make_resource(&b_tx_alloc_payload);
    }
    const udpard_rx_mem_resources_t b_rx_mem{ .session  = instrumented_allocator_make_resource(&b_rx_alloc_session),
                                              .fragment = instrumented_allocator_make_resource(&b_rx_alloc_frag) };

    // ================================================================================================================
    // NODE UIDs AND ENDPOINTS
    // ================================================================================================================
    constexpr uint64_t node_a_uid = 0x1111AAAA2222BBBBULL;
    constexpr uint64_t node_b_uid = 0x3333CCCC4444DDDDULL;

    const std::array<udpard_udpip_ep_t, UDPARD_IFACE_COUNT_MAX> node_a_sources{
        udpard_udpip_ep_t{ .ip = 0x0A000021U, .port = 8400U },
        udpard_udpip_ep_t{},
        udpard_udpip_ep_t{},
    };
    const std::array<udpard_udpip_ep_t, UDPARD_IFACE_COUNT_MAX> node_b_sources{
        udpard_udpip_ep_t{ .ip = 0x0A000031U, .port = 8500U },
        udpard_udpip_ep_t{},
        udpard_udpip_ep_t{},
    };

    constexpr uint64_t transfer_id = 99;

    // ================================================================================================================
    // TX/RX PIPELINES - One TX and one RX per node
    // ================================================================================================================
    udpard_tx_t                a_tx{};
    std::vector<CapturedFrame> a_frames;
    TEST_ASSERT_TRUE(udpard_tx_new(&a_tx, node_a_uid, 100, 64, a_tx_mem, &tx_vtable));
    a_tx.user                 = &a_frames;
    a_tx.ack_baseline_timeout = 8000;

    udpard_rx_t a_rx{};
    udpard_rx_new(&a_rx, &a_tx);
    NodeAResponseContext a_response_ctx{};
    NodeContext          a_node_ctx{ .topic_ctx = nullptr, .response_ctx = &a_response_ctx };
    a_rx.user = &a_node_ctx;

    udpard_rx_port_t a_p2p_port{};
    TEST_ASSERT_TRUE(udpard_rx_port_new_p2p(&a_p2p_port, 4096, a_rx_mem, &p2p_response_callbacks));

    udpard_tx_t                b_tx{};
    std::vector<CapturedFrame> b_frames;
    TEST_ASSERT_TRUE(udpard_tx_new(&b_tx, node_b_uid, 200, 64, b_tx_mem, &tx_vtable));
    b_tx.user                 = &b_frames;
    b_tx.ack_baseline_timeout = 8000;

    udpard_rx_t b_rx{};
    udpard_rx_new(&b_rx, &b_tx);
    NodeBTopicContext b_topic_ctx{};
    NodeContext       b_node_ctx{ .topic_ctx = &b_topic_ctx, .response_ctx = nullptr };
    b_rx.user = &b_node_ctx;

    udpard_rx_port_t b_topic_port{};
    TEST_ASSERT_TRUE(udpard_rx_port_new(&b_topic_port, 4096, b_rx_mem, &topic_callbacks));

    udpard_rx_port_t b_p2p_port{};
    TEST_ASSERT_TRUE(udpard_rx_port_new_p2p(&b_p2p_port, 16, b_rx_mem, &ack_only_callbacks));

    // ================================================================================================================
    // PAYLOADS AND FEEDBACK STATES
    // ================================================================================================================
    const std::vector<uint8_t>     topic_payload      = { 0x10, 0x20, 0x30 };
    const std::vector<uint8_t>     response_payload   = { 0xDE, 0xAD, 0xBE, 0xEF };
    const udpard_bytes_scattered_t topic_payload_scat = make_scattered(topic_payload.data(), topic_payload.size());

    FeedbackState a_topic_fb{};
    FeedbackState b_response_fb{};

    // ================================================================================================================
    // STEP 1: Node A publishes a reliable topic message
    // ================================================================================================================
    udpard_us_t        now            = 0;
    constexpr uint16_t iface_bitmap_1 = (1U << 0U);
    TEST_ASSERT_TRUE(udpard_tx_push(&a_tx,
                                    now,
                                    now + 500000,
                                    iface_bitmap_1,
                                    udpard_prio_fast,
                                    transfer_id,
                                    topic_payload_scat,
                                    &record_feedback,
                                    make_user_context(&a_topic_fb)));

    // ================================================================================================================
    // SIMULATION LOOP WITH LOSSES
    // ================================================================================================================
    size_t           iterations             = 0;
    constexpr size_t max_iterations         = 30;
    bool             first_response_dropped = false;
    bool             first_resp_ack_dropped = false;
    bool             response_sent          = false;
    uint64_t         b_response_tid         = 0;

    while (iterations < max_iterations) {
        iterations++;

        // --- Node A transmits (topic message, topic ACKs, or response ACKs) ---
        a_frames.clear();
        udpard_tx_poll(&a_tx, now, UDPARD_IFACE_BITMAP_ALL);

        for (const auto& frame : a_frames) {
            if (b_topic_ctx.message_count == 0) {
                // Topic message frames go to B's topic port
                (void)udpard_rx_port_push(&b_rx,
                                          &b_topic_port,
                                          now,
                                          node_a_sources[frame.iface_index],
                                          frame.datagram,
                                          tx_payload_deleter,
                                          frame.iface_index);
            } else {
                // Response ACK frames go to B's P2P port
                if (!first_resp_ack_dropped && (a_response_ctx.response_count > 0) && (b_response_fb.count == 0)) {
                    first_resp_ack_dropped = true;
                    drop_frame(frame);
                    continue;
                }

                (void)udpard_rx_port_push(&b_rx,
                                          &b_p2p_port,
                                          now,
                                          node_a_sources[frame.iface_index],
                                          frame.datagram,
                                          tx_payload_deleter,
                                          frame.iface_index);
            }
        }
        a_frames.clear();
        udpard_rx_poll(&b_rx, now);

        // --- Node B transmits (topic ACKs first, before pushing response) ---
        b_frames.clear();
        udpard_tx_poll(&b_tx, now, UDPARD_IFACE_BITMAP_ALL);

        // Deliver B's frames (topic ACKs) to A before pushing response
        for (const auto& frame : b_frames) {
            (void)udpard_rx_port_push(&a_rx,
                                      &a_p2p_port,
                                      now,
                                      node_b_sources[frame.iface_index],
                                      frame.datagram,
                                      tx_payload_deleter,
                                      frame.iface_index);
        }
        b_frames.clear();
        udpard_rx_poll(&a_rx, now);

        // --- If B received topic, send response ---
        if ((b_topic_ctx.message_count > 0) && !response_sent) {
            response_sent = true;

            udpard_remote_t remote_a{};
            remote_a.uid          = b_topic_ctx.sender_uid;
            remote_a.endpoints[0] = node_a_sources[0];

            const udpard_bytes_scattered_t response_scat =
              make_scattered(response_payload.data(), response_payload.size());
            TEST_ASSERT_TRUE(udpard_tx_push_p2p(&b_tx,
                                                now,
                                                now + 500000,
                                                udpard_prio_fast,
                                                remote_a,
                                                response_scat,
                                                &record_feedback,
                                                make_user_context(&b_response_fb),
                                                &b_response_tid));
        }

        // --- Node B transmits (responses) ---
        b_frames.clear();
        udpard_tx_poll(&b_tx, now, UDPARD_IFACE_BITMAP_ALL);

        for (const auto& frame : b_frames) {
            // Check if this frame is an ACK vs response.
            const bool is_ack = is_ack_frame(frame.datagram);

            // Drop first response (non-ACK) to test retransmission.
            if (!first_response_dropped && response_sent && !is_ack) {
                first_response_dropped = true;
                drop_frame(frame);
                continue;
            }

            (void)udpard_rx_port_push(&a_rx,
                                      &a_p2p_port,
                                      now,
                                      node_b_sources[frame.iface_index],
                                      frame.datagram,
                                      tx_payload_deleter,
                                      frame.iface_index);
        }
        b_frames.clear();
        udpard_rx_poll(&a_rx, now);

        // Check if both feedbacks have fired
        if ((a_topic_fb.count > 0) && (b_response_fb.count > 0)) {
            break;
        }

        now += a_tx.ack_baseline_timeout + 5000;
    }

    // ================================================================================================================
    // VERIFY
    // ================================================================================================================
    TEST_ASSERT_LESS_THAN_size_t(max_iterations, iterations);
    TEST_ASSERT_TRUE(first_response_dropped);
    TEST_ASSERT_TRUE(first_resp_ack_dropped);

    TEST_ASSERT_EQUAL_size_t(1, a_topic_fb.count);
    TEST_ASSERT_EQUAL_UINT32(1, a_topic_fb.acknowledgements);

    TEST_ASSERT_EQUAL_size_t(1, b_response_fb.count);
    TEST_ASSERT_EQUAL_UINT32(1, b_response_fb.acknowledgements);

    TEST_ASSERT_GREATER_OR_EQUAL_size_t(1, b_topic_ctx.message_count);
    TEST_ASSERT_EQUAL_size_t(1, a_response_ctx.response_count);
    TEST_ASSERT_EQUAL_UINT64(b_response_tid, a_response_ctx.transfer_id);
    TEST_ASSERT_EQUAL_size_t(response_payload.size(), a_response_ctx.received_response.size());
    TEST_ASSERT_EQUAL_MEMORY(response_payload.data(), a_response_ctx.received_response.data(), response_payload.size());

    // ================================================================================================================
    // CLEANUP
    // ================================================================================================================
    udpard_rx_port_free(&b_rx, &b_topic_port);
    udpard_rx_port_free(&b_rx, &b_p2p_port);
    udpard_rx_port_free(&a_rx, &a_p2p_port);
    udpard_tx_free(&a_tx);
    udpard_tx_free(&b_tx);

    TEST_ASSERT_EQUAL_size_t(0, a_tx_alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, a_tx_alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, a_rx_alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, a_rx_alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, b_tx_alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, b_tx_alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, b_rx_alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, b_rx_alloc_session.allocated_fragments);

    instrumented_allocator_reset(&a_tx_alloc_transfer);
    instrumented_allocator_reset(&a_tx_alloc_payload);
    instrumented_allocator_reset(&a_rx_alloc_frag);
    instrumented_allocator_reset(&a_rx_alloc_session);
    instrumented_allocator_reset(&b_tx_alloc_transfer);
    instrumented_allocator_reset(&b_tx_alloc_payload);
    instrumented_allocator_reset(&b_rx_alloc_frag);
    instrumented_allocator_reset(&b_rx_alloc_session);
}

} // namespace

extern "C" void setUp() {}

extern "C" void tearDown() {}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_topic_with_p2p_response);
    RUN_TEST(test_topic_with_p2p_response_under_loss);
    return UNITY_END();
}
