/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT
/// This test validates reliable delivery with ORDERED mode under packet loss and reordering.

#include <udpard.h>
#include "helpers.h"
#include <unity.h>
#include <array>
#include <vector>

namespace {

constexpr size_t CyphalHeaderSize = 48; // Cyphal/UDP header size

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

constexpr udpard_deleter_vtable_t tx_refcount_deleter_vt{ .free = &tx_refcount_free };
constexpr udpard_deleter_t        tx_payload_deleter{ .vtable = &tx_refcount_deleter_vt, .context = nullptr };

void drop_frame(const CapturedFrame& frame)
{
    udpard_tx_refcount_dec(udpard_bytes_t{ .size = frame.datagram.size, .data = frame.datagram.data });
}

// Extract transfer_id from Cyphal/UDP header (bytes 16-23 of datagram).
uint64_t extract_transfer_id(const udpard_bytes_mut_t& datagram)
{
    if (datagram.size < 24) {
        return 0;
    }
    const auto* p   = static_cast<const uint8_t*>(datagram.data);
    uint64_t    tid = 0;
    for (size_t i = 0; i < 8; i++) {
        tid |= static_cast<uint64_t>(p[16 + i]) << (i * 8U);
    }
    return tid;
}

// Extract the transfer_id being ACKed from P2P header in payload.
// P2P header format: kind(1) + reserved(7) + topic_hash(8) + transfer_id(8)
// Starts at byte 48 (after Cyphal header), so transfer_id is at bytes 64-71.
uint64_t extract_acked_transfer_id(const udpard_bytes_mut_t& datagram)
{
    constexpr size_t p2p_tid_offset = CyphalHeaderSize + 16;
    if (datagram.size < p2p_tid_offset + 8) {
        return 0;
    }
    const auto* p   = static_cast<const uint8_t*>(datagram.data);
    uint64_t    tid = 0;
    for (size_t i = 0; i < 8; i++) {
        tid |= static_cast<uint64_t>(p[p2p_tid_offset + i]) << (i * 8U);
    }
    return tid;
}

bool capture_tx_frame_impl(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection)
{
    auto* frames = static_cast<std::vector<CapturedFrame>*>(tx->user);
    if (frames == nullptr) {
        return false;
    }
    udpard_tx_refcount_inc(ejection->datagram);
    void* const              data = const_cast<void*>(ejection->datagram.data); // NOLINT
    const udpard_bytes_mut_t dgram{ .size = ejection->datagram.size, .data = data };
    frames->push_back(CapturedFrame{ .datagram = dgram, .iface_index = ejection->iface_index });
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

struct FeedbackState
{
    size_t   count            = 0;
    uint16_t acknowledgements = 0;
    uint64_t topic_hash       = 0;
    uint64_t transfer_id      = 0;
};

void record_feedback(udpard_tx_t*, const udpard_tx_feedback_t fb)
{
    auto* st = static_cast<FeedbackState*>(fb.user.ptr[0]);
    if (st != nullptr) {
        st->count++;
        st->acknowledgements = fb.acknowledgements;
        st->topic_hash       = fb.topic_hash;
        st->transfer_id      = fb.transfer_id;
    }
}

struct ReceiverContext
{
    std::vector<uint64_t> received_transfer_ids;
};

void on_message(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    auto* ctx = static_cast<ReceiverContext*>(rx->user);
    ctx->received_transfer_ids.push_back(transfer.transfer_id);
    udpard_fragment_free_all(transfer.payload, udpard_make_deleter(port->memory.fragment));
}

void on_collision(udpard_rx_t*, udpard_rx_port_t*, udpard_remote_t) {}

constexpr udpard_rx_port_vtable_t topic_callbacks{ .on_message = &on_message, .on_collision = &on_collision };

void on_ack_only(udpard_rx_t*, udpard_rx_port_p2p_t* port, const udpard_rx_transfer_p2p_t tr)
{
    udpard_fragment_free_all(tr.base.payload, udpard_make_deleter(port->base.memory.fragment));
}

constexpr udpard_rx_port_p2p_vtable_t ack_only_callbacks{ .on_message = &on_ack_only };

/// Test scenario:
/// - Sender publishes messages A, B, C (tid=100, 101, 102) in reliable mode, in quick succession.
/// - A is delivered successfully, establishing the session baseline for the receiver in ORDERED mode.
/// - First attempt to deliver B fails (lost).
/// - Every first ACK for B and C is lost, forcing sender to retransmit.
///
/// The receiver first sees A, then C (tid=102), which gets interned waiting for lower transfer IDs.
/// When B (tid=101) arrives via retransmission, it gets delivered first, then C is ejected in order.
///
/// Transmission sequence:
///   1. A (tid=100) delivered successfully -- establishes ordered session
///   2. B (tid=101) lost
///   3. C (tid=102) delivered but ACK lost -- interned, waiting for tid < 102
///   4. B (tid=101) delivered but ACK lost -- delivered first, then C ejected
///   5. C (tid=102) re-delivered, duplicate ignored, ACK delivered
///   6. B (tid=101) re-delivered, duplicate ignored, ACK delivered
///
/// Receiver must validate: receives A, then B, then C, in correct order without duplicates.
void test_reliable_ordered_with_loss_and_reordering()
{
    seed_prng();

    // Allocators
    instrumented_allocator_t sender_tx_alloc_transfer{};
    instrumented_allocator_t sender_tx_alloc_payload{};
    instrumented_allocator_t receiver_rx_alloc_frag{};
    instrumented_allocator_t receiver_rx_alloc_session{};
    instrumented_allocator_t receiver_tx_alloc_transfer{};
    instrumented_allocator_t receiver_tx_alloc_payload{};
    instrumented_allocator_t sender_rx_alloc_frag{};
    instrumented_allocator_t sender_rx_alloc_session{};
    instrumented_allocator_new(&sender_tx_alloc_transfer);
    instrumented_allocator_new(&sender_tx_alloc_payload);
    instrumented_allocator_new(&receiver_rx_alloc_frag);
    instrumented_allocator_new(&receiver_rx_alloc_session);
    instrumented_allocator_new(&receiver_tx_alloc_transfer);
    instrumented_allocator_new(&receiver_tx_alloc_payload);
    instrumented_allocator_new(&sender_rx_alloc_frag);
    instrumented_allocator_new(&sender_rx_alloc_session);

    // Memory resources
    udpard_tx_mem_resources_t sender_tx_mem{};
    sender_tx_mem.transfer = instrumented_allocator_make_resource(&sender_tx_alloc_transfer);
    for (auto& res : sender_tx_mem.payload) {
        res = instrumented_allocator_make_resource(&sender_tx_alloc_payload);
    }
    const udpard_rx_mem_resources_t sender_rx_mem{ .session =
                                                     instrumented_allocator_make_resource(&sender_rx_alloc_session),
                                                   .fragment =
                                                     instrumented_allocator_make_resource(&sender_rx_alloc_frag) };

    udpard_tx_mem_resources_t receiver_tx_mem{};
    receiver_tx_mem.transfer = instrumented_allocator_make_resource(&receiver_tx_alloc_transfer);
    for (auto& res : receiver_tx_mem.payload) {
        res = instrumented_allocator_make_resource(&receiver_tx_alloc_payload);
    }
    const udpard_rx_mem_resources_t receiver_rx_mem{ .session =
                                                       instrumented_allocator_make_resource(&receiver_rx_alloc_session),
                                                     .fragment =
                                                       instrumented_allocator_make_resource(&receiver_rx_alloc_frag) };

    // Node identifiers
    constexpr uint64_t      sender_uid   = 0xAAAA1111BBBB2222ULL;
    constexpr uint64_t      receiver_uid = 0xCCCC3333DDDD4444ULL;
    const udpard_udpip_ep_t sender_source{ .ip = 0x0A000001U, .port = 7400U };
    const udpard_udpip_ep_t receiver_source{ .ip = 0x0A000011U, .port = 7500U };
    constexpr uint64_t      topic_hash     = 0x0123456789ABCDEFULL;
    constexpr uint64_t      tid_a          = 100;
    constexpr uint64_t      tid_b          = 101;
    constexpr uint64_t      tid_c          = 102;
    constexpr uint16_t      iface_bitmap_1 = (1U << 0U);

    // Use a large reordering window to ensure retransmissions arrive within the window.
    // With exponential backoff, retransmissions can take significant time.
    constexpr udpard_us_t reordering_window = 1000000; // 1 second
    constexpr udpard_us_t ack_timeout       = 10000;   // 10ms baseline

    // Sender TX/RX
    udpard_tx_t                sender_tx{};
    std::vector<CapturedFrame> sender_frames;
    TEST_ASSERT_TRUE(udpard_tx_new(&sender_tx, sender_uid, 100, 64, sender_tx_mem, &tx_vtable));
    sender_tx.user                 = &sender_frames;
    sender_tx.ack_baseline_timeout = ack_timeout;

    udpard_rx_t sender_rx{};
    udpard_rx_new(&sender_rx, &sender_tx);

    udpard_rx_port_p2p_t sender_p2p_port{};
    TEST_ASSERT_TRUE(udpard_rx_port_new_p2p(
      &sender_p2p_port, sender_uid, UDPARD_P2P_HEADER_BYTES, sender_rx_mem, &ack_only_callbacks));

    // Receiver TX/RX
    udpard_tx_t                receiver_tx{};
    std::vector<CapturedFrame> receiver_frames;
    TEST_ASSERT_TRUE(udpard_tx_new(&receiver_tx, receiver_uid, 200, 64, receiver_tx_mem, &tx_vtable));
    receiver_tx.user                 = &receiver_frames;
    receiver_tx.ack_baseline_timeout = ack_timeout;

    udpard_rx_t     receiver_rx{};
    ReceiverContext receiver_ctx{};
    udpard_rx_new(&receiver_rx, &receiver_tx);
    receiver_rx.user = &receiver_ctx;

    udpard_rx_port_t receiver_topic_port{};
    TEST_ASSERT_TRUE(udpard_rx_port_new(
      &receiver_topic_port, topic_hash, 4096, udpard_rx_ordered, reordering_window, receiver_rx_mem, &topic_callbacks));

    // Payloads
    const std::array<uint8_t, 4> payload_a{ 0xAA, 0xAA, 0xAA, 0xAA };
    const std::array<uint8_t, 4> payload_b{ 0xBB, 0xBB, 0xBB, 0xBB };
    const std::array<uint8_t, 4> payload_c{ 0xCC, 0xCC, 0xCC, 0xCC };

    // Feedback states
    FeedbackState fb_a{};
    FeedbackState fb_b{};
    FeedbackState fb_c{};

    udpard_us_t       now      = 0;
    const udpard_us_t deadline = now + 2000000; // 2 second deadline

    // Step 1: Send transfer A that is delivered successfully (establishes the session baseline).
    TEST_ASSERT_TRUE(udpard_tx_push(&sender_tx,
                                    now,
                                    deadline,
                                    iface_bitmap_1,
                                    udpard_prio_nominal,
                                    topic_hash,
                                    tid_a,
                                    make_scattered(payload_a.data(), payload_a.size()),
                                    &record_feedback,
                                    make_user_context(&fb_a)));

    // Deliver A
    sender_frames.clear();
    udpard_tx_poll(&sender_tx, now, UDPARD_IFACE_BITMAP_ALL);
    for (const auto& frame : sender_frames) {
        TEST_ASSERT_TRUE(udpard_rx_port_push(&receiver_rx,
                                             &receiver_topic_port,
                                             now,
                                             sender_source,
                                             frame.datagram,
                                             tx_payload_deleter,
                                             frame.iface_index));
    }
    sender_frames.clear();
    udpard_rx_poll(&receiver_rx, now);

    // Deliver A's ACK back to sender
    receiver_frames.clear();
    udpard_tx_poll(&receiver_tx, now, UDPARD_IFACE_BITMAP_ALL);
    for (const auto& frame : receiver_frames) {
        TEST_ASSERT_TRUE(udpard_rx_port_push(&sender_rx,
                                             reinterpret_cast<udpard_rx_port_t*>(&sender_p2p_port),
                                             now,
                                             receiver_source,
                                             frame.datagram,
                                             tx_payload_deleter,
                                             frame.iface_index));
    }
    receiver_frames.clear();
    udpard_rx_poll(&sender_rx, now);

    // Verify A was received
    TEST_ASSERT_EQUAL_size_t(1, receiver_ctx.received_transfer_ids.size());
    TEST_ASSERT_EQUAL_UINT64(tid_a, receiver_ctx.received_transfer_ids[0]);
    TEST_ASSERT_EQUAL_size_t(1, fb_a.count);
    TEST_ASSERT_EQUAL_UINT32(1, fb_a.acknowledgements);

    // Step 2: Push transfers B and C
    TEST_ASSERT_TRUE(udpard_tx_push(&sender_tx,
                                    now,
                                    deadline,
                                    iface_bitmap_1,
                                    udpard_prio_nominal,
                                    topic_hash,
                                    tid_b,
                                    make_scattered(payload_b.data(), payload_b.size()),
                                    &record_feedback,
                                    make_user_context(&fb_b)));

    TEST_ASSERT_TRUE(udpard_tx_push(&sender_tx,
                                    now,
                                    deadline,
                                    iface_bitmap_1,
                                    udpard_prio_nominal,
                                    topic_hash,
                                    tid_c,
                                    make_scattered(payload_c.data(), payload_c.size()),
                                    &record_feedback,
                                    make_user_context(&fb_c)));

    // Simulation state tracking
    bool             b_first_tx_dropped  = false;
    bool             c_first_tx_done     = false;
    bool             b_first_ack_dropped = false;
    bool             c_first_ack_dropped = false;
    size_t           iterations          = 0;
    constexpr size_t max_iterations      = 100;

    // Main simulation loop
    while (iterations < max_iterations) {
        iterations++;

        // Sender transmits frames
        sender_frames.clear();
        udpard_tx_poll(&sender_tx, now, UDPARD_IFACE_BITMAP_ALL);

        for (const auto& frame : sender_frames) {
            const uint64_t tid = extract_transfer_id(frame.datagram);

            // First transmission of B is lost
            if ((tid == tid_b) && !b_first_tx_dropped) {
                b_first_tx_dropped = true;
                drop_frame(frame);
                continue;
            }

            // Track first transmission of C
            if ((tid == tid_c) && !c_first_tx_done) {
                c_first_tx_done = true;
            }

            // Deliver frame to receiver
            TEST_ASSERT_TRUE(udpard_rx_port_push(&receiver_rx,
                                                 &receiver_topic_port,
                                                 now,
                                                 sender_source,
                                                 frame.datagram,
                                                 tx_payload_deleter,
                                                 frame.iface_index));
        }
        sender_frames.clear();
        udpard_rx_poll(&receiver_rx, now);

        // Receiver transmits ACKs
        receiver_frames.clear();
        udpard_tx_poll(&receiver_tx, now, UDPARD_IFACE_BITMAP_ALL);

        for (const auto& frame : receiver_frames) {
            const uint64_t acked_tid = extract_acked_transfer_id(frame.datagram);

            // First ACK for B is lost
            if ((acked_tid == tid_b) && !b_first_ack_dropped) {
                b_first_ack_dropped = true;
                drop_frame(frame);
                continue;
            }

            // First ACK for C is lost
            if ((acked_tid == tid_c) && !c_first_ack_dropped) {
                c_first_ack_dropped = true;
                drop_frame(frame);
                continue;
            }

            // Deliver ACK to sender
            TEST_ASSERT_TRUE(udpard_rx_port_push(&sender_rx,
                                                 reinterpret_cast<udpard_rx_port_t*>(&sender_p2p_port),
                                                 now,
                                                 receiver_source,
                                                 frame.datagram,
                                                 tx_payload_deleter,
                                                 frame.iface_index));
        }
        receiver_frames.clear();
        udpard_rx_poll(&sender_rx, now);

        // Check termination condition: both B and C feedbacks received
        if ((fb_b.count > 0) && (fb_c.count > 0)) {
            break;
        }

        // Advance time to trigger retransmission (2x baseline timeout)
        now += ack_timeout * 2;
    }

    // Wait for reordering window to close and eject pending transfers
    now += reordering_window + 10000;
    udpard_rx_poll(&receiver_rx, now);

    // Verify the simulation exercised all loss paths
    TEST_ASSERT_TRUE(b_first_tx_dropped);
    TEST_ASSERT_TRUE(c_first_tx_done);
    TEST_ASSERT_TRUE(b_first_ack_dropped);
    TEST_ASSERT_TRUE(c_first_ack_dropped);
    TEST_ASSERT_LESS_THAN_size_t(max_iterations, iterations);

    // Verify sender received ACKs for all transfers
    TEST_ASSERT_EQUAL_size_t(1, fb_b.count);
    TEST_ASSERT_EQUAL_UINT32(1, fb_b.acknowledgements);
    TEST_ASSERT_EQUAL_UINT64(topic_hash, fb_b.topic_hash);
    TEST_ASSERT_EQUAL_UINT64(tid_b, fb_b.transfer_id);

    TEST_ASSERT_EQUAL_size_t(1, fb_c.count);
    TEST_ASSERT_EQUAL_UINT32(1, fb_c.acknowledgements);
    TEST_ASSERT_EQUAL_UINT64(topic_hash, fb_c.topic_hash);
    TEST_ASSERT_EQUAL_UINT64(tid_c, fb_c.transfer_id);

    // CRITICAL: Verify receiver got exactly 3 transfers in correct order: A, B, then C
    // This validates that ORDERED mode correctly reorders out-of-order arrivals.
    TEST_ASSERT_EQUAL_size_t(3, receiver_ctx.received_transfer_ids.size());
    TEST_ASSERT_EQUAL_UINT64(tid_a, receiver_ctx.received_transfer_ids[0]);
    TEST_ASSERT_EQUAL_UINT64(tid_b, receiver_ctx.received_transfer_ids[1]);
    TEST_ASSERT_EQUAL_UINT64(tid_c, receiver_ctx.received_transfer_ids[2]);

    // Cleanup
    udpard_rx_port_free(&receiver_rx, &receiver_topic_port);
    udpard_rx_port_free(&sender_rx, reinterpret_cast<udpard_rx_port_t*>(&sender_p2p_port));
    udpard_tx_free(&sender_tx);
    udpard_tx_free(&receiver_tx);

    TEST_ASSERT_EQUAL_size_t(0, sender_tx_alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, sender_tx_alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, sender_rx_alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, sender_rx_alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, receiver_tx_alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, receiver_tx_alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, receiver_rx_alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, receiver_rx_alloc_session.allocated_fragments);

    instrumented_allocator_reset(&sender_tx_alloc_transfer);
    instrumented_allocator_reset(&sender_tx_alloc_payload);
    instrumented_allocator_reset(&sender_rx_alloc_frag);
    instrumented_allocator_reset(&sender_rx_alloc_session);
    instrumented_allocator_reset(&receiver_tx_alloc_transfer);
    instrumented_allocator_reset(&receiver_tx_alloc_payload);
    instrumented_allocator_reset(&receiver_rx_alloc_frag);
    instrumented_allocator_reset(&receiver_rx_alloc_session);
}

} // namespace

extern "C" void setUp() {}

extern "C" void tearDown() {}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_reliable_ordered_with_loss_and_reordering);
    return UNITY_END();
}
