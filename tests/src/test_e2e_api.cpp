/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.h>
#include "helpers.h"
#include <unity.h>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

struct CapturedFrame
{
    std::vector<uint8_t> bytes;
    uint_fast8_t         iface_index = 0;
    udpard_udpip_ep_t    destination{};
};

struct RxState
{
    std::size_t          count;
    uint64_t             transfer_id;
    std::vector<uint8_t> payload;
    udpard_remote_t      remote;
};

// Captures each ejected datagram for manual delivery to RX.
bool capture_tx(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection)
{
    auto* out = static_cast<std::vector<CapturedFrame>*>(tx->user);
    if (out == nullptr) {
        return false;
    }
    CapturedFrame frame{};
    frame.bytes.assign(static_cast<const uint8_t*>(ejection->datagram.data),
                       static_cast<const uint8_t*>(ejection->datagram.data) + ejection->datagram.size);
    frame.iface_index = ejection->iface_index;
    frame.destination = ejection->destination;
    out->push_back(frame);
    return true;
}

constexpr udpard_tx_vtable_t tx_vtable{ .eject = &capture_tx };

// Collects the received transfer and frees its fragment tree.
void on_message(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    auto* st = static_cast<RxState*>(rx->user);
    TEST_ASSERT_NOT_NULL(st);
    st->count++;
    st->transfer_id = transfer.transfer_id;
    st->remote      = transfer.remote;
    st->payload.resize(transfer.payload_size_stored);
    const udpard_fragment_t* cursor = transfer.payload;
    (void)udpard_fragment_gather(&cursor, 0, transfer.payload_size_stored, st->payload.data());
    udpard_fragment_free_all(transfer.payload, udpard_make_deleter(port->memory.fragment));
}

constexpr udpard_rx_port_vtable_t rx_vtable{ .on_message = &on_message };

// Allocates and sends one captured frame into RX.
void deliver_frame(const CapturedFrame&    frame,
                   const udpard_mem_t      mem,
                   const udpard_deleter_t  del,
                   udpard_rx_t* const      rx,
                   udpard_rx_port_t* const port,
                   const udpard_us_t       ts,
                   const udpard_udpip_ep_t source)
{
    void* const dgram = mem_res_alloc(mem, frame.bytes.size());
    TEST_ASSERT_NOT_NULL(dgram);
    (void)memcpy(dgram, frame.bytes.data(), frame.bytes.size());
    TEST_ASSERT_TRUE(udpard_rx_port_push(
      rx, port, ts, source, udpard_bytes_mut_t{ .size = frame.bytes.size(), .data = dgram }, del, frame.iface_index));
}

void test_subject_roundtrip()
{
    seed_prng();

    // Configure TX fixture with captured ejections.
    instrumented_allocator_t tx_alloc_transfer{};
    instrumented_allocator_t tx_alloc_payload{};
    instrumented_allocator_new(&tx_alloc_transfer);
    instrumented_allocator_new(&tx_alloc_payload);
    udpard_tx_mem_resources_t tx_mem{};
    tx_mem.transfer = instrumented_allocator_make_resource(&tx_alloc_transfer);
    for (auto& res : tx_mem.payload) {
        res = instrumented_allocator_make_resource(&tx_alloc_payload);
    }
    udpard_tx_t tx{};
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x1010101010101010ULL, 123U, 32U, tx_mem, &tx_vtable));
    tx.mtu[0] = 256U;
    tx.mtu[1] = 256U;
    tx.mtu[2] = 256U;
    std::vector<CapturedFrame> frames;
    tx.user = &frames;

    // Configure RX fixture.
    instrumented_allocator_t rx_alloc_session{};
    instrumented_allocator_t rx_alloc_fragment{};
    instrumented_allocator_new(&rx_alloc_session);
    instrumented_allocator_new(&rx_alloc_fragment);
    const udpard_rx_mem_resources_t rx_mem{
        .session  = instrumented_allocator_make_resource(&rx_alloc_session),
        .slot     = instrumented_allocator_make_resource(&rx_alloc_session),
        .fragment = instrumented_allocator_make_resource(&rx_alloc_fragment),
    };
    const udpard_deleter_t del = instrumented_allocator_make_deleter(&rx_alloc_fragment);
    udpard_rx_t            rx{};
    udpard_rx_port_t       port{};
    RxState                state{};
    udpard_rx_new(&rx, nullptr);
    rx.user = &state;
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 1024U, rx_mem, &rx_vtable));

    // Send one multi-frame transfer over two interfaces.
    std::vector<uint8_t> payload(300U);
    for (std::size_t i = 0; i < payload.size(); i++) {
        payload[i] = static_cast<uint8_t>(i);
    }
    const udpard_udpip_ep_t destination = udpard_make_subject_endpoint(1234U);
    TEST_ASSERT_TRUE(udpard_tx_push_native(&tx,
                                           1000,
                                           100000,
                                           (1U << 0U) | (1U << 1U),
                                           udpard_prio_nominal,
                                           55U,
                                           destination,
                                           make_scattered(payload.data(), payload.size()),
                                           nullptr));
    udpard_tx_poll(&tx, 1001, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_TRUE(!frames.empty());

    // Deliver the first interface copy only.
    for (const auto& frame : frames) {
        if (frame.iface_index == 0U) {
            deliver_frame(
              frame, rx_mem.fragment, del, &rx, &port, 2000, udpard_udpip_ep_t{ .ip = 0x0A000001U, .port = 9382U });
        }
    }
    udpard_rx_poll(&rx, 3000);

    // Validate the received transfer.
    TEST_ASSERT_EQUAL_size_t(1, state.count);
    TEST_ASSERT_EQUAL_UINT64(55U, state.transfer_id);
    TEST_ASSERT_EQUAL_size_t(payload.size(), state.payload.size());
    TEST_ASSERT_EQUAL_MEMORY(payload.data(), state.payload.data(), payload.size());
    TEST_ASSERT_EQUAL_UINT64(0x1010101010101010ULL, state.remote.uid);

    // Release all resources.
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
    RUN_TEST(test_subject_roundtrip);
    return UNITY_END();
}
