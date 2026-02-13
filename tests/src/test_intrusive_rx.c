/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c> // NOLINT(bugprone-suspicious-include)
#include "helpers.h"
#include <unity.h>
#include <string.h>

typedef struct
{
    size_t          count;
    uint64_t        transfer_id;
    size_t          payload_size;
    byte_t          payload[256];
    udpard_remote_t remote;
} capture_t;

// Captures one transfer and frees its payload tree immediately.
static void on_message(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    capture_t* const cap = (capture_t*)rx->user;
    TEST_ASSERT_NOT_NULL(cap);
    cap->count++;
    cap->transfer_id  = transfer.transfer_id;
    cap->payload_size = transfer.payload_size_stored;
    cap->remote       = transfer.remote;
    if (transfer.payload_size_stored > 0U) {
        const udpard_fragment_t* cursor = transfer.payload;
        TEST_ASSERT_EQUAL_size_t(transfer.payload_size_stored,
                                 udpard_fragment_gather(&cursor, 0, transfer.payload_size_stored, cap->payload));
    }
    udpard_fragment_free_all(transfer.payload, udpard_make_deleter(port->memory.fragment));
}

static const udpard_rx_port_vtable_t callbacks = { .on_message = on_message };

// Builds a valid datagram in allocator-backed memory.
static udpard_bytes_mut_t make_datagram(const udpard_mem_t  mem,
                                        const udpard_prio_t prio,
                                        const uint64_t      transfer_id,
                                        const uint64_t      sender_uid,
                                        const size_t        offset,
                                        const void* const   payload,
                                        const size_t        payload_size)
{
    const size_t  total_size = HEADER_SIZE_BYTES + payload_size;
    byte_t* const data       = mem_res_alloc(mem, total_size);
    TEST_ASSERT_NOT_NULL(data);
    if (payload_size > 0U) {
        (void)memcpy(&data[HEADER_SIZE_BYTES], payload, payload_size);
    }
    const meta_t meta = {
        .priority              = prio,
        .transfer_payload_size = (uint32_t)(offset + payload_size),
        .transfer_id           = transfer_id,
        .sender_uid            = sender_uid,
    };
    const uint32_t prefix_crc = crc_full(offset + payload_size, &data[HEADER_SIZE_BYTES - offset]);
    (void)header_serialize(data, meta, (uint32_t)offset, prefix_crc);
    return (udpard_bytes_mut_t){ .size = total_size, .data = data };
}

static void test_rx_single_frame(void)
{
    // Prepare RX and allocators.
    instrumented_allocator_t alloc_rx_frag = { 0 };
    instrumented_allocator_t alloc_rx_ses  = { 0 };
    instrumented_allocator_t alloc_dgram   = { 0 };
    instrumented_allocator_new(&alloc_rx_frag);
    instrumented_allocator_new(&alloc_rx_ses);
    instrumented_allocator_new(&alloc_dgram);
    const udpard_rx_mem_resources_t rx_mem = {
        .session  = instrumented_allocator_make_resource(&alloc_rx_ses),
        .slot     = instrumented_allocator_make_resource(&alloc_rx_ses),
        .fragment = instrumented_allocator_make_resource(&alloc_rx_frag),
    };
    const udpard_mem_t     dgram_mem = instrumented_allocator_make_resource(&alloc_dgram);
    const udpard_deleter_t dgram_del = instrumented_allocator_make_deleter(&alloc_dgram);

    // Create RX and one normal port.
    capture_t        cap  = { 0 };
    udpard_rx_t      rx   = { 0 };
    udpard_rx_port_t port = { 0 };
    udpard_rx_new(&rx);
    rx.user = &cap;
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 1024U, rx_mem, &callbacks));

    // Push one valid single-frame transfer.
    static const byte_t      payload[] = { 1, 2, 3, 4, 5 };
    const udpard_bytes_mut_t dgram =
      make_datagram(dgram_mem, udpard_prio_high, 42U, 0x1122334455667788ULL, 0U, payload, sizeof(payload));
    TEST_ASSERT_TRUE(udpard_rx_port_push(
      &rx, &port, 1000, (udpard_udpip_ep_t){ .ip = 0x0A000001U, .port = 7000U }, dgram, dgram_del, 0U));
    udpard_rx_poll(&rx, 1001);

    // Verify callback output and no memory leaks.
    TEST_ASSERT_EQUAL_size_t(1, cap.count);
    TEST_ASSERT_EQUAL_UINT64(42U, cap.transfer_id);
    TEST_ASSERT_EQUAL_size_t(sizeof(payload), cap.payload_size);
    TEST_ASSERT_EQUAL_MEMORY(payload, cap.payload, sizeof(payload));
    TEST_ASSERT_EQUAL_size_t(0, alloc_dgram.allocated_fragments);

    // Tear down and validate allocator state.
    udpard_rx_port_free(&rx, &port);
    TEST_ASSERT_EQUAL_size_t(0, alloc_rx_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_rx_ses.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_dgram.allocated_fragments);
    instrumented_allocator_reset(&alloc_rx_frag);
    instrumented_allocator_reset(&alloc_rx_ses);
    instrumented_allocator_reset(&alloc_dgram);
}

static void test_rx_duplicate_rejected_and_freed(void)
{
    // Prepare RX and allocators.
    instrumented_allocator_t alloc_rx_frag = { 0 };
    instrumented_allocator_t alloc_rx_ses  = { 0 };
    instrumented_allocator_t alloc_dgram   = { 0 };
    instrumented_allocator_new(&alloc_rx_frag);
    instrumented_allocator_new(&alloc_rx_ses);
    instrumented_allocator_new(&alloc_dgram);
    const udpard_rx_mem_resources_t rx_mem = {
        .session  = instrumented_allocator_make_resource(&alloc_rx_ses),
        .slot     = instrumented_allocator_make_resource(&alloc_rx_ses),
        .fragment = instrumented_allocator_make_resource(&alloc_rx_frag),
    };
    const udpard_mem_t     dgram_mem = instrumented_allocator_make_resource(&alloc_dgram);
    const udpard_deleter_t dgram_del = instrumented_allocator_make_deleter(&alloc_dgram);

    // Create RX and one normal port.
    capture_t        cap  = { 0 };
    udpard_rx_t      rx   = { 0 };
    udpard_rx_port_t port = { 0 };
    udpard_rx_new(&rx);
    rx.user = &cap;
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 1024U, rx_mem, &callbacks));

    // Deliver the first transfer.
    static const byte_t      payload_a[] = { 9, 8, 7 };
    const udpard_bytes_mut_t first =
      make_datagram(dgram_mem, udpard_prio_nominal, 7U, 0xAABBCCDDEEFF0011ULL, 0U, payload_a, sizeof(payload_a));
    TEST_ASSERT_TRUE(udpard_rx_port_push(
      &rx, &port, 2000, (udpard_udpip_ep_t){ .ip = 0x0A000002U, .port = 7100U }, first, dgram_del, 0U));
    udpard_rx_poll(&rx, 2001);
    TEST_ASSERT_EQUAL_size_t(1, cap.count);
    TEST_ASSERT_EQUAL_size_t(0, alloc_dgram.allocated_fragments);

    // Deliver the same transfer-ID again; it must be dropped and freed.
    static const byte_t      payload_b[] = { 1, 1, 1 };
    const udpard_bytes_mut_t duplicate =
      make_datagram(dgram_mem, udpard_prio_nominal, 7U, 0xAABBCCDDEEFF0011ULL, 0U, payload_b, sizeof(payload_b));
    TEST_ASSERT_TRUE(udpard_rx_port_push(
      &rx, &port, 2010, (udpard_udpip_ep_t){ .ip = 0x0A000002U, .port = 7100U }, duplicate, dgram_del, 0U));
    udpard_rx_poll(&rx, 2011);
    TEST_ASSERT_EQUAL_size_t(1, cap.count);
    TEST_ASSERT_EQUAL_size_t(0, alloc_dgram.allocated_fragments);

    // Tear down and validate allocator state.
    udpard_rx_port_free(&rx, &port);
    TEST_ASSERT_EQUAL_size_t(0, alloc_rx_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_rx_ses.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_dgram.allocated_fragments);
    instrumented_allocator_reset(&alloc_rx_frag);
    instrumented_allocator_reset(&alloc_rx_ses);
    instrumented_allocator_reset(&alloc_dgram);
}

static void test_rx_malformed_frame(void)
{
    // Prepare RX and allocators.
    instrumented_allocator_t alloc_rx_frag = { 0 };
    instrumented_allocator_t alloc_rx_ses  = { 0 };
    instrumented_allocator_t alloc_dgram   = { 0 };
    instrumented_allocator_new(&alloc_rx_frag);
    instrumented_allocator_new(&alloc_rx_ses);
    instrumented_allocator_new(&alloc_dgram);
    const udpard_rx_mem_resources_t rx_mem = {
        .session  = instrumented_allocator_make_resource(&alloc_rx_ses),
        .slot     = instrumented_allocator_make_resource(&alloc_rx_ses),
        .fragment = instrumented_allocator_make_resource(&alloc_rx_frag),
    };
    const udpard_mem_t     dgram_mem = instrumented_allocator_make_resource(&alloc_dgram);
    const udpard_deleter_t dgram_del = instrumented_allocator_make_deleter(&alloc_dgram);

    // Create RX and one normal port.
    capture_t        cap  = { 0 };
    udpard_rx_t      rx   = { 0 };
    udpard_rx_port_t port = { 0 };
    udpard_rx_new(&rx);
    rx.user = &cap;
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 1024U, rx_mem, &callbacks));

    // Corrupt the header CRC and ensure the frame is rejected.
    static const byte_t payload[] = { 0xAA, 0xBB };
    udpard_bytes_mut_t  dgram =
      make_datagram(dgram_mem, udpard_prio_low, 99U, 0x123456789ABCDEF0ULL, 0U, payload, sizeof(payload));
    ((byte_t*)dgram.data)[HEADER_SIZE_BYTES - 1U] ^= 0x5AU;
    const uint64_t malformed_before = rx.errors_frame_malformed;
    TEST_ASSERT_TRUE(udpard_rx_port_push(
      &rx, &port, 3000, (udpard_udpip_ep_t){ .ip = 0x0A000003U, .port = 7200U }, dgram, dgram_del, 0U));
    TEST_ASSERT_EQUAL_UINT64(malformed_before + 1U, rx.errors_frame_malformed);
    TEST_ASSERT_EQUAL_size_t(0, cap.count);
    TEST_ASSERT_EQUAL_size_t(0, alloc_dgram.allocated_fragments);

    // Tear down and validate allocator state.
    udpard_rx_port_free(&rx, &port);
    TEST_ASSERT_EQUAL_size_t(0, alloc_rx_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_rx_ses.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_dgram.allocated_fragments);
    instrumented_allocator_reset(&alloc_rx_frag);
    instrumented_allocator_reset(&alloc_rx_ses);
    instrumented_allocator_reset(&alloc_dgram);
}

static void test_rx_p2p_remote_endpoint_tracking(void)
{
    // Prepare RX and allocators.
    instrumented_allocator_t alloc_rx_frag = { 0 };
    instrumented_allocator_t alloc_rx_ses  = { 0 };
    instrumented_allocator_t alloc_dgram   = { 0 };
    instrumented_allocator_new(&alloc_rx_frag);
    instrumented_allocator_new(&alloc_rx_ses);
    instrumented_allocator_new(&alloc_dgram);
    const udpard_rx_mem_resources_t rx_mem = {
        .session  = instrumented_allocator_make_resource(&alloc_rx_ses),
        .slot     = instrumented_allocator_make_resource(&alloc_rx_ses),
        .fragment = instrumented_allocator_make_resource(&alloc_rx_frag),
    };
    const udpard_mem_t     dgram_mem = instrumented_allocator_make_resource(&alloc_dgram);
    const udpard_deleter_t dgram_del = instrumented_allocator_make_deleter(&alloc_dgram);

    // Create RX and one P2P port.
    capture_t        cap  = { 0 };
    udpard_rx_t      rx   = { 0 };
    udpard_rx_port_t port = { 0 };
    udpard_rx_new(&rx);
    rx.user = &cap;
    TEST_ASSERT_TRUE(udpard_rx_port_new_p2p(&port, 1024U, rx_mem, &callbacks));

    // Push a frame from iface 1 and verify endpoint discovery.
    static const byte_t      payload[]  = { 0x10, 0x20, 0x30 };
    const uint64_t           remote_uid = 0xCAFEBABE12345678ULL;
    const udpard_bytes_mut_t dgram =
      make_datagram(dgram_mem, udpard_prio_nominal, 501U, remote_uid, 0U, payload, sizeof(payload));
    const udpard_udpip_ep_t src = { .ip = 0x0A00000AU, .port = 7300U };
    TEST_ASSERT_TRUE(udpard_rx_port_push(&rx, &port, 4000, src, dgram, dgram_del, 1U));
    udpard_rx_poll(&rx, 4001);

    // Validate transfer metadata and endpoint tracking.
    TEST_ASSERT_EQUAL_size_t(1, cap.count);
    TEST_ASSERT_EQUAL_UINT64(remote_uid, cap.remote.uid);
    TEST_ASSERT_EQUAL_UINT32(src.ip, cap.remote.endpoints[1].ip);
    TEST_ASSERT_EQUAL_UINT16(src.port, cap.remote.endpoints[1].port);
    TEST_ASSERT_EQUAL_size_t(0, alloc_dgram.allocated_fragments);

    // Tear down and validate allocator state.
    udpard_rx_port_free(&rx, &port);
    TEST_ASSERT_EQUAL_size_t(0, alloc_rx_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_rx_ses.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_dgram.allocated_fragments);
    instrumented_allocator_reset(&alloc_rx_frag);
    instrumented_allocator_reset(&alloc_rx_ses);
    instrumented_allocator_reset(&alloc_dgram);
}

void setUp(void) {}
void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_rx_single_frame);
    RUN_TEST(test_rx_duplicate_rejected_and_freed);
    RUN_TEST(test_rx_malformed_frame);
    RUN_TEST(test_rx_p2p_remote_endpoint_tracking);
    return UNITY_END();
}
