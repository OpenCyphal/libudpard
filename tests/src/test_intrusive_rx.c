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

typedef struct
{
    instrumented_allocator_t  alloc_rx_frag;
    instrumented_allocator_t  alloc_rx_ses;
    instrumented_allocator_t  alloc_dgram;
    udpard_rx_mem_resources_t rx_mem;
    udpard_mem_t              dgram_mem;
    udpard_deleter_t          dgram_del;
} rx_mem_fixture_t;

// Initializes the common RX-side allocators used by intrusive tests.
static void rx_mem_fixture_init(rx_mem_fixture_t* const self)
{
    instrumented_allocator_new(&self->alloc_rx_frag);
    instrumented_allocator_new(&self->alloc_rx_ses);
    instrumented_allocator_new(&self->alloc_dgram);
    self->rx_mem = (udpard_rx_mem_resources_t){
        .session  = instrumented_allocator_make_resource(&self->alloc_rx_ses),
        .slot     = instrumented_allocator_make_resource(&self->alloc_rx_ses),
        .fragment = instrumented_allocator_make_resource(&self->alloc_rx_frag),
    };
    self->dgram_mem = instrumented_allocator_make_resource(&self->alloc_dgram);
    self->dgram_del = instrumented_allocator_make_deleter(&self->alloc_dgram);
}

// Verifies that all intrusive RX allocators are fully released.
static void rx_mem_fixture_fini(rx_mem_fixture_t* const self)
{
    TEST_ASSERT_EQUAL_size_t(0U, self->alloc_rx_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0U, self->alloc_rx_ses.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0U, self->alloc_dgram.allocated_fragments);
    instrumented_allocator_reset(&self->alloc_rx_frag);
    instrumented_allocator_reset(&self->alloc_rx_ses);
    instrumented_allocator_reset(&self->alloc_dgram);
}

// Builds a valid first-frame datagram with a custom total transfer size.
static udpard_bytes_mut_t make_first_frame_datagram(const udpard_mem_t  mem,
                                                    const udpard_prio_t prio,
                                                    const uint64_t      transfer_id,
                                                    const uint64_t      sender_uid,
                                                    const size_t        transfer_payload_size,
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
        .transfer_payload_size = (uint32_t)transfer_payload_size,
        .transfer_id           = transfer_id,
        .sender_uid            = sender_uid,
    };
    const uint32_t prefix_crc = crc_full(payload_size, &data[HEADER_SIZE_BYTES]);
    (void)header_serialize(data, meta, 0U, prefix_crc);
    return (udpard_bytes_mut_t){ .size = total_size, .data = data };
}

// Builds an intrusive RX frame with allocator-backed payload ownership.
static rx_frame_t make_frame(const udpard_mem_t  mem,
                             const udpard_prio_t prio,
                             const uint64_t      transfer_id,
                             const uint64_t      sender_uid,
                             const size_t        offset,
                             const size_t        transfer_payload_size,
                             const void* const   payload,
                             const size_t        payload_size,
                             const uint32_t      crc)
{
    void* data = NULL;
    if (payload_size > 0U) {
        data = mem_res_alloc(mem, payload_size);
        TEST_ASSERT_NOT_NULL(data);
        (void)memcpy(data, payload, payload_size);
    }
    return (rx_frame_t){
        .base =
          {
              .offset  = offset,
              .payload = { .size = payload_size, .data = data },
              .origin  = { .size = payload_size, .data = data },
              .crc     = crc,
          },
        .meta =
          {
              .priority              = prio,
              .transfer_payload_size = (uint32_t)transfer_payload_size,
              .transfer_id           = transfer_id,
              .sender_uid            = sender_uid,
          },
    };
}

// Counts fragments in offset order for tree-shape checks.
static size_t fragment_count(udpard_tree_t* const root)
{
    size_t out = 0U;
    for (udpard_tree_t* p = cavl2_min(root); p != NULL; p = cavl2_next_greater(p)) {
        out++;
    }
    return out;
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

static void test_rx_unicast_remote_endpoint_tracking(void)
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

    // Create RX and one unicast port.
    capture_t        cap  = { 0 };
    udpard_rx_t      rx   = { 0 };
    udpard_rx_port_t port = { 0 };
    udpard_rx_new(&rx);
    rx.user = &cap;
    TEST_ASSERT_TRUE(udpard_rx_port_new_unicast(&port, 1024U, rx_mem, &callbacks));

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

static void test_rx_stateful_session_oom(void)
{
    // Fail the session allocation and ensure the payload is released.
    rx_mem_fixture_t fx = { 0 };
    rx_mem_fixture_init(&fx);
    fx.alloc_rx_ses.limit_fragments = 0U;
    capture_t        cap            = { 0 };
    udpard_rx_t      rx             = { 0 };
    udpard_rx_port_t port           = { 0 };
    udpard_rx_new(&rx);
    rx.user = &cap;
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 1024U, fx.rx_mem, &callbacks));

    static const byte_t      payload[] = { 0x42U };
    const udpard_bytes_mut_t dgram =
      make_datagram(fx.dgram_mem, udpard_prio_nominal, 700U, 0x0102030405060708ULL, 0U, payload, sizeof(payload));
    TEST_ASSERT_TRUE(udpard_rx_port_push(
      &rx, &port, 5000, (udpard_udpip_ep_t){ .ip = 0x0A000004U, .port = 7400U }, dgram, fx.dgram_del, 0U));
    TEST_ASSERT_EQUAL_UINT64(1U, rx.errors_oom);
    TEST_ASSERT_EQUAL_size_t(0U, cap.count);
    TEST_ASSERT_EQUAL_size_t(0U, fx.alloc_dgram.allocated_fragments);

    udpard_rx_port_free(&rx, &port);
    rx_mem_fixture_fini(&fx);
}

static void test_rx_idle_session_retirement(void)
{
    // Retire an idle session through udpard_rx_poll().
    rx_mem_fixture_t fx = { 0 };
    rx_mem_fixture_init(&fx);
    capture_t        cap  = { 0 };
    udpard_rx_t      rx   = { 0 };
    udpard_rx_port_t port = { 0 };
    udpard_rx_new(&rx);
    rx.user = &cap;
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 1024U, fx.rx_mem, &callbacks));

    static const byte_t      payload[] = { 1U, 2U, 3U };
    const udpard_bytes_mut_t dgram =
      make_datagram(fx.dgram_mem, udpard_prio_nominal, 701U, 0x1111222233334444ULL, 0U, payload, sizeof(payload));
    TEST_ASSERT_TRUE(udpard_rx_port_push(
      &rx, &port, 6000, (udpard_udpip_ep_t){ .ip = 0x0A000005U, .port = 7500U }, dgram, fx.dgram_del, 0U));
    udpard_rx_poll(&rx, 6001);
    TEST_ASSERT_EQUAL_size_t(1U, cap.count);
    TEST_ASSERT_NOT_NULL(port.index_session_by_remote_uid);
    TEST_ASSERT_EQUAL_size_t(1U, fx.alloc_rx_ses.allocated_fragments);

    udpard_rx_poll(&rx, 6000 + SESSION_LIFETIME);
    TEST_ASSERT_NULL(port.index_session_by_remote_uid);
    TEST_ASSERT_NULL(rx.list_session_by_animation.head);
    TEST_ASSERT_NULL(rx.list_session_by_animation.tail);
    TEST_ASSERT_EQUAL_size_t(0U, fx.alloc_rx_ses.allocated_fragments);

    udpard_rx_port_free(&rx, &port);
    rx_mem_fixture_fini(&fx);
}

static void test_rx_stateless_first_frame_extent_handling(void)
{
    // Accept a first-frame prefix if it covers the extent; otherwise reject it.
    rx_mem_fixture_t fx = { 0 };
    rx_mem_fixture_init(&fx);
    static const struct
    {
        size_t extent;
        bool   accept;
    } cases[] = {
        { 10U, true },
        { 0U, true },
        { 48U, false },
    };
    static const byte_t payload[] = {
        0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
        0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U, 0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU,
    };

    for (size_t i = 0U; i < (sizeof(cases) / sizeof(cases[0])); i++) {
        capture_t        cap  = { 0 };
        udpard_rx_t      rx   = { 0 };
        udpard_rx_port_t port = { 0 };
        udpard_rx_new(&rx);
        rx.user = &cap;
        TEST_ASSERT_TRUE(udpard_rx_port_new_stateless(&port, cases[i].extent, fx.rx_mem, &callbacks));

        const udpard_bytes_mut_t dgram = make_first_frame_datagram(
          fx.dgram_mem, udpard_prio_nominal, 702U + i, 0xABCDEF1234567890ULL, 64U, payload, sizeof(payload));
        TEST_ASSERT_TRUE(udpard_rx_port_push(&rx,
                                             &port,
                                             7000 + (udpard_us_t)i,
                                             (udpard_udpip_ep_t){ .ip = 0x0A000006U, .port = 7600U },
                                             dgram,
                                             fx.dgram_del,
                                             0U));
        if (cases[i].accept) {
            TEST_ASSERT_EQUAL_size_t(1U, cap.count);
            TEST_ASSERT_EQUAL_UINT64(0U, rx.errors_transfer_malformed);
            TEST_ASSERT_EQUAL_size_t(sizeof(payload), cap.payload_size);
            TEST_ASSERT_EQUAL_MEMORY(payload, cap.payload, sizeof(payload));
        } else {
            TEST_ASSERT_EQUAL_size_t(0U, cap.count);
            TEST_ASSERT_EQUAL_UINT64(1U, rx.errors_transfer_malformed);
        }
        TEST_ASSERT_EQUAL_size_t(0U, fx.alloc_dgram.allocated_fragments);
        udpard_rx_port_free(&rx, &port);
    }
    rx_mem_fixture_fini(&fx);
}

static void test_rx_stateless_nonzero_offset_rejected(void)
{
    // Stateless mode requires the accepted frame to start at offset zero.
    rx_mem_fixture_t fx = { 0 };
    rx_mem_fixture_init(&fx);
    capture_t        cap  = { 0 };
    udpard_rx_t      rx   = { 0 };
    udpard_rx_port_t port = { 0 };
    udpard_rx_new(&rx);
    rx.user = &cap;
    TEST_ASSERT_TRUE(udpard_rx_port_new_stateless(&port, 10U, fx.rx_mem, &callbacks));

    static const byte_t      payload[] = { 0xAAU, 0xBBU, 0xCCU, 0xDDU };
    const udpard_bytes_mut_t dgram =
      make_datagram(fx.dgram_mem, udpard_prio_nominal, 704U, 0x2222333344445555ULL, 8U, payload, sizeof(payload));
    TEST_ASSERT_TRUE(udpard_rx_port_push(
      &rx, &port, 8100, (udpard_udpip_ep_t){ .ip = 0x0A000008U, .port = 7710U }, dgram, fx.dgram_del, 0U));
    TEST_ASSERT_EQUAL_size_t(0U, cap.count);
    TEST_ASSERT_EQUAL_UINT64(1U, rx.errors_transfer_malformed);
    TEST_ASSERT_EQUAL_size_t(0U, fx.alloc_dgram.allocated_fragments);

    udpard_rx_port_free(&rx, &port);
    rx_mem_fixture_fini(&fx);
}

static void test_rx_stateless_fragment_oom(void)
{
    // Fail the stateless fragment allocation and report OOM.
    rx_mem_fixture_t fx = { 0 };
    rx_mem_fixture_init(&fx);
    fx.alloc_rx_frag.limit_fragments = 0U;
    capture_t        cap             = { 0 };
    udpard_rx_t      rx              = { 0 };
    udpard_rx_port_t port            = { 0 };
    udpard_rx_new(&rx);
    rx.user = &cap;
    TEST_ASSERT_TRUE(udpard_rx_port_new_stateless(&port, 1024U, fx.rx_mem, &callbacks));

    static const byte_t      payload[] = { 0x21U, 0x22U, 0x23U };
    const udpard_bytes_mut_t dgram =
      make_datagram(fx.dgram_mem, udpard_prio_high, 703U, 0x0101010101010101ULL, 0U, payload, sizeof(payload));
    TEST_ASSERT_TRUE(udpard_rx_port_push(
      &rx, &port, 8000, (udpard_udpip_ep_t){ .ip = 0x0A000007U, .port = 7700U }, dgram, fx.dgram_del, 0U));
    TEST_ASSERT_EQUAL_size_t(0U, cap.count);
    TEST_ASSERT_EQUAL_UINT64(1U, rx.errors_oom);
    TEST_ASSERT_EQUAL_size_t(0U, fx.alloc_dgram.allocated_fragments);

    udpard_rx_port_free(&rx, &port);
    rx_mem_fixture_fini(&fx);
}

static void test_rx_session_get_slot_paths(void)
{
    // Reuse, timeout, and sacrifice slots explicitly.
    rx_mem_fixture_t fx   = { 0 };
    udpard_rx_port_t port = { 0 };
    rx_mem_fixture_init(&fx);
    port.memory = fx.rx_mem;

    rx_session_t reuse = { 0 };
    reuse.port         = &port;
    reuse.slots[2]     = rx_slot_new(port.memory.slot);
    TEST_ASSERT_NOT_NULL(reuse.slots[2]);
    reuse.slots[2]->transfer_id = 11U;
    TEST_ASSERT_EQUAL_PTR(&reuse.slots[2], rx_session_get_slot(&reuse, 1U, 11U));
    rx_slot_destroy(&reuse.slots[2], port.memory.fragment, port.memory.slot);

    rx_session_t timed = { 0 };
    timed.port         = &port;
    timed.slots[0]     = rx_slot_new(port.memory.slot);
    TEST_ASSERT_NOT_NULL(timed.slots[0]);
    timed.slots[0]->transfer_id = 22U;
    timed.slots[0]->ts_max      = 5U;
    TEST_ASSERT_EQUAL_PTR(&timed.slots[0], rx_session_get_slot(&timed, 5U + SESSION_LIFETIME, 23U));
    TEST_ASSERT_NOT_NULL(timed.slots[0]);
    TEST_ASSERT_EQUAL(HEAT_DEATH, timed.slots[0]->ts_min);
    rx_slot_destroy(&timed.slots[0], port.memory.fragment, port.memory.slot);

    rx_session_t full = { 0 };
    full.port         = &port;
    for (size_t i = 0U; i < RX_SLOT_COUNT; i++) {
        full.slots[i] = rx_slot_new(port.memory.slot);
        TEST_ASSERT_NOT_NULL(full.slots[i]);
        full.slots[i]->transfer_id = (uint64_t)i;
        full.slots[i]->ts_max      = 100LL + (udpard_us_t)i;
    }
    full.slots[2]->ts_max = 1U;
    TEST_ASSERT_EQUAL_PTR(&full.slots[2], rx_session_get_slot(&full, 10U, 99U));
    TEST_ASSERT_NOT_NULL(full.slots[2]);
    TEST_ASSERT_EQUAL(HEAT_DEATH, full.slots[2]->ts_min);
    for (size_t i = 0U; i < RX_SLOT_COUNT; i++) {
        rx_slot_destroy(&full.slots[i], port.memory.fragment, port.memory.slot);
    }

    rx_mem_fixture_fini(&fx);
}

static void test_rx_slot_update_paths(void)
{
    // Cover mismatch, OOM, and finalize-failure slot updates.
    rx_mem_fixture_t fx = { 0 };
    rx_mem_fixture_init(&fx);

    // Force slot allocation failure.
    fx.alloc_rx_ses.limit_fragments = 0U;
    TEST_ASSERT_NULL(rx_slot_new(fx.rx_mem.slot));
    fx.alloc_rx_ses.limit_fragments = SIZE_MAX;

    rx_slot_t* slot = rx_slot_new(fx.rx_mem.slot);
    TEST_ASSERT_NOT_NULL(slot);
    static const byte_t mismatch_payload[] = { 0x01U };
    rx_frame_t          mismatch =
      make_frame(fx.dgram_mem, udpard_prio_low, 800U, 1U, 0U, 5U, mismatch_payload, sizeof(mismatch_payload), 0U);
    slot->ts_min        = 0U;
    slot->ts_max        = 0U;
    slot->total_size    = 4U;
    slot->priority      = udpard_prio_high;
    uint64_t errors_oom = 0U;
    TEST_ASSERT_EQUAL(rx_slot_failure,
                      rx_slot_update(slot, 0U, fx.rx_mem.fragment, fx.dgram_del, &mismatch, 16U, &errors_oom));
    TEST_ASSERT_EQUAL_size_t(0U, fx.alloc_dgram.allocated_fragments);
    rx_slot_destroy(&slot, fx.rx_mem.fragment, fx.rx_mem.slot);

    // Trigger partial-initialization branch and priority-only mismatch.
    slot = rx_slot_new(fx.rx_mem.slot);
    TEST_ASSERT_NOT_NULL(slot);
    static const byte_t prio_payload[] = { 0x7EU };
    rx_frame_t          prio_mismatch =
      make_frame(fx.dgram_mem, udpard_prio_nominal, 803U, 4U, 0U, 1U, prio_payload, sizeof(prio_payload), 0U);
    slot->ts_min     = HEAT_DEATH;
    slot->ts_max     = 0U;
    slot->total_size = prio_mismatch.meta.transfer_payload_size;
    slot->priority   = udpard_prio_high;
    errors_oom       = 0U;
    TEST_ASSERT_EQUAL(rx_slot_failure,
                      rx_slot_update(slot, 0U, fx.rx_mem.fragment, fx.dgram_del, &prio_mismatch, 16U, &errors_oom));
    TEST_ASSERT_EQUAL_size_t(0U, fx.alloc_dgram.allocated_fragments);
    rx_slot_destroy(&slot, fx.rx_mem.fragment, fx.rx_mem.slot);

    slot = rx_slot_new(fx.rx_mem.slot);
    TEST_ASSERT_NOT_NULL(slot);
    fx.alloc_rx_frag.limit_fragments  = 0U;
    static const byte_t oom_payload[] = { 0x02U };
    rx_frame_t          oom =
      make_frame(fx.dgram_mem, udpard_prio_nominal, 801U, 2U, 0U, 1U, oom_payload, sizeof(oom_payload), 0U);
    errors_oom = 0U;
    TEST_ASSERT_EQUAL(rx_slot_incomplete,
                      rx_slot_update(slot, 1U, fx.rx_mem.fragment, fx.dgram_del, &oom, 16U, &errors_oom));
    TEST_ASSERT_EQUAL_UINT64(1U, errors_oom);
    TEST_ASSERT_NULL(slot->fragments);
    TEST_ASSERT_EQUAL_size_t(0U, fx.alloc_dgram.allocated_fragments);
    fx.alloc_rx_frag.limit_fragments = SIZE_MAX;
    rx_slot_destroy(&slot, fx.rx_mem.fragment, fx.rx_mem.slot);

    slot = rx_slot_new(fx.rx_mem.slot);
    TEST_ASSERT_NOT_NULL(slot);
    static const byte_t crc_payload[] = { 0x03U, 0x04U, 0x05U };
    rx_frame_t          crc_bad       = make_frame(
      fx.dgram_mem, udpard_prio_nominal, 802U, 3U, 0U, sizeof(crc_payload), crc_payload, sizeof(crc_payload), 0U);
    errors_oom = 0U;
    TEST_ASSERT_EQUAL(rx_slot_failure,
                      rx_slot_update(slot, 2U, fx.rx_mem.fragment, fx.dgram_del, &crc_bad, 16U, &errors_oom));
    rx_slot_destroy(&slot, fx.rx_mem.fragment, fx.rx_mem.slot);

    rx_mem_fixture_fini(&fx);
}

static void test_rx_session_update_failure_paths(void)
{
    // Cover compare, slot-OOM, and slot-update failure branches.
    rx_mem_fixture_t fx = { 0 };
    rx_mem_fixture_init(&fx);
    udpard_rx_t rx = { 0 };
    udpard_rx_new(&rx);
    udpard_rx_port_t port = { 0 };
    port.memory           = fx.rx_mem;
    port.extent           = 64U;
    port.vtable           = &callbacks;

    // Directly cover uid_a < uid_b comparator branch.
    const uint64_t key = 1U;
    rx_session_t   cmp = { 0 };
    cmp.remote.uid     = 2U;
    TEST_ASSERT_EQUAL_INT32(-1, cavl_compare_rx_session_by_remote_uid(&key, &cmp.index_remote_uid));

    // Force slot allocation failure in rx_session_update().
    rx_session_t ses_oom            = { 0 };
    ses_oom.port                    = &port;
    ses_oom.remote.uid              = 10U;
    fx.alloc_rx_ses.limit_fragments = 0U;
    static const byte_t p0[]        = { 0x44U };
    rx_frame_t          f0 =
      make_frame(fx.dgram_mem, udpard_prio_nominal, 1000U, ses_oom.remote.uid, 0U, 1U, p0, sizeof(p0), 0U);
    rx_session_update(
      &ses_oom, &rx, 100U, (udpard_udpip_ep_t){ .ip = 0x0A000009U, .port = 7720U }, &f0, fx.dgram_del, 0U);
    TEST_ASSERT_EQUAL_UINT64(1U, rx.errors_oom);
    TEST_ASSERT_EQUAL_size_t(0U, fx.alloc_dgram.allocated_fragments);
    fx.alloc_rx_ses.limit_fragments = SIZE_MAX;

    // Force rx_slot_update() failure path in rx_session_update().
    rx_session_t ses_fail = { 0 };
    ses_fail.port         = &port;
    ses_fail.remote.uid   = 11U;
    ses_fail.slots[0]     = rx_slot_new(port.memory.slot);
    TEST_ASSERT_NOT_NULL(ses_fail.slots[0]);
    ses_fail.slots[0]->transfer_id = 2000U;
    ses_fail.slots[0]->ts_min      = 0U;
    ses_fail.slots[0]->ts_max      = 0U;
    ses_fail.slots[0]->total_size  = 2U;
    ses_fail.slots[0]->priority    = udpard_prio_nominal;
    static const byte_t p1[]       = { 0x55U };
    rx_frame_t          f1 =
      make_frame(fx.dgram_mem, udpard_prio_nominal, 2000U, ses_fail.remote.uid, 0U, 1U, p1, sizeof(p1), 0U);
    rx_session_update(
      &ses_fail, &rx, 101U, (udpard_udpip_ep_t){ .ip = 0x0A00000AU, .port = 7730U }, &f1, fx.dgram_del, 0U);
    TEST_ASSERT_EQUAL_UINT64(1U, rx.errors_transfer_malformed);
    TEST_ASSERT_NULL(ses_fail.slots[0]);
    TEST_ASSERT_EQUAL_size_t(0U, fx.alloc_dgram.allocated_fragments);

    rx_mem_fixture_fini(&fx);
}

static void test_rx_port_free_with_incomplete_transfer(void)
{
    // Ensure rx_port_free() destroys sessions containing unfinished slots.
    rx_mem_fixture_t fx = { 0 };
    rx_mem_fixture_init(&fx);
    capture_t        cap  = { 0 };
    udpard_rx_t      rx   = { 0 };
    udpard_rx_port_t port = { 0 };
    udpard_rx_new(&rx);
    rx.user = &cap;
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 1024U, fx.rx_mem, &callbacks));

    static const byte_t payload[] = {
        0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U, 0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU,
        0x20U, 0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U, 0x29U, 0x2AU, 0x2BU, 0x2CU, 0x2DU, 0x2EU, 0x2FU,
    };
    const udpard_bytes_mut_t dgram = make_first_frame_datagram(
      fx.dgram_mem, udpard_prio_nominal, 3000U, 0xDEADBEEF00112233ULL, 64U, payload, sizeof(payload));
    TEST_ASSERT_TRUE(udpard_rx_port_push(
      &rx, &port, 9000, (udpard_udpip_ep_t){ .ip = 0x0A00000BU, .port = 7740U }, dgram, fx.dgram_del, 0U));
    TEST_ASSERT_EQUAL_size_t(0U, cap.count);
    TEST_ASSERT_NOT_NULL(port.index_session_by_remote_uid);

    udpard_rx_port_free(&rx, &port);
    TEST_ASSERT_NULL(port.index_session_by_remote_uid);
    TEST_ASSERT_NULL(rx.list_session_by_animation.head);
    TEST_ASSERT_NULL(rx.list_session_by_animation.tail);
    TEST_ASSERT_EQUAL_size_t(0U, fx.alloc_rx_ses.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0U, fx.alloc_rx_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0U, fx.alloc_dgram.allocated_fragments);
    rx_mem_fixture_fini(&fx);
}

static void test_rx_fragment_tree_update_paths(void)
{
    // Cover extent rejection, heuristic rejection, victim eviction, and prefix updates.
    rx_mem_fixture_t fx = { 0 };
    rx_mem_fixture_init(&fx);

    udpard_tree_t*      root   = NULL;
    size_t              prefix = 0U;
    static const byte_t one[]  = { 0xAAU };
    rx_frame_t          beyond = make_frame(fx.dgram_mem, udpard_prio_nominal, 900U, 1U, 4U, 5U, one, sizeof(one), 0U);
    TEST_ASSERT_EQUAL(rx_fragment_tree_rejected,
                      rx_fragment_tree_update(&root, fx.rx_mem.fragment, fx.dgram_del, beyond.base, 5U, 4U, &prefix));
    TEST_ASSERT_NULL(root);
    TEST_ASSERT_EQUAL_size_t(0U, fx.alloc_dgram.allocated_fragments);

    rx_frame_t zero_extent = make_frame(fx.dgram_mem, udpard_prio_nominal, 901U, 1U, 1U, 2U, one, sizeof(one), 0U);
    TEST_ASSERT_EQUAL(
      rx_fragment_tree_rejected,
      rx_fragment_tree_update(&root, fx.rx_mem.fragment, fx.dgram_del, zero_extent.base, 2U, 0U, &prefix));
    TEST_ASSERT_NULL(root);
    TEST_ASSERT_EQUAL_size_t(0U, fx.alloc_dgram.allocated_fragments);

    static const byte_t aaaa[] = { 'A', 'A', 'A', 'A' };
    static const byte_t bbbb[] = { 'B', 'B' };
    static const byte_t cccc[] = { 'C', 'C', 'C', 'C' };
    static const byte_t dddd[] = { 'D', 'D', 'D', 'D' };
    rx_frame_t          f0 = make_frame(fx.dgram_mem, udpard_prio_nominal, 902U, 1U, 0U, 8U, aaaa, sizeof(aaaa), 0U);
    TEST_ASSERT_EQUAL(rx_fragment_tree_accepted,
                      rx_fragment_tree_update(&root, fx.rx_mem.fragment, fx.dgram_del, f0.base, 8U, 8U, &prefix));
    rx_frame_t contained = make_frame(fx.dgram_mem, udpard_prio_nominal, 903U, 1U, 1U, 8U, bbbb, sizeof(bbbb), 0U);
    TEST_ASSERT_EQUAL(
      rx_fragment_tree_rejected,
      rx_fragment_tree_update(&root, fx.rx_mem.fragment, fx.dgram_del, contained.base, 8U, 8U, &prefix));
    rx_frame_t f2 = make_frame(fx.dgram_mem, udpard_prio_nominal, 904U, 1U, 2U, 8U, cccc, sizeof(cccc), 0U);
    TEST_ASSERT_EQUAL(rx_fragment_tree_accepted,
                      rx_fragment_tree_update(&root, fx.rx_mem.fragment, fx.dgram_del, f2.base, 8U, 8U, &prefix));
    TEST_ASSERT_EQUAL_size_t(6U, prefix);
    TEST_ASSERT_EQUAL_size_t(6U, rx_fragment_tree_update_covered_prefix(root, prefix, 7U, 1U));
    rx_frame_t reject = make_frame(fx.dgram_mem, udpard_prio_nominal, 905U, 1U, 1U, 8U, dddd, sizeof(dddd), 0U);
    TEST_ASSERT_EQUAL(rx_fragment_tree_rejected,
                      rx_fragment_tree_update(&root, fx.rx_mem.fragment, fx.dgram_del, reject.base, 8U, 8U, &prefix));
    TEST_ASSERT_EQUAL_size_t(2U, fragment_count(root));
    udpard_fragment_free_all((udpard_fragment_t*)root, udpard_make_deleter(fx.rx_mem.fragment));
    root = NULL;

    prefix                       = 0U;
    static const byte_t bridge[] = { 'X', 'X', 'X', 'X', 'X', 'X' };
    rx_frame_t          left = make_frame(fx.dgram_mem, udpard_prio_nominal, 906U, 1U, 0U, 12U, aaaa, sizeof(aaaa), 0U);
    rx_frame_t victim        = make_frame(fx.dgram_mem, udpard_prio_nominal, 907U, 1U, 4U, 12U, bbbb, sizeof(bbbb), 0U);
    rx_frame_t right         = make_frame(fx.dgram_mem, udpard_prio_nominal, 908U, 1U, 6U, 12U, cccc, sizeof(cccc), 0U);
    TEST_ASSERT_EQUAL(rx_fragment_tree_accepted,
                      rx_fragment_tree_update(&root, fx.rx_mem.fragment, fx.dgram_del, left.base, 12U, 12U, &prefix));
    TEST_ASSERT_EQUAL(rx_fragment_tree_accepted,
                      rx_fragment_tree_update(&root, fx.rx_mem.fragment, fx.dgram_del, victim.base, 12U, 12U, &prefix));
    TEST_ASSERT_EQUAL(rx_fragment_tree_accepted,
                      rx_fragment_tree_update(&root, fx.rx_mem.fragment, fx.dgram_del, right.base, 12U, 12U, &prefix));
    TEST_ASSERT_EQUAL_size_t(3U, fragment_count(root));
    rx_frame_t join = make_frame(fx.dgram_mem, udpard_prio_nominal, 909U, 1U, 2U, 12U, bridge, sizeof(bridge), 0U);
    TEST_ASSERT_EQUAL(rx_fragment_tree_accepted,
                      rx_fragment_tree_update(&root, fx.rx_mem.fragment, fx.dgram_del, join.base, 12U, 12U, &prefix));
    TEST_ASSERT_EQUAL_size_t(3U, fragment_count(root));
    udpard_fragment_t* const mid = udpard_fragment_seek((udpard_fragment_t*)root, 5U);
    TEST_ASSERT_NOT_NULL(mid);
    TEST_ASSERT_EQUAL_size_t(2U, mid->offset);
    udpard_fragment_free_all((udpard_fragment_t*)root, udpard_make_deleter(fx.rx_mem.fragment));

    rx_mem_fixture_fini(&fx);
}

void setUp(void) {}
void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_rx_single_frame);
    RUN_TEST(test_rx_duplicate_rejected_and_freed);
    RUN_TEST(test_rx_malformed_frame);
    RUN_TEST(test_rx_unicast_remote_endpoint_tracking);
    RUN_TEST(test_rx_stateful_session_oom);
    RUN_TEST(test_rx_idle_session_retirement);
    RUN_TEST(test_rx_stateless_first_frame_extent_handling);
    RUN_TEST(test_rx_stateless_nonzero_offset_rejected);
    RUN_TEST(test_rx_stateless_fragment_oom);
    RUN_TEST(test_rx_session_get_slot_paths);
    RUN_TEST(test_rx_slot_update_paths);
    RUN_TEST(test_rx_session_update_failure_paths);
    RUN_TEST(test_rx_port_free_with_incomplete_transfer);
    RUN_TEST(test_rx_fragment_tree_update_paths);
    return UNITY_END();
}
