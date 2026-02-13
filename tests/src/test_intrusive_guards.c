/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c> // NOLINT(bugprone-suspicious-include)
#include "helpers.h"
#include <unity.h>
#include <stdlib.h>

// Heap-backed free helper for guard-path allocations.
static void free_heap(void* const user, const size_t size, void* const pointer)
{
    (void)user;
    (void)size;
    free(pointer);
}

// Heap-backed allocator for guard-path allocations.
static void* alloc_heap(void* const user, const size_t size)
{
    (void)user;
    return (size > 0U) ? malloc(size) : NULL;
}

// Shared vtables for guard-path checks.
static const udpard_mem_vtable_t     mem_vtable = { .base = { .free = free_heap }, .alloc = alloc_heap };
static const udpard_deleter_vtable_t del_vtable = { .free = free_heap };

static udpard_mem_t make_mem(void* const tag)
{
    (void)tag;
    return (udpard_mem_t){ .vtable = &mem_vtable, .context = NULL };
}

// TX eject stub used for constructor checks.
static bool eject_stub(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection)
{
    (void)tx;
    (void)ejection;
    return true;
}

static const udpard_tx_vtable_t tx_vtable = { .eject = eject_stub };

// RX callback stub used for constructor checks.
static void on_message_stub(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    (void)rx;
    (void)port;
    (void)transfer;
}

static const udpard_rx_port_vtable_t rx_vtable = { .on_message = on_message_stub };

static void test_misc_guards(void)
{
    // Endpoint validity.
    TEST_ASSERT_TRUE(udpard_is_valid_endpoint((udpard_udpip_ep_t){ .ip = 1U, .port = UDP_PORT }));
    TEST_ASSERT_FALSE(udpard_is_valid_endpoint((udpard_udpip_ep_t){ .ip = 0U, .port = UDP_PORT }));
    TEST_ASSERT_FALSE(udpard_is_valid_endpoint((udpard_udpip_ep_t){ .ip = UINT32_MAX, .port = UDP_PORT }));
    TEST_ASSERT_FALSE(udpard_is_valid_endpoint((udpard_udpip_ep_t){ .ip = 1U, .port = 0U }));

    // Subject endpoint masking.
    const udpard_udpip_ep_t ep = udpard_make_subject_endpoint(0xFFFFFFFFUL);
    TEST_ASSERT_EQUAL_UINT16(UDP_PORT, ep.port);
    TEST_ASSERT_EQUAL_UINT32(IPv4_MCAST_PREFIX | UDPARD_IPv4_SUBJECT_ID_MAX, ep.ip);
}

static void test_tx_new_guards(void)
{
    // Prepare valid memory resources.
    static byte_t                   transfer_pool[1024];
    static byte_t                   payload_pool[1024];
    const udpard_tx_mem_resources_t mem_ok = {
        .transfer = make_mem(transfer_pool),
        .payload  = { make_mem(payload_pool), make_mem(payload_pool), make_mem(payload_pool) },
    };

    // Validate constructor argument checks.
    udpard_tx_t tx = { 0 };
    TEST_ASSERT_FALSE(udpard_tx_new(NULL, 1U, 1U, 1U, mem_ok, &tx_vtable));
    TEST_ASSERT_FALSE(udpard_tx_new(&tx, 0U, 1U, 1U, mem_ok, &tx_vtable));
    TEST_ASSERT_FALSE(udpard_tx_new(&tx, 1U, 1U, 1U, mem_ok, NULL));
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 1U, 1U, 4U, mem_ok, &tx_vtable));
    udpard_tx_free(&tx);
}

static void test_tx_push_guards(void)
{
    // Prepare a valid TX instance.
    static byte_t                   transfer_pool[1024];
    static byte_t                   payload_pool[1024];
    const udpard_tx_mem_resources_t mem_ok = {
        .transfer = make_mem(transfer_pool),
        .payload  = { make_mem(payload_pool), make_mem(payload_pool), make_mem(payload_pool) },
    };
    udpard_tx_t tx = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 1U, 1U, 4U, mem_ok, &tx_vtable));

    // Validate argument checks for subject push.
    const udpard_bytes_scattered_t empty_payload = make_scattered("", 0U);
    TEST_ASSERT_FALSE(udpard_tx_push_native(
      NULL, 0, 1, 1U, udpard_prio_fast, 1U, udpard_make_subject_endpoint(1U), empty_payload, NULL));
    TEST_ASSERT_FALSE(udpard_tx_push_native(
      &tx, 2, 1, 1U, udpard_prio_fast, 1U, udpard_make_subject_endpoint(1U), empty_payload, NULL));
    TEST_ASSERT_FALSE(udpard_tx_push_native(
      &tx, 0, 1, 0U, udpard_prio_fast, 1U, udpard_make_subject_endpoint(1U), empty_payload, NULL));
    TEST_ASSERT_FALSE(udpard_tx_push_native(
      &tx, 0, 1, 1U, udpard_prio_fast, 1U, (udpard_udpip_ep_t){ .ip = 0U, .port = 0U }, empty_payload, NULL));
    TEST_ASSERT_TRUE(udpard_tx_push_native(
      &tx, 0, 1, 1U, udpard_prio_fast, 1U, udpard_make_subject_endpoint(1U), empty_payload, NULL));
    udpard_tx_free(&tx);
}

static void test_tx_push_p2p_guards(void)
{
    // Prepare a valid TX instance.
    static byte_t                   transfer_pool[1024];
    static byte_t                   payload_pool[1024];
    const udpard_tx_mem_resources_t mem_ok = {
        .transfer = make_mem(transfer_pool),
        .payload  = { make_mem(payload_pool), make_mem(payload_pool), make_mem(payload_pool) },
    };
    udpard_tx_t tx = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 2U, 2U, 4U, mem_ok, &tx_vtable));

    // Validate argument checks for P2P push.
    const udpard_bytes_scattered_t empty_payload                     = make_scattered("", 0U);
    udpard_udpip_ep_t              endpoints[UDPARD_IFACE_COUNT_MAX] = { 0 };
    endpoints[0] = (udpard_udpip_ep_t){ .ip = 0x0A000001U, .port = 9000U };
    TEST_ASSERT_FALSE(udpard_tx_push_p2p_native(NULL, 0, 1, udpard_prio_nominal, endpoints, empty_payload, NULL));
    TEST_ASSERT_FALSE(udpard_tx_push_p2p_native(&tx, 2, 1, udpard_prio_nominal, endpoints, empty_payload, NULL));
    TEST_ASSERT_TRUE(udpard_tx_push_p2p_native(&tx, 0, 1, udpard_prio_nominal, endpoints, empty_payload, NULL));
    endpoints[0] = (udpard_udpip_ep_t){ .ip = 0U, .port = 0U };
    TEST_ASSERT_FALSE(udpard_tx_push_p2p_native(&tx, 0, 1, udpard_prio_nominal, endpoints, empty_payload, NULL));
    udpard_tx_free(&tx);
}

static void test_rx_port_push_guards(void)
{
    // Prepare RX and port.
    static byte_t                   session_pool[1024];
    static byte_t                   fragment_pool[1024];
    const udpard_rx_mem_resources_t rx_mem = {
        .session  = make_mem(session_pool),
        .slot     = make_mem(session_pool),
        .fragment = make_mem(fragment_pool),
    };
    udpard_rx_t      rx   = { 0 };
    udpard_rx_port_t port = { 0 };
    udpard_rx_new(&rx, NULL);
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 256U, rx_mem, &rx_vtable));

    // Build one valid datagram then check argument validation.
    byte_t       datagram[HEADER_SIZE_BYTES] = { 0 };
    const meta_t meta                        = {
                               .priority              = udpard_prio_nominal,
                               .transfer_payload_size = 0U,
                               .transfer_id           = 1U,
                               .sender_uid            = 3U,
    };
    (void)header_serialize(datagram, meta, 0U, crc_full(0U, NULL));
    const udpard_bytes_mut_t payload = { .size = sizeof(datagram), .data = datagram };
    const udpard_deleter_t   del     = { .vtable = &del_vtable, .context = NULL };
    TEST_ASSERT_FALSE(
      udpard_rx_port_push(NULL, &port, 0, (udpard_udpip_ep_t){ .ip = 1U, .port = 1U }, payload, del, 0U));
    TEST_ASSERT_FALSE(udpard_rx_port_push(&rx, NULL, 0, (udpard_udpip_ep_t){ .ip = 1U, .port = 1U }, payload, del, 0U));
    TEST_ASSERT_FALSE(
      udpard_rx_port_push(&rx, &port, 0, (udpard_udpip_ep_t){ .ip = 1U, .port = 1U }, payload, del, 99U));
    TEST_ASSERT_FALSE(udpard_rx_port_push(&rx,
                                          &port,
                                          0,
                                          (udpard_udpip_ep_t){ .ip = 1U, .port = 1U },
                                          (udpard_bytes_mut_t){ .size = 1U, .data = NULL },
                                          del,
                                          0U));
    TEST_ASSERT_TRUE(udpard_rx_port_push(&rx, &port, 0, (udpard_udpip_ep_t){ .ip = 1U, .port = 1U }, payload, del, 0U));

    udpard_rx_port_free(&rx, &port);
}

void setUp(void) {}
void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_misc_guards);
    RUN_TEST(test_tx_new_guards);
    RUN_TEST(test_tx_push_guards);
    RUN_TEST(test_tx_push_p2p_guards);
    RUN_TEST(test_rx_port_push_guards);
    return UNITY_END();
}
