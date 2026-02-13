/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c> // NOLINT(bugprone-suspicious-include)
#include "helpers.h"
#include <unity.h>

typedef struct
{
    bool   allow;
    size_t count;
    struct
    {
        uint64_t          transfer_id;
        udpard_udpip_ep_t destination;
        uint_fast8_t      iface_index;
    } items[16];
} eject_state_t;

typedef struct
{
    instrumented_allocator_t  transfer_alloc;
    instrumented_allocator_t  payload_alloc;
    udpard_tx_mem_resources_t mem;
    udpard_tx_t               tx;
    eject_state_t             eject;
} tx_fixture_t;

// Captures metadata from each ejected frame.
static bool eject_capture(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection)
{
    eject_state_t* const st = (eject_state_t*)tx->user;
    TEST_ASSERT_NOT_NULL(st);
    if (!st->allow) {
        return false;
    }
    if (st->count < (sizeof(st->items) / sizeof(st->items[0]))) {
        meta_t         meta    = { 0 };
        uint32_t       offset  = 0;
        uint32_t       prefix  = 0;
        udpard_bytes_t payload = { 0 };
        TEST_ASSERT_TRUE(header_deserialize(
          (udpard_bytes_mut_t){ .size = ejection->datagram.size, .data = (void*)ejection->datagram.data }, // NOLINT
          &meta,
          &offset,
          &prefix,
          &payload));
        st->items[st->count].transfer_id = meta.transfer_id;
        st->items[st->count].destination = ejection->destination;
        st->items[st->count].iface_index = ejection->iface_index;
    }
    st->count++;
    return true;
}

static const udpard_tx_vtable_t tx_vtable = { .eject = eject_capture };

// Initializes a TX fixture with instrumented allocators.
static void fixture_init(tx_fixture_t* const self, const size_t queue_limit, const size_t mtu, const bool allow_eject)
{
    instrumented_allocator_new(&self->transfer_alloc);
    instrumented_allocator_new(&self->payload_alloc);
    self->mem.transfer = instrumented_allocator_make_resource(&self->transfer_alloc);
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        self->mem.payload[i] = instrumented_allocator_make_resource(&self->payload_alloc);
    }
    self->eject = (eject_state_t){ .allow = allow_eject, .count = 0U };
    TEST_ASSERT_TRUE(udpard_tx_new(&self->tx, 0x1122334455667788ULL, 123U, queue_limit, self->mem, &tx_vtable));
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        self->tx.mtu[i] = mtu;
    }
    self->tx.user = &self->eject;
}

// Frees TX fixture and checks allocator state.
static void fixture_fini(tx_fixture_t* const self)
{
    udpard_tx_free(&self->tx);
    TEST_ASSERT_EQUAL_size_t(0, self->transfer_alloc.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, self->payload_alloc.allocated_fragments);
    instrumented_allocator_reset(&self->transfer_alloc);
    instrumented_allocator_reset(&self->payload_alloc);
}

static void test_tx_subject_ejection(void)
{
    // Push one subject transfer on two interfaces and verify ejections.
    tx_fixture_t fx = { 0 };
    fixture_init(&fx, 8U, 128U, true);
    const byte_t                   data[]  = { 1, 2, 3, 4, 5, 6 };
    const udpard_udpip_ep_t        subject = udpard_make_subject_endpoint(321U);
    const udpard_bytes_scattered_t payload = make_scattered(data, sizeof(data));
    TEST_ASSERT_TRUE(udpard_tx_push_native(
      &fx.tx, 0, 10000, (1U << 0U) | (1U << 2U), udpard_prio_fast, 0x0000AABBCCDDEEFFULL, subject, payload, NULL));
    TEST_ASSERT_EQUAL_UINT16((1U << 0U) | (1U << 2U), udpard_tx_pending_ifaces(&fx.tx));

    udpard_tx_poll(&fx.tx, 1, (1U << 0U) | (1U << 2U));
    TEST_ASSERT_EQUAL_size_t(2, fx.eject.count);
    TEST_ASSERT_EQUAL_UINT64(0x0000AABBCCDDEEFFULL, fx.eject.items[0].transfer_id);
    TEST_ASSERT_EQUAL_UINT32(subject.ip, fx.eject.items[0].destination.ip);
    TEST_ASSERT_EQUAL_UINT16(subject.port, fx.eject.items[0].destination.port);
    TEST_ASSERT_EQUAL_UINT16(0U, udpard_tx_pending_ifaces(&fx.tx));

    fixture_fini(&fx);
}

static void test_tx_p2p_endpoints(void)
{
    // Push one P2P transfer and verify only valid endpoints are used.
    tx_fixture_t fx = { 0 };
    fixture_init(&fx, 8U, 128U, true);
    const byte_t                   data[]                      = { 9, 8, 7 };
    const udpard_bytes_scattered_t payload                     = make_scattered(data, sizeof(data));
    udpard_udpip_ep_t              eps[UDPARD_IFACE_COUNT_MAX] = { 0 };
    eps[0] = (udpard_udpip_ep_t){ .ip = 0x0A000001U, .port = 8001U };
    eps[2] = (udpard_udpip_ep_t){ .ip = 0x0A000003U, .port = 8003U };
    TEST_ASSERT_TRUE(udpard_tx_push_p2p_native(&fx.tx, 0, 10000, udpard_prio_nominal, eps, payload, NULL));
    TEST_ASSERT_EQUAL_UINT16((1U << 0U) | (1U << 2U), udpard_tx_pending_ifaces(&fx.tx));

    udpard_tx_poll(&fx.tx, 1, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_EQUAL_size_t(2, fx.eject.count);
    TEST_ASSERT_EQUAL_UINT32(eps[0].ip, fx.eject.items[0].destination.ip);
    TEST_ASSERT_EQUAL_UINT16(eps[0].port, fx.eject.items[0].destination.port);
    TEST_ASSERT_EQUAL_UINT32(eps[2].ip, fx.eject.items[1].destination.ip);
    TEST_ASSERT_EQUAL_UINT16(eps[2].port, fx.eject.items[1].destination.port);

    fixture_fini(&fx);
}

static void test_tx_expiration(void)
{
    // Keep ejection blocked and ensure expired transfers are purged.
    tx_fixture_t fx = { 0 };
    fixture_init(&fx, 8U, 128U, false);
    const byte_t                   data[]  = { 0xAA };
    const udpard_bytes_scattered_t payload = make_scattered(data, sizeof(data));
    TEST_ASSERT_TRUE(udpard_tx_push_native(
      &fx.tx, 0, 10, (1U << 1U), udpard_prio_high, 5U, udpard_make_subject_endpoint(111U), payload, NULL));
    TEST_ASSERT_EQUAL_UINT16((1U << 1U), udpard_tx_pending_ifaces(&fx.tx));

    udpard_tx_poll(&fx.tx, 11, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_EQUAL_UINT16(0U, udpard_tx_pending_ifaces(&fx.tx));
    TEST_ASSERT_EQUAL_UINT64(1U, fx.tx.errors_expiration);
    TEST_ASSERT_EQUAL_size_t(0, fx.eject.count);

    fixture_fini(&fx);
}

static void test_tx_sacrifice_oldest(void)
{
    // Force queue pressure and verify oldest transfer is sacrificed.
    tx_fixture_t fx = { 0 };
    fixture_init(&fx, 1U, 128U, true);
    const byte_t                   data[]  = { 0x01, 0x02 };
    const udpard_bytes_scattered_t payload = make_scattered(data, sizeof(data));
    const udpard_udpip_ep_t        ep      = udpard_make_subject_endpoint(222U);
    TEST_ASSERT_TRUE(udpard_tx_push_native(&fx.tx, 0, 10000, 1U, udpard_prio_nominal, 10U, ep, payload, NULL));
    TEST_ASSERT_TRUE(udpard_tx_push_native(&fx.tx, 1, 10000, 1U, udpard_prio_nominal, 20U, ep, payload, NULL));
    TEST_ASSERT_EQUAL_UINT64(1U, fx.tx.errors_sacrifice);

    udpard_tx_poll(&fx.tx, 2, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_EQUAL_size_t(1, fx.eject.count);
    TEST_ASSERT_EQUAL_UINT64(20U, fx.eject.items[0].transfer_id);

    fixture_fini(&fx);
}

static void test_tx_transfer_id_masking(void)
{
    // Verify only low 48 bits of transfer-ID are serialized.
    tx_fixture_t fx = { 0 };
    fixture_init(&fx, 8U, 128U, true);
    const byte_t                   data[]      = { 0x55 };
    const udpard_bytes_scattered_t payload     = make_scattered(data, sizeof(data));
    const uint64_t                 transfer_id = 0xABCDEF0123456789ULL;
    TEST_ASSERT_TRUE(udpard_tx_push_native(
      &fx.tx, 0, 10000, 1U, udpard_prio_nominal, transfer_id, udpard_make_subject_endpoint(333U), payload, NULL));
    udpard_tx_poll(&fx.tx, 1, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_EQUAL_size_t(1, fx.eject.count);
    TEST_ASSERT_EQUAL_UINT64(transfer_id & UDPARD_TRANSFER_ID_MASK, fx.eject.items[0].transfer_id);

    fixture_fini(&fx);
}

void setUp(void) {}
void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_tx_subject_ejection);
    RUN_TEST(test_tx_p2p_endpoints);
    RUN_TEST(test_tx_expiration);
    RUN_TEST(test_tx_sacrifice_oldest);
    RUN_TEST(test_tx_transfer_id_masking);
    return UNITY_END();
}
