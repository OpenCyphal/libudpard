/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c> // NOLINT(bugprone-suspicious-include)
#include "helpers.h"
#include <unity.h>

typedef struct
{
    bool           allow;
    bool           retain_first;
    size_t         count;
    udpard_bytes_t held;
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
    if (st->retain_first && (st->count == 0U)) {
        st->held = ejection->datagram;
        udpard_tx_refcount_inc(ejection->datagram);
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
    self->eject = (eject_state_t){ .allow = allow_eject, .retain_first = false, .count = 0U, .held = { 0 } };
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
    TEST_ASSERT_TRUE(udpard_tx_push(
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

static void test_tx_unicast_endpoints(void)
{
    // Push one unicast transfer and verify only valid endpoints are used.
    tx_fixture_t fx = { 0 };
    fixture_init(&fx, 8U, 128U, true);
    const byte_t                   data[]                      = { 9, 8, 7 };
    const udpard_bytes_scattered_t payload                     = make_scattered(data, sizeof(data));
    udpard_udpip_ep_t              eps[UDPARD_IFACE_COUNT_MAX] = { 0 };
    eps[0] = (udpard_udpip_ep_t){ .ip = 0x0A000001U, .port = 8001U };
    eps[2] = (udpard_udpip_ep_t){ .ip = 0x0A000003U, .port = 8003U };
    TEST_ASSERT_TRUE(udpard_tx_push_unicast(&fx.tx, 0, 10000, udpard_prio_nominal, eps, payload, NULL));
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
    TEST_ASSERT_TRUE(udpard_tx_push(
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
    TEST_ASSERT_TRUE(udpard_tx_push(&fx.tx, 0, 10000, 1U, udpard_prio_nominal, 10U, ep, payload, NULL));
    TEST_ASSERT_TRUE(udpard_tx_push(&fx.tx, 1, 10000, 1U, udpard_prio_nominal, 20U, ep, payload, NULL));
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
    TEST_ASSERT_TRUE(udpard_tx_push(
      &fx.tx, 0, 10000, 1U, udpard_prio_nominal, transfer_id, udpard_make_subject_endpoint(333U), payload, NULL));
    udpard_tx_poll(&fx.tx, 1, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_EQUAL_size_t(1, fx.eject.count);
    TEST_ASSERT_EQUAL_UINT64(transfer_id & UDPARD_TRANSFER_ID_MASK, fx.eject.items[0].transfer_id);

    fixture_fini(&fx);
}

static void test_tx_capacity_failure(void)
{
    // Reject a transfer that cannot ever fit into the queue.
    tx_fixture_t fx = { 0 };
    fixture_init(&fx, 1U, 128U, true);
    byte_t data[600] = { 0 };
    TEST_ASSERT_FALSE(udpard_tx_push(&fx.tx,
                                     0,
                                     10000,
                                     1U,
                                     udpard_prio_nominal,
                                     1U,
                                     udpard_make_subject_endpoint(444U),
                                     make_scattered(data, 600U),
                                     NULL));
    TEST_ASSERT_EQUAL_UINT64(1U, fx.tx.errors_capacity);
    TEST_ASSERT_EQUAL_size_t(0U, fx.transfer_alloc.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0U, fx.payload_alloc.allocated_fragments);
    fixture_fini(&fx);
}

static void test_tx_spool_oom_rollback(void)
{
    // Abort a partially built spool cleanly on payload-frame OOM.
    tx_fixture_t fx = { 0 };
    fixture_init(&fx, 4U, 128U, true);
    fx.payload_alloc.limit_fragments = 1U;
    byte_t data[600]                 = { 0 };
    TEST_ASSERT_FALSE(udpard_tx_push(&fx.tx,
                                     0,
                                     10000,
                                     1U,
                                     udpard_prio_nominal,
                                     2U,
                                     udpard_make_subject_endpoint(555U),
                                     make_scattered(data, 600U),
                                     NULL));
    TEST_ASSERT_EQUAL_UINT64(1U, fx.tx.errors_oom);
    TEST_ASSERT_EQUAL_size_t(0U, fx.tx.enqueued_frames_count);
    TEST_ASSERT_EQUAL_size_t(0U, fx.transfer_alloc.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0U, fx.payload_alloc.allocated_fragments);
    fixture_fini(&fx);
}

static void test_tx_refcount_retention(void)
{
    // Retain one frame, then verify capacity handling while no transfer remains to sacrifice.
    tx_fixture_t fx = { 0 };
    fixture_init(&fx, 2U, 128U, true);
    fx.eject.retain_first = true;
    const byte_t data[]   = { 0xAB };
    TEST_ASSERT_TRUE(udpard_tx_push(&fx.tx,
                                    0,
                                    10000,
                                    1U,
                                    udpard_prio_nominal,
                                    3U,
                                    udpard_make_subject_endpoint(666U),
                                    make_scattered(data, 1U),
                                    NULL));
    udpard_tx_poll(&fx.tx, 1, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_EQUAL_size_t(1U, fx.eject.count);
    TEST_ASSERT_EQUAL_size_t(1U, fx.payload_alloc.allocated_fragments);
    TEST_ASSERT_EQUAL_UINT16(0U, udpard_tx_pending_ifaces(&fx.tx));

    // With only a retained frame left, queue-space reclamation cannot sacrifice anything.
    byte_t large[600] = { 0 };
    TEST_ASSERT_FALSE(udpard_tx_push(&fx.tx,
                                     2,
                                     10000,
                                     1U,
                                     udpard_prio_nominal,
                                     4U,
                                     udpard_make_subject_endpoint(667U),
                                     make_scattered(large, 600U),
                                     NULL));
    TEST_ASSERT_EQUAL_UINT64(1U, fx.tx.errors_capacity);
    TEST_ASSERT_EQUAL_UINT16(0U, udpard_tx_pending_ifaces(NULL));
    udpard_tx_refcount_inc((udpard_bytes_t){ 0 });
    udpard_tx_refcount_dec((udpard_bytes_t){ 0 });

    udpard_tx_free(&fx.tx);
    TEST_ASSERT_EQUAL_size_t(0U, fx.transfer_alloc.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(1U, fx.payload_alloc.allocated_fragments);
    udpard_tx_refcount_dec(fx.eject.held);
    TEST_ASSERT_EQUAL_size_t(0U, fx.payload_alloc.allocated_fragments);
    instrumented_allocator_reset(&fx.transfer_alloc);
    instrumented_allocator_reset(&fx.payload_alloc);
}

static void test_tx_validate_and_compare_deadlines(void)
{
    // Exercise constructor validation and deadline comparison branches directly.
    instrumented_allocator_t payload_alloc = { 0 };
    instrumented_allocator_new(&payload_alloc);
    const udpard_mem_t              valid  = instrumented_allocator_make_resource(&payload_alloc);
    const udpard_tx_mem_resources_t memory = {
        .transfer = { 0 },
        .payload  = { valid, valid, valid },
    };
    udpard_tx_t tx = { 0 };
    TEST_ASSERT_FALSE(udpard_tx_new(&tx, 1U, 1U, 1U, memory, &tx_vtable));

    tx_transfer_t early = { 0 };
    tx_transfer_t late  = { 0 };
    early.deadline      = 1;
    late.deadline       = 2;
    TEST_ASSERT_EQUAL_INT32(-1, tx_cavl_compare_deadline(&early, &late.index_deadline));
    TEST_ASSERT_EQUAL_INT32(+1, tx_cavl_compare_deadline(&late, &early.index_deadline));

    tx_transfer_t a  = { 0 };
    tx_transfer_t b  = { 0 };
    a.deadline       = 3;
    b.deadline       = 3;
    const int32_t ab = tx_cavl_compare_deadline(&a, &b.index_deadline);
    const int32_t ba = tx_cavl_compare_deadline(&b, &a.index_deadline);
    TEST_ASSERT_TRUE((ab == -1) || (ab == +1));
    TEST_ASSERT_EQUAL_INT32(-ab, ba);
    instrumented_allocator_reset(&payload_alloc);
}

static void test_tx_transfer_alloc_oom(void)
{
    // Fail transfer-object allocation before any payload spool is attempted.
    tx_fixture_t fx = { 0 };
    fixture_init(&fx, 4U, 128U, true);
    fx.transfer_alloc.limit_fragments = 0U;
    const byte_t data[]               = { 0x5AU };
    TEST_ASSERT_FALSE(udpard_tx_push(&fx.tx,
                                     0,
                                     10000,
                                     1U,
                                     udpard_prio_nominal,
                                     10U,
                                     udpard_make_subject_endpoint(777U),
                                     make_scattered(data, sizeof(data)),
                                     NULL));
    TEST_ASSERT_EQUAL_UINT64(1U, fx.tx.errors_oom);
    TEST_ASSERT_EQUAL_size_t(0U, fx.transfer_alloc.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0U, fx.payload_alloc.allocated_fragments);
    fixture_fini(&fx);
}

static void test_tx_eject_stall(void)
{
    // If ejection makes no progress, pending queues should remain intact.
    tx_fixture_t fx = { 0 };
    fixture_init(&fx, 8U, 128U, false);
    const byte_t data[] = { 0x11U, 0x22U };
    TEST_ASSERT_TRUE(udpard_tx_push(&fx.tx,
                                    0,
                                    100000,
                                    1U,
                                    udpard_prio_nominal,
                                    11U,
                                    udpard_make_subject_endpoint(778U),
                                    make_scattered(data, sizeof(data)),
                                    NULL));
    TEST_ASSERT_EQUAL_UINT16(1U, udpard_tx_pending_ifaces(&fx.tx));
    udpard_tx_poll(&fx.tx, 1, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_EQUAL_size_t(0U, fx.eject.count);
    TEST_ASSERT_EQUAL_UINT16(1U, udpard_tx_pending_ifaces(&fx.tx));
    fixture_fini(&fx);
}

static void test_tx_sharing_branches(void)
{
    // Exercise shareability and prediction logic with mixed allocators.
    instrumented_allocator_t alloc_a = { 0 };
    instrumented_allocator_t alloc_b = { 0 };
    instrumented_allocator_new(&alloc_a);
    instrumented_allocator_new(&alloc_b);
    const udpard_mem_t mem_a = instrumented_allocator_make_resource(&alloc_a);
    const udpard_mem_t mem_b = instrumented_allocator_make_resource(&alloc_b);
    TEST_ASSERT_TRUE(tx_spool_shareable(128U, mem_a, 128U, mem_a, 120U));
    TEST_ASSERT_TRUE(tx_spool_shareable(256U, mem_a, 128U, mem_a, 120U));
    TEST_ASSERT_FALSE(tx_spool_shareable(256U, mem_a, 128U, mem_a, 200U));
    TEST_ASSERT_FALSE(tx_spool_shareable(128U, mem_a, 128U, mem_b, 120U));

    const size_t       mtu[UDPARD_IFACE_COUNT_MAX]          = { 128U, 128U, 128U };
    const udpard_mem_t mem[UDPARD_IFACE_COUNT_MAX]          = { mem_a, mem_b, mem_a };
    const size_t       predicted_nonshareable               = tx_predict_frame_count(mtu, mem, 0x7U, 10U);
    const udpard_mem_t mem_all_same[UDPARD_IFACE_COUNT_MAX] = { mem_a, mem_a, mem_a };
    const size_t       predicted_shareable                  = tx_predict_frame_count(mtu, mem_all_same, 0x7U, 10U);
    TEST_ASSERT_EQUAL_size_t(2U, predicted_nonshareable);
    TEST_ASSERT_EQUAL_size_t(1U, predicted_shareable);

    // Push over two interfaces backed by different payload memory resources to prevent deduplication.
    instrumented_allocator_t alloc_transfer = { 0 };
    instrumented_allocator_t alloc_p0       = { 0 };
    instrumented_allocator_t alloc_p1       = { 0 };
    instrumented_allocator_t alloc_p2       = { 0 };
    instrumented_allocator_new(&alloc_transfer);
    instrumented_allocator_new(&alloc_p0);
    instrumented_allocator_new(&alloc_p1);
    instrumented_allocator_new(&alloc_p2);
    const udpard_tx_mem_resources_t tx_mem = {
        .transfer = instrumented_allocator_make_resource(&alloc_transfer),
        .payload  = { instrumented_allocator_make_resource(&alloc_p0),
                      instrumented_allocator_make_resource(&alloc_p1),
                      instrumented_allocator_make_resource(&alloc_p2) },
    };
    udpard_tx_t tx = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 0x0102030405060708ULL, 42U, 8U, tx_mem, &tx_vtable));
    tx.user   = NULL;
    tx.mtu[0] = tx.mtu[1] = tx.mtu[2] = 128U;
    const byte_t p[]                  = { 0xABU };
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    10000,
                                    (1U << 0U) | (1U << 1U),
                                    udpard_prio_nominal,
                                    12U,
                                    udpard_make_subject_endpoint(779U),
                                    make_scattered(p, 1U),
                                    NULL));
    TEST_ASSERT_EQUAL_size_t(2U, tx.enqueued_frames_count);
    udpard_tx_free(&tx);
    TEST_ASSERT_EQUAL_size_t(0U, alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0U, alloc_p0.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0U, alloc_p1.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0U, alloc_p2.allocated_fragments);
    instrumented_allocator_reset(&alloc_transfer);
    instrumented_allocator_reset(&alloc_p0);
    instrumented_allocator_reset(&alloc_p1);
    instrumented_allocator_reset(&alloc_p2);
    instrumented_allocator_reset(&alloc_a);
    instrumented_allocator_reset(&alloc_b);
}

void setUp(void) {}
void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_tx_subject_ejection);
    RUN_TEST(test_tx_unicast_endpoints);
    RUN_TEST(test_tx_expiration);
    RUN_TEST(test_tx_sacrifice_oldest);
    RUN_TEST(test_tx_transfer_id_masking);
    RUN_TEST(test_tx_capacity_failure);
    RUN_TEST(test_tx_spool_oom_rollback);
    RUN_TEST(test_tx_refcount_retention);
    RUN_TEST(test_tx_validate_and_compare_deadlines);
    RUN_TEST(test_tx_transfer_alloc_oom);
    RUN_TEST(test_tx_eject_stall);
    RUN_TEST(test_tx_sharing_branches);
    return UNITY_END();
}
