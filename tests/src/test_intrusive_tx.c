/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c> // NOLINT(bugprone-suspicious-include)
#include "helpers.h"
#include <unity.h>

typedef struct
{
    size_t count;
    bool   allow;
} eject_state_t;

typedef struct
{
    size_t               count;
    udpard_tx_feedback_t last;
} feedback_state_t;

typedef struct
{
    size_t      count;
    udpard_us_t when[8];
} eject_log_t;

static void noop_free(void* const user, const size_t size, void* const pointer)
{
    (void)user;
    (void)size;
    (void)pointer;
}

// No-op memory vtable for guard checks.
static const udpard_mem_vtable_t mem_vtable_noop_alloc = { .base = { .free = noop_free }, .alloc = dummy_alloc };

// Ejects with a configurable outcome (subject variant).
static bool eject_subject_with_flag(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection)
{
    (void)ejection;
    eject_state_t* const st = (eject_state_t*)tx->user;
    if (st != NULL) {
        st->count++;
        return st->allow;
    }
    return true;
}

// Ejects with a configurable outcome (P2P variant).
static bool eject_p2p_with_flag(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection, udpard_udpip_ep_t dest)
{
    (void)ejection;
    (void)dest;
    eject_state_t* const st = (eject_state_t*)tx->user;
    if (st != NULL) {
        st->count++;
        return st->allow;
    }
    return true;
}

// Records ejection timestamps for later inspection (subject variant).
static bool eject_subject_with_log(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection)
{
    eject_log_t* const st = (eject_log_t*)tx->user;
    if ((st != NULL) && (st->count < (sizeof(st->when) / sizeof(st->when[0])))) {
        st->when[st->count++] = ejection->now;
    }
    return true;
}

// Records ejection timestamps for later inspection (P2P variant).
static bool eject_p2p_with_log(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection, udpard_udpip_ep_t dest)
{
    (void)dest;
    eject_log_t* const st = (eject_log_t*)tx->user;
    if ((st != NULL) && (st->count < (sizeof(st->when) / sizeof(st->when[0])))) {
        st->when[st->count++] = ejection->now;
    }
    return true;
}

// Records feedback into the provided state via user context.
static void record_feedback(udpard_tx_t* const tx, const udpard_tx_feedback_t fb)
{
    (void)tx;
    feedback_state_t* const st = (feedback_state_t*)fb.user.ptr[0];
    if (st != NULL) {
        st->count++;
        st->last = fb;
    }
}

// Minimal endpoint helper.
static udpard_udpip_ep_t make_ep(const uint32_t ip) { return (udpard_udpip_ep_t){ .ip = ip, .port = 1U }; }

// Small helpers for intrusive checks.
static size_t frames_for(const size_t mtu, const size_t payload) { return larger(1, (payload + mtu - 1U) / mtu); }
static tx_transfer_t* latest_transfer(udpard_tx_t* const tx)
{
    return LIST_MEMBER(tx->agewise.head, tx_transfer_t, agewise);
}

static void test_bytes_scattered_read(void)
{
    // Skips empty fragments and spans boundaries.
    {
        const byte_t                   frag_a[] = { 1U, 2U, 3U };
        const byte_t                   frag_c[] = { 4U, 5U, 6U, 7U, 8U };
        const udpard_bytes_scattered_t frag3    = { .bytes = { .size = sizeof(frag_c), .data = frag_c }, .next = NULL };
        const udpard_bytes_scattered_t frag2    = { .bytes = { .size = 0U, .data = NULL }, .next = &frag3 };
        const udpard_bytes_scattered_t frag1  = { .bytes = { .size = sizeof(frag_a), .data = frag_a }, .next = &frag2 };
        const udpard_bytes_scattered_t frag0  = { .bytes = { .size = 0U, .data = NULL }, .next = &frag1 };
        bytes_scattered_reader_t       reader = { .cursor = &frag0, .position = 0U };
        byte_t                         out[7] = { 0 };
        bytes_scattered_read(&reader, sizeof(out), out);
        const byte_t expected[] = { 1U, 2U, 3U, 4U, 5U, 6U, 7U };
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, out, sizeof(expected));
        TEST_ASSERT_EQUAL_PTR(&frag3, reader.cursor);
        TEST_ASSERT_EQUAL_size_t(4U, reader.position);
    }

    // Resumes mid-fragment when data remains.
    {
        const byte_t                   frag_tail[] = { 9U, 10U, 11U };
        const udpard_bytes_scattered_t frag        = { .bytes = { .size = sizeof(frag_tail), .data = frag_tail },
                                                       .next  = NULL };
        bytes_scattered_reader_t       reader      = { .cursor = &frag, .position = 1U };
        byte_t                         out[2]      = { 0 };
        bytes_scattered_read(&reader, sizeof(out), out);
        const byte_t expected[] = { 10U, 11U };
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, out, sizeof(out));
        TEST_ASSERT_EQUAL_PTR(&frag, reader.cursor);
        TEST_ASSERT_EQUAL_size_t(frag.bytes.size, reader.position);
    }

    // Size accounts for chained fragments.
    {
        const byte_t                   frag_a[] = { 1U, 2U };
        const byte_t                   frag_b[] = { 3U, 4U, 5U };
        const udpard_bytes_scattered_t tail     = { .bytes = { .size = sizeof(frag_b), .data = frag_b }, .next = NULL };
        const udpard_bytes_scattered_t head = { .bytes = { .size = sizeof(frag_a), .data = frag_a }, .next = &tail };
        TEST_ASSERT_EQUAL_size_t(sizeof(frag_a) + sizeof(frag_b), bytes_scattered_size(head));
    }
}

static void test_tx_serialize_header(void)
{
    typedef struct
    {
        byte_t data[HEADER_SIZE_BYTES];
    } header_buffer_t;

    // Test case 1: Basic header serialization
    {
        header_buffer_t buffer;
        const meta_t    meta = {
               .priority              = udpard_prio_fast,
               .flag_reliable         = false,
               .flag_acknowledgement  = false,
               .transfer_payload_size = 12345,
               .transfer_id           = 0xBADC0FFEE0DDF00DULL,
               .sender_uid            = 0x0123456789ABCDEFULL,
               .topic_hash            = 0xFEDCBA9876543210ULL,
        };
        (void)header_serialize(buffer.data, meta, 12345, 0, 0);
        TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES, sizeof(buffer.data));
        // Verify version and priority in first byte
        TEST_ASSERT_EQUAL((HEADER_VERSION | ((unsigned)udpard_prio_fast << 5U)), buffer.data[0]);
    }
    // Test case 2: Reliable flag
    {
        header_buffer_t buffer;
        const meta_t    meta = {
               .priority              = udpard_prio_nominal,
               .flag_reliable         = true,
               .flag_acknowledgement  = false,
               .transfer_payload_size = 5000,
               .transfer_id           = 0xAAAAAAAAAAAAAAAAULL,
               .sender_uid            = 0xBBBBBBBBBBBBBBBBULL,
               .topic_hash            = 0xCCCCCCCCCCCCCCCCULL,
        };
        (void)header_serialize(buffer.data, meta, 100, 200, 0);
        TEST_ASSERT_EQUAL((HEADER_VERSION | ((unsigned)udpard_prio_nominal << 5U)), buffer.data[0]);
        TEST_ASSERT_EQUAL(HEADER_FLAG_RELIABLE, buffer.data[1]);
    }
    // Test case 3: ACK flag
    {
        header_buffer_t buffer;
        const meta_t    meta = {
               .priority              = udpard_prio_nominal,
               .flag_reliable         = false,
               .flag_acknowledgement  = true,
               .transfer_payload_size = 16,
               .transfer_id           = 0x1111111111111111ULL,
               .sender_uid            = 0x2222222222222222ULL,
               .topic_hash            = 0x3333333333333333ULL,
        };
        (void)header_serialize(buffer.data, meta, 0, 0, 0);
        TEST_ASSERT_EQUAL((HEADER_VERSION | ((unsigned)udpard_prio_nominal << 5U)), buffer.data[0]);
        TEST_ASSERT_EQUAL(HEADER_FLAG_ACKNOWLEDGEMENT, buffer.data[1]);
    }
}

static void test_tx_validation_and_free(void)
{
    // Invalid memory config fails fast.
    udpard_tx_mem_resources_t bad = { 0 };
    TEST_ASSERT_FALSE(tx_validate_mem_resources(bad));
    // Reject payload vtables with missing hooks.
    const udpard_mem_vtable_t vtable_no_free  = { .base = { .free = NULL }, .alloc = dummy_alloc };
    const udpard_mem_vtable_t vtable_no_alloc = { .base = { .free = noop_free }, .alloc = NULL };
    const udpard_mem_vtable_t vtable_ok       = { .base = { .free = noop_free }, .alloc = dummy_alloc };
    udpard_tx_mem_resources_t bad_payload     = { .transfer = { .vtable = &vtable_ok, .context = NULL } };
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        bad_payload.payload[i] = (udpard_mem_t){ .vtable = &vtable_no_free, .context = NULL };
    }
    TEST_ASSERT_FALSE(tx_validate_mem_resources(bad_payload));
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        bad_payload.payload[i] = (udpard_mem_t){ .vtable = &vtable_no_alloc, .context = NULL };
    }
    TEST_ASSERT_FALSE(tx_validate_mem_resources(bad_payload));
    // Reject transfer vtables with missing hooks.
    udpard_tx_mem_resources_t bad_transfer = bad_payload;
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        bad_transfer.payload[i] = (udpard_mem_t){ .vtable = &vtable_ok, .context = NULL };
    }
    bad_transfer.transfer = (udpard_mem_t){ .vtable = &vtable_no_free, .context = NULL };
    TEST_ASSERT_FALSE(tx_validate_mem_resources(bad_transfer));
    bad_transfer.transfer = (udpard_mem_t){ .vtable = &vtable_no_alloc, .context = NULL };
    TEST_ASSERT_FALSE(tx_validate_mem_resources(bad_transfer));

    instrumented_allocator_t alloc_transfer = { 0 };
    instrumented_allocator_t alloc_payload  = { 0 };
    instrumented_allocator_new(&alloc_transfer);
    instrumented_allocator_new(&alloc_payload);
    udpard_tx_mem_resources_t mem = { .transfer = instrumented_allocator_make_resource(&alloc_transfer) };
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        mem.payload[i] = instrumented_allocator_make_resource(&alloc_payload);
    }

    // Populate indexes then free to hit all removal paths.
    udpard_tx_t tx = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx,
      1U,
      1U,
      4U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    tx_transfer_t* const tr = mem_alloc(mem.transfer, sizeof(tx_transfer_t));
    mem_zero(sizeof(*tr), tr);
    tr->priority           = udpard_prio_fast;
    tr->deadline           = 10;
    tr->staged_until       = 1;
    tr->remote_topic_hash  = 99;
    tr->remote_transfer_id = 100;
    tx_transfer_key_t key  = { .topic_hash = 5, .transfer_id = 7 };
    // Insert with stable ordering keys.
    const tx_time_key_t staged_key   = { .time        = tr->staged_until,
                                         .topic_hash  = tr->topic_hash,
                                         .transfer_id = tr->transfer_id };
    const tx_time_key_t deadline_key = { .time        = tr->deadline,
                                         .topic_hash  = tr->topic_hash,
                                         .transfer_id = tr->transfer_id };
    (void)cavl2_find_or_insert(
      &tx.index_staged, &staged_key, tx_cavl_compare_staged, &tr->index_staged, cavl2_trivial_factory);
    (void)cavl2_find_or_insert(
      &tx.index_deadline, &deadline_key, tx_cavl_compare_deadline, &tr->index_deadline, cavl2_trivial_factory);
    (void)cavl2_find_or_insert(
      &tx.index_transfer, &key, tx_cavl_compare_transfer, &tr->index_transfer, cavl2_trivial_factory);
    (void)cavl2_find_or_insert(
      &tx.index_transfer_ack, &key, tx_cavl_compare_transfer_remote, &tr->index_transfer_ack, cavl2_trivial_factory);
    enlist_head(&tx.agewise, &tr->agewise);
    tx_transfer_retire(&tx, tr, true);
    TEST_ASSERT_NULL(tx.index_staged);
    TEST_ASSERT_NULL(tx.index_transfer_ack);
    instrumented_allocator_reset(&alloc_transfer);
    instrumented_allocator_reset(&alloc_payload);
}

static void test_tx_comparators_and_feedback(void)
{
    tx_transfer_t tr;
    mem_zero(sizeof(tr), &tr);
    tr.staged_until       = 5;
    tr.deadline           = 7;
    tr.topic_hash         = 10;
    tr.transfer_id        = 20;
    tr.remote_topic_hash  = 3;
    tr.remote_transfer_id = 4;

    // Staged/deadline comparisons both ways.
    tx_time_key_t tkey = { .time = 6, .topic_hash = tr.topic_hash, .transfer_id = tr.transfer_id };
    TEST_ASSERT_EQUAL(1, tx_cavl_compare_staged(&tkey, &tr.index_staged));
    tkey.time = 4;
    TEST_ASSERT_EQUAL(-1, tx_cavl_compare_staged(&tkey, &tr.index_staged));
    tkey.time = 8;
    TEST_ASSERT_EQUAL(1, tx_cavl_compare_deadline(&tkey, &tr.index_deadline));
    tkey.time = 6;
    TEST_ASSERT_EQUAL(-1, tx_cavl_compare_deadline(&tkey, &tr.index_deadline));
    // Staged comparator covers topic_hash/transfer_id branches.
    tkey = (tx_time_key_t){ .time = tr.staged_until, .topic_hash = tr.topic_hash - 1, .transfer_id = tr.transfer_id };
    TEST_ASSERT_EQUAL(-1, tx_cavl_compare_staged(&tkey, &tr.index_staged));
    tkey.topic_hash = tr.topic_hash + 1;
    TEST_ASSERT_EQUAL(1, tx_cavl_compare_staged(&tkey, &tr.index_staged));
    tkey.topic_hash  = tr.topic_hash;
    tkey.transfer_id = tr.transfer_id - 1;
    TEST_ASSERT_EQUAL(-1, tx_cavl_compare_staged(&tkey, &tr.index_staged));
    tkey.transfer_id = tr.transfer_id + 1;
    TEST_ASSERT_EQUAL(1, tx_cavl_compare_staged(&tkey, &tr.index_staged));
    // Deadline comparator covers topic_hash/transfer_id branches.
    tkey = (tx_time_key_t){ .time = tr.deadline, .topic_hash = tr.topic_hash - 1, .transfer_id = tr.transfer_id };
    TEST_ASSERT_EQUAL(-1, tx_cavl_compare_deadline(&tkey, &tr.index_deadline));
    tkey.topic_hash = tr.topic_hash + 1;
    TEST_ASSERT_EQUAL(1, tx_cavl_compare_deadline(&tkey, &tr.index_deadline));
    tkey.topic_hash  = tr.topic_hash;
    tkey.transfer_id = tr.transfer_id - 1;
    TEST_ASSERT_EQUAL(-1, tx_cavl_compare_deadline(&tkey, &tr.index_deadline));
    tkey.transfer_id = tr.transfer_id + 1;
    TEST_ASSERT_EQUAL(1, tx_cavl_compare_deadline(&tkey, &tr.index_deadline));

    // Transfer comparator covers all branches.
    tx_transfer_key_t key = { .topic_hash = 5, .transfer_id = 1 };
    TEST_ASSERT_EQUAL(-1, tx_cavl_compare_transfer(&key, &tr.index_transfer));
    key.topic_hash = 15;
    TEST_ASSERT_EQUAL(1, tx_cavl_compare_transfer(&key, &tr.index_transfer));
    key.topic_hash  = tr.topic_hash;
    key.transfer_id = 15;
    TEST_ASSERT_EQUAL(-1, tx_cavl_compare_transfer(&key, &tr.index_transfer));
    key.transfer_id = 25;
    TEST_ASSERT_EQUAL(1, tx_cavl_compare_transfer(&key, &tr.index_transfer));
    key.transfer_id = tr.transfer_id;
    TEST_ASSERT_EQUAL(0, tx_cavl_compare_transfer(&key, &tr.index_transfer));

    // Remote comparator mirrors the above.
    tx_transfer_key_t rkey = { .topic_hash = 2, .transfer_id = 1 };
    TEST_ASSERT_EQUAL(-1, tx_cavl_compare_transfer_remote(&rkey, &tr.index_transfer_ack));
    rkey.topic_hash = 5;
    TEST_ASSERT_EQUAL(1, tx_cavl_compare_transfer_remote(&rkey, &tr.index_transfer_ack));
    rkey.topic_hash  = tr.remote_topic_hash;
    rkey.transfer_id = 2;
    TEST_ASSERT_EQUAL(-1, tx_cavl_compare_transfer_remote(&rkey, &tr.index_transfer_ack));
    rkey.transfer_id = 6;
    TEST_ASSERT_EQUAL(1, tx_cavl_compare_transfer_remote(&rkey, &tr.index_transfer_ack));
    rkey.transfer_id = tr.remote_transfer_id;
    TEST_ASSERT_EQUAL(0, tx_cavl_compare_transfer_remote(&rkey, &tr.index_transfer_ack));
}

static void test_tx_spool_and_queue_errors(void)
{
    // OOM in spool after first frame.
    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    alloc_payload.limit_fragments             = 1;
    udpard_tx_t tx                            = { .enqueued_frames_limit = 1, .enqueued_frames_count = 0 };
    tx.memory.payload[0]                      = instrumented_allocator_make_resource(&alloc_payload);
    byte_t                         buffer[64] = { 0 };
    const udpard_bytes_scattered_t payload    = make_scattered(buffer, sizeof(buffer));
    const meta_t                   meta       = {
                                .priority              = udpard_prio_fast,
                                .flag_reliable         = false,
                                .flag_acknowledgement  = false,
                                .transfer_payload_size = (uint32_t)payload.bytes.size,
                                .transfer_id           = 1,
                                .sender_uid            = 1,
                                .topic_hash            = 1,
    };
    TEST_ASSERT_NULL(tx_spool(&tx, tx.memory.payload[0], 32, meta, payload));
    TEST_ASSERT_EQUAL_size_t(0, tx.enqueued_frames_count);
    TEST_ASSERT_EQUAL_UINT64(80, tx_ack_timeout(5, udpard_prio_high, 1));
    instrumented_allocator_reset(&alloc_payload);

    // Capacity exhaustion.
    instrumented_allocator_new(&alloc_payload);
    udpard_tx_mem_resources_t mem = { .transfer = instrumented_allocator_make_resource(&alloc_payload) };
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        mem.payload[i] = instrumented_allocator_make_resource(&alloc_payload);
    }
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx,
      2U,
      2U,
      1U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    byte_t                         big_buf[2000]   = { 0 };
    const udpard_bytes_scattered_t big_payload     = make_scattered(big_buf, sizeof(big_buf));
    const uint16_t                 iface_bitmap_01 = (1U << 0U);
    TEST_ASSERT_FALSE(udpard_tx_push(
      &tx, 0, 1000, iface_bitmap_01, udpard_prio_fast, 11, 1, big_payload, NULL, UDPARD_USER_CONTEXT_NULL));
    TEST_ASSERT_EQUAL_size_t(1, tx.errors_capacity);

    // Immediate rejection when the request exceeds limits.
    udpard_tx_t tx_limit;
    mem_zero(sizeof(tx_limit), &tx_limit);
    tx_limit.enqueued_frames_limit = 1;
    tx_limit.enqueued_frames_count = 0;
    tx_limit.memory.transfer       = (udpard_mem_t){ .vtable = &mem_vtable_noop_alloc, .context = NULL };
    TEST_ASSERT_FALSE(tx_ensure_queue_space(&tx_limit, 3));

    // Sacrifice clears space when the queue is full.
    udpard_tx_t tx_sac;
    mem_zero(sizeof(tx_sac), &tx_sac);
    tx_sac.enqueued_frames_limit = 1;
    tx_sac.enqueued_frames_count = 1;
    tx_sac.errors_sacrifice      = 0;
    tx_sac.memory.transfer       = (udpard_mem_t){ .vtable = &mem_vtable_noop_alloc, .context = NULL };
    tx_transfer_t victim;
    mem_zero(sizeof(victim), &victim);
    victim.priority    = udpard_prio_fast;
    victim.deadline    = 1;
    victim.topic_hash  = 7;
    victim.transfer_id = 9;
    // Insert into deadline index with stable key.
    const tx_time_key_t deadline_key = { .time        = victim.deadline,
                                         .topic_hash  = victim.topic_hash,
                                         .transfer_id = victim.transfer_id };
    (void)cavl2_find_or_insert(
      &tx_sac.index_deadline, &deadline_key, tx_cavl_compare_deadline, &victim.index_deadline, cavl2_trivial_factory);
    (void)cavl2_find_or_insert(
      &tx_sac.index_transfer,
      &(tx_transfer_key_t){ .topic_hash = victim.topic_hash, .transfer_id = victim.transfer_id },
      tx_cavl_compare_transfer,
      &victim.index_transfer,
      cavl2_trivial_factory);
    enlist_head(&tx_sac.agewise, &victim.agewise);
    TEST_ASSERT_FALSE(tx_ensure_queue_space(&tx_sac, 1));
    TEST_ASSERT_EQUAL_size_t(1, tx_sac.errors_sacrifice);

    // Transfer allocation OOM.
    alloc_payload.limit_fragments = 0;
    tx.errors_capacity            = 0;
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx,
      3U,
      3U,
      2U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    TEST_ASSERT_FALSE(udpard_tx_push(
      &tx, 0, 1000, iface_bitmap_01, udpard_prio_fast, 12, 2, make_scattered(NULL, 0), NULL, UDPARD_USER_CONTEXT_NULL));
    TEST_ASSERT_EQUAL_size_t(1, tx.errors_oom);

    // Spool OOM inside tx_push.
    alloc_payload.limit_fragments = 1;
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx,
      4U,
      4U,
      4U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    TEST_ASSERT_FALSE(udpard_tx_push(
      &tx, 0, 1000, iface_bitmap_01, udpard_prio_fast, 13, 3, big_payload, NULL, UDPARD_USER_CONTEXT_NULL));
    TEST_ASSERT_EQUAL_size_t(1, tx.errors_oom);

    // Reliable transfer gets staged.
    alloc_payload.limit_fragments = SIZE_MAX;
    feedback_state_t fstate       = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx,
      5U,
      5U,
      4U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    tx.ack_baseline_timeout = 1;
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    100000,
                                    iface_bitmap_01,
                                    udpard_prio_nominal,
                                    14,
                                    4,
                                    make_scattered(NULL, 0),
                                    record_feedback,
                                    make_user_context(&fstate)));
    TEST_ASSERT_NOT_NULL(tx.index_staged);
    udpard_tx_free(&tx);
    instrumented_allocator_reset(&alloc_payload);
}

static void test_tx_ack_and_scheduler(void)
{
    instrumented_allocator_t alloc = { 0 };
    instrumented_allocator_new(&alloc);
    udpard_tx_mem_resources_t mem = { .transfer = instrumented_allocator_make_resource(&alloc) };
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        mem.payload[i] = instrumented_allocator_make_resource(&alloc);
    }
    const uint16_t iface_bitmap_01 = (1U << 0U);

    // Ack reception triggers feedback.
    feedback_state_t fstate = { 0 };
    udpard_tx_t      tx1    = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx1,
      10U,
      1U,
      8U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    TEST_ASSERT_TRUE(udpard_tx_push(&tx1,
                                    0,
                                    1000,
                                    iface_bitmap_01,
                                    udpard_prio_fast,
                                    21,
                                    42,
                                    make_scattered(NULL, 0),
                                    record_feedback,
                                    make_user_context(&fstate)));
    TEST_ASSERT_EQUAL_UINT32(1U << 0U, udpard_tx_pending_ifaces(&tx1));
    udpard_rx_t rx = { .tx = &tx1 };
    tx_receive_ack(&rx, 21, 42);
    TEST_ASSERT_EQUAL_size_t(1, fstate.count);
    TEST_ASSERT_EQUAL_UINT32(0U, udpard_tx_pending_ifaces(&tx1));
    // Ignore ACKs when RX has no TX.
    rx.tx = NULL;
    tx_receive_ack(&rx, 21, 42);
    udpard_tx_free(&tx1);

    // Best-effort transfers ignore ACKs.
    udpard_tx_t tx_be = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx_be,
      10U,
      1U,
      8U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    TEST_ASSERT_TRUE(udpard_tx_push(&tx_be,
                                    0,
                                    1000,
                                    iface_bitmap_01,
                                    udpard_prio_fast,
                                    22,
                                    43,
                                    make_scattered(NULL, 0),
                                    NULL,
                                    UDPARD_USER_CONTEXT_NULL));
    udpard_rx_t rx_be = { .tx = &tx_be };
    tx_receive_ack(&rx_be, 22, 43);
    TEST_ASSERT_NOT_NULL(tx_transfer_find(&tx_be, 22, 43));
    udpard_tx_free(&tx_be);

    // Ack suppressed when coverage not improved.
    udpard_tx_t tx2 = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx2,
      11U,
      2U,
      4U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    tx_transfer_t prior;
    mem_zero(sizeof(prior), &prior);
    prior.p2p_destination[0] = make_ep(3);
    prior.iface_bitmap       = 1U; // matches p2p_destination[0] being valid
    prior.remote_topic_hash  = 7;
    prior.remote_transfer_id = 8;
    cavl2_find_or_insert(&tx2.index_transfer_ack,
                         &(tx_transfer_key_t){ .topic_hash = 7, .transfer_id = 8 },
                         tx_cavl_compare_transfer_remote,
                         &prior.index_transfer_ack,
                         cavl2_trivial_factory);
    rx.errors_ack_tx = 0;
    rx.tx            = &tx2;
    tx_send_ack(&rx, 0, udpard_prio_fast, 7, 8, (udpard_remote_t){ .uid = 9, .endpoints = { make_ep(3) } });
    TEST_ASSERT_EQUAL_UINT64(0, rx.errors_ack_tx);
    TEST_ASSERT_EQUAL_UINT32(0U, udpard_tx_pending_ifaces(&tx2));
    udpard_tx_free(&tx2);

    // Ack replaced with broader coverage.
    udpard_tx_t tx3 = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx3,
      12U,
      3U,
      4U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    rx.tx = &tx3;
    tx_send_ack(&rx, 0, udpard_prio_fast, 9, 9, (udpard_remote_t){ .uid = 11, .endpoints = { make_ep(4) } });
    tx_send_ack(
      &rx, 0, udpard_prio_fast, 9, 9, (udpard_remote_t){ .uid = 11, .endpoints = { make_ep(4), make_ep(5) } });
    TEST_ASSERT_NOT_EQUAL(0U, udpard_tx_pending_ifaces(&tx3));
    udpard_tx_free(&tx3);

    // Ack push failure with TX present.
    udpard_tx_mem_resources_t fail_mem = { .transfer = { .vtable = &mem_vtable_noop_alloc, .context = NULL } };
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        fail_mem.payload[i] = fail_mem.transfer;
    }
    udpard_tx_t tx6 = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx6,
      15U,
      6U,
      1U,
      fail_mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    rx.errors_ack_tx = 0;
    rx.tx            = &tx6;
    tx_send_ack(&rx, 0, udpard_prio_fast, 2, 2, (udpard_remote_t){ .uid = 1, .endpoints = { make_ep(6) } });
    TEST_ASSERT_GREATER_THAN_UINT64(0, rx.errors_ack_tx);
    udpard_tx_free(&tx6);

    // Ack push failure increments error.
    udpard_rx_t rx_fail = { .tx = NULL };
    tx_send_ack(&rx_fail, 0, udpard_prio_fast, 1, 1, (udpard_remote_t){ 0 });
    TEST_ASSERT_GREATER_THAN_UINT64(0, rx_fail.errors_ack_tx);

    // Expired transfer purge with feedback.
    udpard_tx_t tx4 = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx4,
      13U,
      4U,
      4U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    tx4.errors_expiration = 0;
    tx_transfer_t* exp    = mem_alloc(mem.transfer, sizeof(tx_transfer_t));
    mem_zero(sizeof(*exp), exp);
    exp->deadline    = 1;
    exp->priority    = udpard_prio_slow;
    exp->topic_hash  = 55;
    exp->transfer_id = 66;
    exp->user        = make_user_context(&fstate);
    exp->reliable    = true;
    exp->feedback    = record_feedback;
    // Insert into deadline index with stable key.
    const tx_time_key_t tx4_deadline_key = { .time        = exp->deadline,
                                             .topic_hash  = exp->topic_hash,
                                             .transfer_id = exp->transfer_id };
    (void)cavl2_find_or_insert(
      &tx4.index_deadline, &tx4_deadline_key, tx_cavl_compare_deadline, &exp->index_deadline, cavl2_trivial_factory);
    (void)cavl2_find_or_insert(&tx4.index_transfer,
                               &(tx_transfer_key_t){ .topic_hash = 55, .transfer_id = 66 },
                               tx_cavl_compare_transfer,
                               &exp->index_transfer,
                               cavl2_trivial_factory);
    tx_purge_expired_transfers(&tx4, 2);
    TEST_ASSERT_GREATER_THAN_UINT64(0, tx4.errors_expiration);
    udpard_tx_free(&tx4);

    // Staged promotion re-enqueues transfer.
    udpard_tx_t tx5 = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx5,
      14U,
      5U,
      4U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    tx_transfer_t staged;
    mem_zero(sizeof(staged), &staged);
    staged.staged_until       = 0;
    staged.deadline           = 100;
    staged.priority           = udpard_prio_fast;
    staged.iface_bitmap       = (1U << 0U);
    staged.p2p_destination[0] = make_ep(7);
    tx_frame_t dummy_frame    = { 0 };
    staged.head[0] = staged.cursor[0] = &dummy_frame;
    // Insert into staged index with stable key.
    const tx_time_key_t tx5_staged_key = { .time        = staged.staged_until,
                                           .topic_hash  = staged.topic_hash,
                                           .transfer_id = staged.transfer_id };
    cavl2_find_or_insert(
      &tx5.index_staged, &tx5_staged_key, tx_cavl_compare_staged, &staged.index_staged, cavl2_trivial_factory);
    tx5.ack_baseline_timeout = 1;
    tx_promote_staged_transfers(&tx5, 1);
    TEST_ASSERT_NOT_NULL(tx5.queue[0][staged.priority].head);
    TEST_ASSERT_EQUAL_UINT32(1U << 0U, udpard_tx_pending_ifaces(&tx5));
    // Already-listed transfers stay in the queue.
    tx_promote_staged_transfers(&tx5, 1000);
    TEST_ASSERT_EQUAL_PTR(&staged.queue[0], tx5.queue[0][staged.priority].head);

    // Ejection stops when NIC refuses.
    staged.cursor[0]                   = staged.head[0];
    staged.queue[0].next               = NULL;
    staged.queue[0].prev               = NULL;
    tx5.queue[0][staged.priority].head = &staged.queue[0];
    tx5.queue[0][staged.priority].tail = &staged.queue[0];
    eject_state_t eject_flag           = { .count = 0, .allow = false };
    tx5.vtable = &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag };
    tx5.user   = &eject_flag;
    tx_eject_pending_frames(&tx5, 5, 0);
    TEST_ASSERT_EQUAL_size_t(1, eject_flag.count);
    udpard_tx_free(&tx5);

    instrumented_allocator_reset(&alloc);
}

static void test_tx_stage_if(void)
{
    // Exercises retransmission gating near deadline.
    udpard_tx_t tx          = { 0 };
    tx.ack_baseline_timeout = 10;

    tx_transfer_t tr;
    mem_zero(sizeof(tr), &tr);
    tr.priority     = udpard_prio_nominal;
    tr.deadline     = 1000;
    tr.staged_until = 100;

    udpard_us_t expected = tr.staged_until;

    tx_stage_if(&tx, &tr);
    expected += tx_ack_timeout(tx.ack_baseline_timeout, tr.priority, 0);
    TEST_ASSERT_EQUAL_UINT8(1, tr.epoch);
    TEST_ASSERT_EQUAL(expected, tr.staged_until);
    TEST_ASSERT_NOT_NULL(tx.index_staged);
    cavl2_remove(&tx.index_staged, &tr.index_staged);

    tx_stage_if(&tx, &tr);
    expected += tx_ack_timeout(tx.ack_baseline_timeout, tr.priority, 1);
    TEST_ASSERT_EQUAL_UINT8(2, tr.epoch);
    TEST_ASSERT_EQUAL(expected, tr.staged_until);
    TEST_ASSERT_NOT_NULL(tx.index_staged);
    cavl2_remove(&tx.index_staged, &tr.index_staged);

    tx_stage_if(&tx, &tr);
    expected += tx_ack_timeout(tx.ack_baseline_timeout, tr.priority, 2);
    TEST_ASSERT_EQUAL_UINT8(3, tr.epoch);
    TEST_ASSERT_EQUAL(expected, tr.staged_until);
    TEST_ASSERT_NULL(tx.index_staged);
}

static void test_tx_stage_if_via_tx_push(void)
{
    // Tracks retransmission times via the scheduler.
    instrumented_allocator_t alloc = { 0 };
    instrumented_allocator_new(&alloc);
    udpard_tx_mem_resources_t mem = { .transfer = instrumented_allocator_make_resource(&alloc) };
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        mem.payload[i] = instrumented_allocator_make_resource(&alloc);
    }

    udpard_tx_t        tx  = { 0 };
    eject_log_t        log = { 0 };
    feedback_state_t   fb  = { 0 };
    udpard_tx_vtable_t vt  = { .eject_subject = eject_subject_with_log, .eject_p2p = eject_p2p_with_log };
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 30U, 1U, 4U, mem, &vt));
    tx.user                        = &log;
    tx.ack_baseline_timeout        = 10;
    const uint16_t iface_bitmap_12 = (1U << 0U) | (1U << 1U);

    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    500,
                                    iface_bitmap_12,
                                    udpard_prio_nominal,
                                    77,
                                    1,
                                    make_scattered(NULL, 0),
                                    record_feedback,
                                    make_user_context(&fb)));
    TEST_ASSERT_EQUAL_UINT32(iface_bitmap_12, udpard_tx_pending_ifaces(&tx));

    udpard_tx_poll(&tx, 0, UDPARD_IFACE_BITMAP_ALL);
    udpard_tx_poll(&tx, 160, UDPARD_IFACE_BITMAP_ALL);
    udpard_tx_poll(&tx, 400, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_EQUAL_UINT32(0U, udpard_tx_pending_ifaces(&tx));

    TEST_ASSERT_EQUAL_size_t(4, log.count);
    TEST_ASSERT_EQUAL(0, log.when[0]);
    TEST_ASSERT_EQUAL(0, log.when[1]);
    TEST_ASSERT_EQUAL(160, log.when[2]);
    TEST_ASSERT_EQUAL(160, log.when[3]);
    TEST_ASSERT_NULL(tx.index_staged);
    udpard_tx_free(&tx);
    instrumented_allocator_reset(&alloc);
}

static void test_tx_stage_if_short_deadline(void)
{
    // Ensures retransmission is skipped when deadline is too close.
    instrumented_allocator_t alloc = { 0 };
    instrumented_allocator_new(&alloc);
    udpard_tx_mem_resources_t mem = { .transfer = instrumented_allocator_make_resource(&alloc) };
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        mem.payload[i] = instrumented_allocator_make_resource(&alloc);
    }

    udpard_tx_t        tx  = { 0 };
    eject_log_t        log = { 0 };
    feedback_state_t   fb  = { 0 };
    udpard_tx_vtable_t vt  = { .eject_subject = eject_subject_with_log, .eject_p2p = eject_p2p_with_log };
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 31U, 1U, 4U, mem, &vt));
    tx.user                       = &log;
    tx.ack_baseline_timeout       = 10;
    const uint16_t iface_bitmap_1 = (1U << 0U);

    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    50,
                                    iface_bitmap_1,
                                    udpard_prio_nominal,
                                    78,
                                    1,
                                    make_scattered(NULL, 0),
                                    record_feedback,
                                    make_user_context(&fb)));

    udpard_tx_poll(&tx, 0, UDPARD_IFACE_BITMAP_ALL);
    udpard_tx_poll(&tx, 30, UDPARD_IFACE_BITMAP_ALL);
    udpard_tx_poll(&tx, 60, UDPARD_IFACE_BITMAP_ALL);

    TEST_ASSERT_EQUAL_size_t(1, log.count);
    TEST_ASSERT_EQUAL(0, log.when[0]);
    udpard_tx_free(&tx);
    instrumented_allocator_reset(&alloc);
}

// Cancels transfers and reports outcome.
static void test_tx_cancel(void)
{
    TEST_ASSERT_FALSE(udpard_tx_cancel(NULL, 0, 0));

    instrumented_allocator_t alloc = { 0 };
    instrumented_allocator_new(&alloc);
    udpard_tx_mem_resources_t mem = { .transfer = instrumented_allocator_make_resource(&alloc) };
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        mem.payload[i] = instrumented_allocator_make_resource(&alloc);
    }

    udpard_tx_t        tx             = { 0 };
    feedback_state_t   fstate         = { 0 };
    const uint16_t     iface_bitmap_1 = (1U << 0U);
    udpard_tx_vtable_t vt             = { .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag };
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 20U, 1U, 8U, mem, &vt));

    // Reliable transfer cancels with failure feedback.
    TEST_ASSERT_GREATER_THAN_UINT32(0,
                                    udpard_tx_push(&tx,
                                                   0,
                                                   100,
                                                   iface_bitmap_1,
                                                   udpard_prio_fast,
                                                   200,
                                                   1,
                                                   make_scattered(NULL, 0),
                                                   record_feedback,
                                                   make_user_context(&fstate)));
    TEST_ASSERT_NOT_NULL(tx_transfer_find(&tx, 200, 1));
    TEST_ASSERT_TRUE(udpard_tx_cancel(&tx, 200, 1));
    TEST_ASSERT_NULL(tx_transfer_find(&tx, 200, 1));
    TEST_ASSERT_EQUAL_size_t(1, fstate.count);
    TEST_ASSERT_EQUAL_UINT32(0, fstate.last.acknowledgements);
    TEST_ASSERT_EQUAL_size_t(0, tx.enqueued_frames_count);
    TEST_ASSERT_FALSE(udpard_tx_cancel(&tx, 200, 1));

    // Best-effort transfer cancels quietly.
    TEST_ASSERT_GREATER_THAN_UINT32(0,
                                    udpard_tx_push(&tx,
                                                   0,
                                                   100,
                                                   iface_bitmap_1,
                                                   udpard_prio_fast,
                                                   201,
                                                   2,
                                                   make_scattered(NULL, 0),
                                                   NULL,
                                                   UDPARD_USER_CONTEXT_NULL));
    TEST_ASSERT_TRUE(udpard_tx_cancel(&tx, 201, 2));
    TEST_ASSERT_EQUAL_size_t(0, tx.enqueued_frames_count);

    udpard_tx_free(&tx);
    instrumented_allocator_reset(&alloc);
}

// Cancels all transfers matching a topic hash.
static void test_tx_cancel_all(void)
{
    // NULL self returns zero.
    TEST_ASSERT_EQUAL_size_t(0, udpard_tx_cancel_all(NULL, 0));

    instrumented_allocator_t alloc = { 0 };
    instrumented_allocator_new(&alloc);
    udpard_tx_mem_resources_t mem = { .transfer = instrumented_allocator_make_resource(&alloc) };
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        mem.payload[i] = instrumented_allocator_make_resource(&alloc);
    }

    udpard_tx_t        tx             = { 0 };
    feedback_state_t   fstate         = { 0 };
    eject_state_t      eject          = { .count = 0, .allow = false }; // Block ejection to retain frames.
    const uint16_t     iface_bitmap_1 = (1U << 0U);
    udpard_tx_vtable_t vt             = { .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag };
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 40U, 1U, 16U, mem, &vt));
    tx.user = &eject;

    // Cancel with no matching transfers returns zero.
    TEST_ASSERT_EQUAL_size_t(0, udpard_tx_cancel_all(&tx, 999));

    // Push multiple transfers with different topic hashes.
    // Topic 100: transfers 1, 2, 3 (reliable)
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    1000,
                                    iface_bitmap_1,
                                    udpard_prio_fast,
                                    100,
                                    1,
                                    make_scattered(NULL, 0),
                                    record_feedback,
                                    make_user_context(&fstate)));
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    1000,
                                    iface_bitmap_1,
                                    udpard_prio_fast,
                                    100,
                                    2,
                                    make_scattered(NULL, 0),
                                    record_feedback,
                                    make_user_context(&fstate)));
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    1000,
                                    iface_bitmap_1,
                                    udpard_prio_fast,
                                    100,
                                    3,
                                    make_scattered(NULL, 0),
                                    record_feedback,
                                    make_user_context(&fstate)));
    // Topic 200: transfers 1, 2 (best-effort)
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    1000,
                                    iface_bitmap_1,
                                    udpard_prio_nominal,
                                    200,
                                    1,
                                    make_scattered(NULL, 0),
                                    NULL,
                                    UDPARD_USER_CONTEXT_NULL));
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    1000,
                                    iface_bitmap_1,
                                    udpard_prio_nominal,
                                    200,
                                    2,
                                    make_scattered(NULL, 0),
                                    NULL,
                                    UDPARD_USER_CONTEXT_NULL));
    // Topic 300: transfer 1 (reliable)
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    1000,
                                    iface_bitmap_1,
                                    udpard_prio_low,
                                    300,
                                    1,
                                    make_scattered(NULL, 0),
                                    record_feedback,
                                    make_user_context(&fstate)));

    TEST_ASSERT_EQUAL_size_t(6, tx.enqueued_frames_count);
    TEST_ASSERT_NOT_NULL(tx_transfer_find(&tx, 100, 1));
    TEST_ASSERT_NOT_NULL(tx_transfer_find(&tx, 100, 2));
    TEST_ASSERT_NOT_NULL(tx_transfer_find(&tx, 100, 3));
    TEST_ASSERT_NOT_NULL(tx_transfer_find(&tx, 200, 1));
    TEST_ASSERT_NOT_NULL(tx_transfer_find(&tx, 200, 2));
    TEST_ASSERT_NOT_NULL(tx_transfer_find(&tx, 300, 1));

    // Cancel all topic 100 transfers; feedback invoked for each reliable transfer.
    fstate.count = 0;
    TEST_ASSERT_EQUAL_size_t(3, udpard_tx_cancel_all(&tx, 100));
    TEST_ASSERT_EQUAL_size_t(3, fstate.count);
    TEST_ASSERT_EQUAL_UINT32(0, fstate.last.acknowledgements);
    TEST_ASSERT_NULL(tx_transfer_find(&tx, 100, 1));
    TEST_ASSERT_NULL(tx_transfer_find(&tx, 100, 2));
    TEST_ASSERT_NULL(tx_transfer_find(&tx, 100, 3));
    // Other topics remain.
    TEST_ASSERT_NOT_NULL(tx_transfer_find(&tx, 200, 1));
    TEST_ASSERT_NOT_NULL(tx_transfer_find(&tx, 200, 2));
    TEST_ASSERT_NOT_NULL(tx_transfer_find(&tx, 300, 1));
    TEST_ASSERT_EQUAL_size_t(3, tx.enqueued_frames_count);

    // Cancel topic 200 (best-effort, no feedback).
    fstate.count = 0;
    TEST_ASSERT_EQUAL_size_t(2, udpard_tx_cancel_all(&tx, 200));
    TEST_ASSERT_EQUAL_size_t(0, fstate.count);
    TEST_ASSERT_NULL(tx_transfer_find(&tx, 200, 1));
    TEST_ASSERT_NULL(tx_transfer_find(&tx, 200, 2));
    TEST_ASSERT_NOT_NULL(tx_transfer_find(&tx, 300, 1));
    TEST_ASSERT_EQUAL_size_t(1, tx.enqueued_frames_count);

    // Cancel already-cancelled topic returns zero.
    TEST_ASSERT_EQUAL_size_t(0, udpard_tx_cancel_all(&tx, 100));

    // Cancel last remaining topic.
    fstate.count = 0;
    TEST_ASSERT_EQUAL_size_t(1, udpard_tx_cancel_all(&tx, 300));
    TEST_ASSERT_EQUAL_size_t(1, fstate.count);
    TEST_ASSERT_NULL(tx_transfer_find(&tx, 300, 1));
    TEST_ASSERT_EQUAL_size_t(0, tx.enqueued_frames_count);

    udpard_tx_free(&tx);
    instrumented_allocator_reset(&alloc);
}

// Cancels P2P transfers and reports outcome.
static void test_tx_cancel_p2p(void)
{
    // NULL self returns false.
    TEST_ASSERT_FALSE(udpard_tx_cancel_p2p(NULL, 0, 0));

    instrumented_allocator_t alloc = { 0 };
    instrumented_allocator_new(&alloc);
    udpard_tx_mem_resources_t mem = { .transfer = instrumented_allocator_make_resource(&alloc) };
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        mem.payload[i] = instrumented_allocator_make_resource(&alloc);
    }

    udpard_tx_t        tx     = { 0 };
    feedback_state_t   fstate = { 0 };
    eject_state_t      eject  = { .count = 0, .allow = false };
    udpard_tx_vtable_t vt     = { .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag };
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 50U, 100U, 8U, mem, &vt));
    tx.user = &eject;

    // Push a P2P transfer with feedback (reliable), using out_transfer_id.
    const udpard_remote_t remote  = { .uid = 999, .endpoints = { make_ep(10), make_ep(20) } };
    uint64_t              out_tid = 0;
    TEST_ASSERT_TRUE(udpard_tx_push_p2p(&tx,
                                        0,
                                        1000,
                                        udpard_prio_fast,
                                        remote,
                                        make_scattered(NULL, 0),
                                        record_feedback,
                                        make_user_context(&fstate),
                                        &out_tid));
    // Verify out_transfer_id matches internal counter.
    TEST_ASSERT_EQUAL_UINT64(100, out_tid); // initial p2p_transfer_id was 100
    // P2P transfers are indexed by (remote.uid, internal_transfer_id).
    TEST_ASSERT_NOT_NULL(tx_transfer_find(&tx, remote.uid, out_tid));

    // Cancel using the returned transfer_id from out_transfer_id.
    TEST_ASSERT_TRUE(udpard_tx_cancel_p2p(&tx, remote.uid, out_tid));
    TEST_ASSERT_NULL(tx_transfer_find(&tx, remote.uid, out_tid));
    TEST_ASSERT_EQUAL_size_t(1, fstate.count);
    TEST_ASSERT_EQUAL_UINT32(0, fstate.last.acknowledgements);
    // Cancelling again returns false (already cancelled).
    TEST_ASSERT_FALSE(udpard_tx_cancel_p2p(&tx, remote.uid, out_tid));

    // Cancelling with wrong destination_uid returns false.
    fstate.count      = 0;
    uint64_t out_tid2 = 0;
    TEST_ASSERT_TRUE(udpard_tx_push_p2p(&tx,
                                        0,
                                        1000,
                                        udpard_prio_fast,
                                        remote,
                                        make_scattered(NULL, 0),
                                        record_feedback,
                                        make_user_context(&fstate),
                                        &out_tid2));
    TEST_ASSERT_FALSE(udpard_tx_cancel_p2p(&tx, 888, out_tid2)); // wrong destination
    TEST_ASSERT_NOT_NULL(tx_transfer_find(&tx, remote.uid, out_tid2));
    TEST_ASSERT_EQUAL_size_t(0, fstate.count); // feedback not invoked

    // Cancelling with wrong transfer_id returns false.
    TEST_ASSERT_FALSE(udpard_tx_cancel_p2p(&tx, remote.uid, 12345)); // wrong transfer_id
    TEST_ASSERT_NOT_NULL(tx_transfer_find(&tx, remote.uid, out_tid2));

    // Cancel with correct parameters works.
    TEST_ASSERT_TRUE(udpard_tx_cancel_p2p(&tx, remote.uid, out_tid2));
    TEST_ASSERT_NULL(tx_transfer_find(&tx, remote.uid, out_tid2));
    TEST_ASSERT_EQUAL_size_t(1, fstate.count);

    // Best-effort P2P transfer cancels quietly (no feedback); using NULL for out_transfer_id.
    fstate.count      = 0;
    uint64_t out_tid3 = 0;
    TEST_ASSERT_TRUE(udpard_tx_push_p2p(
      &tx, 0, 1000, udpard_prio_nominal, remote, make_scattered(NULL, 0), NULL, UDPARD_USER_CONTEXT_NULL, &out_tid3));
    TEST_ASSERT_TRUE(udpard_tx_cancel_p2p(&tx, remote.uid, out_tid3));
    TEST_ASSERT_EQUAL_size_t(0, fstate.count); // no feedback for best-effort

    // Test cancel_all with P2P transfers (using destination_uid as topic_hash).
    // Pass NULL for out_transfer_id to verify optional behavior.
    TEST_ASSERT_TRUE(udpard_tx_push_p2p(
      &tx, 0, 1000, udpard_prio_fast, remote, make_scattered(NULL, 0), NULL, UDPARD_USER_CONTEXT_NULL, NULL));
    TEST_ASSERT_TRUE(udpard_tx_push_p2p(
      &tx, 0, 1000, udpard_prio_fast, remote, make_scattered(NULL, 0), NULL, UDPARD_USER_CONTEXT_NULL, NULL));
    const udpard_remote_t other_remote = { .uid = 777, .endpoints = { make_ep(30) } };
    TEST_ASSERT_TRUE(udpard_tx_push_p2p(
      &tx, 0, 1000, udpard_prio_fast, other_remote, make_scattered(NULL, 0), NULL, UDPARD_USER_CONTEXT_NULL, NULL));
    TEST_ASSERT_EQUAL_size_t(2, udpard_tx_cancel_all(&tx, remote.uid));
    TEST_ASSERT_EQUAL_size_t(1, udpard_tx_cancel_all(&tx, other_remote.uid));

    udpard_tx_free(&tx);
    instrumented_allocator_reset(&alloc);
}

static void test_tx_spool_deduplication(void)
{
    instrumented_allocator_t alloc_a = { 0 };
    instrumented_allocator_t alloc_b = { 0 };
    instrumented_allocator_new(&alloc_a);
    instrumented_allocator_new(&alloc_b);
    udpard_tx_mem_resources_t mem = { .transfer = instrumented_allocator_make_resource(&alloc_a) };
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        mem.payload[i] = instrumented_allocator_make_resource(&alloc_a);
    }

    // Dedup when MTU and allocator match (multi-frame).
    udpard_tx_t tx = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx,
      99U,
      1U,
      16U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    tx.mtu[0]                        = 600;
    tx.mtu[1]                        = 600;
    const uint16_t iface_bitmap_12   = (1U << 0U) | (1U << 1U);
    byte_t         payload_big[1300] = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    1000,
                                    iface_bitmap_12,
                                    udpard_prio_nominal,
                                    1,
                                    1,
                                    make_scattered(payload_big, sizeof(payload_big)),
                                    NULL,
                                    UDPARD_USER_CONTEXT_NULL));
    tx_transfer_t* tr = latest_transfer(&tx);
    TEST_ASSERT_EQUAL_size_t(frames_for(tx.mtu[0], sizeof(payload_big)), tx.enqueued_frames_count);
    TEST_ASSERT_EQUAL_PTR(tr->head[0], tr->head[1]);
    for (tx_frame_t* f = tr->head[0]; f != NULL; f = f->next) {
        TEST_ASSERT_EQUAL_size_t(2, f->refcount);
    }
    udpard_tx_free(&tx);

    // Dedup when payload fits both MTU despite mismatch.
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx,
      99U,
      1U,
      8U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    tx.mtu[0]                 = 500;
    tx.mtu[1]                 = 900;
    byte_t payload_small[300] = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    1000,
                                    iface_bitmap_12,
                                    udpard_prio_nominal,
                                    2,
                                    2,
                                    make_scattered(payload_small, sizeof(payload_small)),
                                    NULL,
                                    UDPARD_USER_CONTEXT_NULL));
    tr = latest_transfer(&tx);
    TEST_ASSERT_EQUAL_size_t(1, tx.enqueued_frames_count);
    TEST_ASSERT_EQUAL_PTR(tr->head[0], tr->head[1]);
    TEST_ASSERT_EQUAL_size_t(2, tr->head[0]->refcount);
    udpard_tx_free(&tx);

    // No dedup when MTU differs and payload exceeds the smaller MTU.
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx,
      99U,
      1U,
      8U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    tx.mtu[0]                 = 500;
    tx.mtu[1]                 = 900;
    byte_t payload_split[800] = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    1000,
                                    iface_bitmap_12,
                                    udpard_prio_nominal,
                                    3,
                                    3,
                                    make_scattered(payload_split, sizeof(payload_split)),
                                    NULL,
                                    UDPARD_USER_CONTEXT_NULL));
    tr = latest_transfer(&tx);
    TEST_ASSERT_EQUAL_size_t(frames_for(tx.mtu[0], sizeof(payload_split)) +
                               frames_for(tx.mtu[1], sizeof(payload_split)),
                             tx.enqueued_frames_count);
    TEST_ASSERT_TRUE(tr->head[0] != tr->head[1]);
    TEST_ASSERT_EQUAL_size_t(1, tr->head[0]->refcount);
    TEST_ASSERT_EQUAL_size_t(1, tr->head[1]->refcount);
    udpard_tx_free(&tx);

    // No dedup when allocators differ even with matching MTU and single frame.
    udpard_tx_mem_resources_t mem_split = { .transfer = instrumented_allocator_make_resource(&alloc_a) };
    mem_split.payload[0]                = instrumented_allocator_make_resource(&alloc_a);
    mem_split.payload[1]                = instrumented_allocator_make_resource(&alloc_b);
    mem_split.payload[2]                = mem_split.payload[0];
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx,
      99U,
      1U,
      8U,
      mem_split,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    tx.mtu[0]               = 600;
    tx.mtu[1]               = 600;
    byte_t payload_one[400] = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    1000,
                                    iface_bitmap_12,
                                    udpard_prio_nominal,
                                    4,
                                    4,
                                    make_scattered(payload_one, sizeof(payload_one)),
                                    NULL,
                                    UDPARD_USER_CONTEXT_NULL));
    tr = latest_transfer(&tx);
    TEST_ASSERT_EQUAL_size_t(2, tx.enqueued_frames_count);
    TEST_ASSERT_TRUE(tr->head[0] != tr->head[1]);
    udpard_tx_free(&tx);

    TEST_ASSERT_EQUAL_size_t(0, alloc_a.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_b.allocated_fragments);
}

// Verifies that eject callbacks are ONLY invoked from udpard_tx_poll(), never from push functions.
static void test_tx_eject_only_from_poll(void)
{
    instrumented_allocator_t alloc = { 0 };
    instrumented_allocator_new(&alloc);
    udpard_tx_mem_resources_t mem = { .transfer = instrumented_allocator_make_resource(&alloc) };
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        mem.payload[i] = instrumented_allocator_make_resource(&alloc);
    }

    udpard_tx_t        tx    = { 0 };
    eject_state_t      eject = { .count = 0, .allow = true };
    udpard_tx_vtable_t vt    = { .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag };
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 60U, 1U, 16U, mem, &vt));
    tx.user = &eject;

    const uint16_t iface_bitmap_1 = (1U << 0U);

    // Push a subject transfer; eject must NOT be called.
    eject.count = 0;
    TEST_ASSERT_TRUE(udpard_tx_push(
      &tx, 0, 1000, iface_bitmap_1, udpard_prio_fast, 100, 1, make_scattered(NULL, 0), NULL, UDPARD_USER_CONTEXT_NULL));
    TEST_ASSERT_EQUAL_size_t(0, eject.count); // eject NOT called from push

    // Push a P2P transfer; eject must NOT be called.
    const udpard_remote_t remote = { .uid = 999, .endpoints = { make_ep(10) } };
    TEST_ASSERT_TRUE(udpard_tx_push_p2p(
      &tx, 0, 1000, udpard_prio_fast, remote, make_scattered(NULL, 0), NULL, UDPARD_USER_CONTEXT_NULL, NULL));
    TEST_ASSERT_EQUAL_size_t(0, eject.count); // eject NOT called from push_p2p

    // Now poll; eject MUST be called.
    udpard_tx_poll(&tx, 0, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_GREATER_THAN_size_t(0, eject.count); // eject called from poll

    // Push more transfers while frames are pending; eject still must NOT be called.
    const size_t eject_count_before = eject.count;
    eject.allow                     = false; // block ejection to keep frames pending
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    1000,
                                    iface_bitmap_1,
                                    udpard_prio_nominal,
                                    200,
                                    2,
                                    make_scattered(NULL, 0),
                                    NULL,
                                    UDPARD_USER_CONTEXT_NULL));
    TEST_ASSERT_EQUAL_size_t(eject_count_before, eject.count); // eject NOT called from push

    TEST_ASSERT_TRUE(udpard_tx_push_p2p(
      &tx, 0, 1000, udpard_prio_nominal, remote, make_scattered(NULL, 0), NULL, UDPARD_USER_CONTEXT_NULL, NULL));
    TEST_ASSERT_EQUAL_size_t(eject_count_before, eject.count); // eject NOT called from push_p2p

    // Poll again; eject called again (but rejected by callback).
    udpard_tx_poll(&tx, 0, UDPARD_IFACE_BITMAP_ALL);
    TEST_ASSERT_GREATER_THAN_size_t(eject_count_before, eject.count); // eject called from poll

    udpard_tx_free(&tx);
    instrumented_allocator_reset(&alloc);
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_bytes_scattered_read);
    RUN_TEST(test_tx_serialize_header);
    RUN_TEST(test_tx_validation_and_free);
    RUN_TEST(test_tx_comparators_and_feedback);
    RUN_TEST(test_tx_spool_and_queue_errors);
    RUN_TEST(test_tx_stage_if);
    RUN_TEST(test_tx_stage_if_via_tx_push);
    RUN_TEST(test_tx_stage_if_short_deadline);
    RUN_TEST(test_tx_cancel);
    RUN_TEST(test_tx_cancel_p2p);
    RUN_TEST(test_tx_cancel_all);
    RUN_TEST(test_tx_spool_deduplication);
    RUN_TEST(test_tx_eject_only_from_poll);
    RUN_TEST(test_tx_ack_and_scheduler);
    return UNITY_END();
}
