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

// Looks up a transfer by transfer-ID.
static tx_transfer_t* find_transfer_by_id(udpard_tx_t* const tx, const uint64_t transfer_id)
{
    if (tx == NULL) {
        return NULL;
    }
    const tx_key_transfer_id_t key = { .transfer_id = transfer_id, .seq_no = 0 };
    tx_transfer_t* const       tr  = CAVL2_TO_OWNER(
      cavl2_lower_bound(tx->index_transfer_id, &key, &tx_cavl_compare_transfer_id), tx_transfer_t, index_transfer_id);
    return ((tr != NULL) && (tr->transfer_id == transfer_id)) ? tr : NULL;
}

// Counts transfers by transfer-ID and kind.
static size_t count_transfers_by_id_and_kind(udpard_tx_t* const tx, const uint64_t transfer_id, const frame_kind_t kind)
{
    if (tx == NULL) {
        return 0;
    }
    size_t                     count = 0;
    const tx_key_transfer_id_t key   = { .transfer_id = transfer_id, .seq_no = 0 };
    for (tx_transfer_t* tr =
           CAVL2_TO_OWNER(cavl2_lower_bound(tx->index_transfer_id, &key, &tx_cavl_compare_transfer_id),
                          tx_transfer_t,
                          index_transfer_id);
         (tr != NULL) && (tr->transfer_id == transfer_id);
         tr = CAVL2_TO_OWNER(cavl2_next_greater(&tr->index_transfer_id), tx_transfer_t, index_transfer_id)) {
        if (tr->kind == kind) {
            count++;
        }
    }
    return count;
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
               .kind                  = frame_msg_best,
               .transfer_payload_size = 12345,
               .transfer_id           = 0xBADC0FFEE0DDF00DULL,
               .sender_uid            = 0x0123456789ABCDEFULL,
        };
        (void)header_serialize(buffer.data, meta, 12345, 0, 0);
        TEST_ASSERT_EQUAL(HEADER_SIZE_BYTES, sizeof(buffer.data));
        // Verify version and priority in first byte
        TEST_ASSERT_EQUAL((HEADER_VERSION | ((unsigned)udpard_prio_fast << 5U)), buffer.data[0]);
        TEST_ASSERT_EQUAL_UINT8(frame_msg_best, buffer.data[1]);
    }
    // Test case 2: Reliable flag
    {
        header_buffer_t buffer;
        const meta_t    meta = {
               .priority              = udpard_prio_nominal,
               .kind                  = frame_msg_reliable,
               .transfer_payload_size = 5000,
               .transfer_id           = 0xAAAAAAAAAAAAAAAAULL,
               .sender_uid            = 0xBBBBBBBBBBBBBBBBULL,
        };
        (void)header_serialize(buffer.data, meta, 100, 200, 0);
        TEST_ASSERT_EQUAL((HEADER_VERSION | ((unsigned)udpard_prio_nominal << 5U)), buffer.data[0]);
        TEST_ASSERT_EQUAL_UINT8(frame_msg_reliable, buffer.data[1]);
    }
    // Test case 3: ACK flag
    {
        header_buffer_t buffer;
        const meta_t    meta = {
               .priority              = udpard_prio_nominal,
               .kind                  = frame_ack,
               .transfer_payload_size = 0,
               .transfer_id           = 0x1111111111111111ULL,
               .sender_uid            = 0x2222222222222222ULL,
        };
        (void)header_serialize(buffer.data, meta, 0, 0, 0);
        TEST_ASSERT_EQUAL((HEADER_VERSION | ((unsigned)udpard_prio_nominal << 5U)), buffer.data[0]);
        TEST_ASSERT_EQUAL_UINT8(frame_ack, buffer.data[1]);
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
    // Reject null transfer vtable.
    bad_transfer.transfer = (udpard_mem_t){ .vtable = NULL, .context = NULL };
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
    tr->priority     = udpard_prio_fast;
    tr->deadline     = 10;
    tr->staged_until = 1;
    tr->seq_no       = 1;
    tr->transfer_id  = 7;
    tr->kind         = frame_msg_best;
    // Insert with stable ordering keys.
    (void)cavl2_find_or_insert(&tx.index_staged, tr, tx_cavl_compare_staged, &tr->index_staged, cavl2_trivial_factory);
    (void)cavl2_find_or_insert(
      &tx.index_deadline, tr, tx_cavl_compare_deadline, &tr->index_deadline, cavl2_trivial_factory);
    const tx_key_transfer_id_t key_id = { .transfer_id = tr->transfer_id, .seq_no = tr->seq_no };
    (void)cavl2_find_or_insert(
      &tx.index_transfer_id, &key_id, tx_cavl_compare_transfer_id, &tr->index_transfer_id, cavl2_trivial_factory);
    enlist_head(&tx.agewise, &tr->agewise);
    tx_transfer_retire(&tx, tr, true);
    TEST_ASSERT_NULL(tx.index_staged);
    TEST_ASSERT_NULL(tx.index_transfer_id);
    TEST_ASSERT_NULL(tx.index_deadline);
    instrumented_allocator_reset(&alloc_transfer);
    instrumented_allocator_reset(&alloc_payload);
}

static void test_tx_comparators_and_feedback(void)
{
    tx_transfer_t tr;
    mem_zero(sizeof(tr), &tr);
    tr.staged_until = 5;
    tr.deadline     = 7;
    tr.transfer_id  = 20;
    tr.seq_no       = 9;

    // Staged/deadline comparisons both ways.
    tx_transfer_t key = tr;
    key.staged_until  = 6;
    TEST_ASSERT_EQUAL(1, tx_cavl_compare_staged(&key, &tr.index_staged));
    key.staged_until = 4;
    TEST_ASSERT_EQUAL(-1, tx_cavl_compare_staged(&key, &tr.index_staged));
    key.deadline = 8;
    TEST_ASSERT_EQUAL(1, tx_cavl_compare_deadline(&key, &tr.index_deadline));
    key.deadline = 6;
    TEST_ASSERT_EQUAL(-1, tx_cavl_compare_deadline(&key, &tr.index_deadline));

    // Equality returns zero for staged and deadline comparators.
    key.staged_until = tr.staged_until;
    key.seq_no       = tr.seq_no;
    TEST_ASSERT_EQUAL(0, tx_cavl_compare_staged(&key, &tr.index_staged));
    key.deadline = tr.deadline;
    key.seq_no   = tr.seq_no;
    TEST_ASSERT_EQUAL(0, tx_cavl_compare_deadline(&key, &tr.index_deadline));
    // Staged comparator covers seq_no branches.
    key.staged_until = tr.staged_until;
    key.seq_no       = tr.seq_no - 1;
    TEST_ASSERT_EQUAL(-1, tx_cavl_compare_staged(&key, &tr.index_staged));
    key.seq_no = tr.seq_no + 1;
    TEST_ASSERT_EQUAL(1, tx_cavl_compare_staged(&key, &tr.index_staged));
    // Deadline comparator covers seq_no branches.
    key.deadline = tr.deadline;
    key.seq_no   = tr.seq_no - 1;
    TEST_ASSERT_EQUAL(-1, tx_cavl_compare_deadline(&key, &tr.index_deadline));
    key.seq_no = tr.seq_no + 1;
    TEST_ASSERT_EQUAL(1, tx_cavl_compare_deadline(&key, &tr.index_deadline));

    // Transfer-ID comparator covers all branches.
    tx_key_transfer_id_t key_id = { .transfer_id = 10, .seq_no = tr.seq_no };
    TEST_ASSERT_EQUAL(-1, tx_cavl_compare_transfer_id(&key_id, &tr.index_transfer_id));
    key_id.transfer_id = 30;
    TEST_ASSERT_EQUAL(1, tx_cavl_compare_transfer_id(&key_id, &tr.index_transfer_id));
    key_id.transfer_id = tr.transfer_id;
    key_id.seq_no      = tr.seq_no - 1;
    TEST_ASSERT_EQUAL(-1, tx_cavl_compare_transfer_id(&key_id, &tr.index_transfer_id));
    key_id.seq_no = tr.seq_no + 1;
    TEST_ASSERT_EQUAL(1, tx_cavl_compare_transfer_id(&key_id, &tr.index_transfer_id));
    key_id.seq_no = tr.seq_no;
    TEST_ASSERT_EQUAL(0, tx_cavl_compare_transfer_id(&key_id, &tr.index_transfer_id));
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
                                .kind                  = frame_msg_best,
                                .transfer_payload_size = (uint32_t)payload.bytes.size,
                                .transfer_id           = 1,
                                .sender_uid            = 1,
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
    TEST_ASSERT_FALSE(
      udpard_tx_push(&tx, 0, 1000, iface_bitmap_01, udpard_prio_fast, 11, big_payload, NULL, UDPARD_USER_CONTEXT_NULL));
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
    victim.transfer_id = 9;
    victim.seq_no      = 1;
    victim.kind        = frame_msg_best;
    // Insert into deadline index with stable key.
    (void)cavl2_find_or_insert(
      &tx_sac.index_deadline, &victim, tx_cavl_compare_deadline, &victim.index_deadline, cavl2_trivial_factory);
    (void)cavl2_find_or_insert(&tx_sac.index_transfer_id,
                               &(tx_key_transfer_id_t){ .transfer_id = victim.transfer_id, .seq_no = victim.seq_no },
                               tx_cavl_compare_transfer_id,
                               &victim.index_transfer_id,
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
      &tx, 0, 1000, iface_bitmap_01, udpard_prio_fast, 12, make_scattered(NULL, 0), NULL, UDPARD_USER_CONTEXT_NULL));
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
    TEST_ASSERT_FALSE(
      udpard_tx_push(&tx, 0, 1000, iface_bitmap_01, udpard_prio_fast, 13, big_payload, NULL, UDPARD_USER_CONTEXT_NULL));
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
    TEST_ASSERT_TRUE(udpard_tx_push(
      &tx_be, 0, 1000, iface_bitmap_01, udpard_prio_fast, 43, make_scattered(NULL, 0), NULL, UDPARD_USER_CONTEXT_NULL));
    udpard_rx_t rx_be = { .tx = &tx_be };
    tx_receive_ack(&rx_be, 22, 43);
    TEST_ASSERT_NOT_NULL(find_transfer_by_id(&tx_be, 43));
    udpard_tx_free(&tx_be);

    // Ack lookup misses when the lower bound has a different transfer-ID.
    udpard_tx_t tx_miss = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx_miss,
      10U,
      1U,
      8U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    tx_transfer_t* miss = mem_alloc(mem.transfer, sizeof(tx_transfer_t));
    mem_zero(sizeof(*miss), miss);
    miss->kind        = frame_msg_best;
    miss->transfer_id = 100;
    miss->seq_no      = 1;
    miss->deadline    = 50;
    miss->priority    = udpard_prio_fast;
    cavl2_find_or_insert(
      &tx_miss.index_deadline, miss, tx_cavl_compare_deadline, &miss->index_deadline, cavl2_trivial_factory);
    cavl2_find_or_insert(&tx_miss.index_transfer_id,
                         &(tx_key_transfer_id_t){ .transfer_id = miss->transfer_id, .seq_no = miss->seq_no },
                         tx_cavl_compare_transfer_id,
                         &miss->index_transfer_id,
                         cavl2_trivial_factory);
    enlist_head(&tx_miss.agewise, &miss->agewise);
    udpard_rx_t rx_miss = { .tx = &tx_miss };
    tx_receive_ack(&rx_miss, 21, 99);
    TEST_ASSERT_NOT_NULL(find_transfer_by_id(&tx_miss, 100));
    udpard_tx_free(&tx_miss);

    // ACK acceptance skips colliding P2P transfers from other remotes.
    udpard_tx_t tx_coll_rx = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx_coll_rx,
      10U,
      1U,
      8U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    udpard_rx_t      rx_coll = { .tx = &tx_coll_rx };
    feedback_state_t fb_a    = { 0 };
    feedback_state_t fb_b    = { 0 };
    const uint64_t   coll_id = 55;
    // Insert first colliding transfer.
    tx_transfer_t* tr_a = mem_alloc(mem.transfer, sizeof(tx_transfer_t));
    mem_zero(sizeof(*tr_a), tr_a);
    tr_a->kind           = frame_msg_reliable;
    tr_a->is_p2p         = true;
    tr_a->transfer_id    = coll_id;
    tr_a->seq_no         = 1;
    tr_a->deadline       = 10;
    tr_a->priority       = udpard_prio_fast;
    tr_a->p2p_remote.uid = 1001;
    tr_a->user           = make_user_context(&fb_a);
    tr_a->feedback       = record_feedback;
    cavl2_find_or_insert(
      &tx_coll_rx.index_deadline, tr_a, tx_cavl_compare_deadline, &tr_a->index_deadline, cavl2_trivial_factory);
    cavl2_find_or_insert(&tx_coll_rx.index_transfer_id,
                         &(tx_key_transfer_id_t){ .transfer_id = tr_a->transfer_id, .seq_no = tr_a->seq_no },
                         tx_cavl_compare_transfer_id,
                         &tr_a->index_transfer_id,
                         cavl2_trivial_factory);
    enlist_head(&tx_coll_rx.agewise, &tr_a->agewise);
    // Insert second colliding transfer with different remote UID.
    tx_transfer_t* tr_b = mem_alloc(mem.transfer, sizeof(tx_transfer_t));
    mem_zero(sizeof(*tr_b), tr_b);
    tr_b->kind           = frame_msg_reliable;
    tr_b->is_p2p         = true;
    tr_b->transfer_id    = coll_id;
    tr_b->seq_no         = 2;
    tr_b->deadline       = 10;
    tr_b->priority       = udpard_prio_fast;
    tr_b->p2p_remote.uid = 1002;
    tr_b->user           = make_user_context(&fb_b);
    tr_b->feedback       = record_feedback;
    cavl2_find_or_insert(
      &tx_coll_rx.index_deadline, tr_b, tx_cavl_compare_deadline, &tr_b->index_deadline, cavl2_trivial_factory);
    cavl2_find_or_insert(&tx_coll_rx.index_transfer_id,
                         &(tx_key_transfer_id_t){ .transfer_id = tr_b->transfer_id, .seq_no = tr_b->seq_no },
                         tx_cavl_compare_transfer_id,
                         &tr_b->index_transfer_id,
                         cavl2_trivial_factory);
    enlist_head(&tx_coll_rx.agewise, &tr_b->agewise);
    // Accept ack for the second transfer only.
    tx_receive_ack(&rx_coll, tr_b->p2p_remote.uid, coll_id);
    TEST_ASSERT_EQUAL_size_t(0, fb_a.count);
    TEST_ASSERT_EQUAL_size_t(1, fb_b.count);
    TEST_ASSERT_EQUAL_size_t(1, count_transfers_by_id_and_kind(&tx_coll_rx, coll_id, frame_msg_reliable));
    // Accept ack for the first transfer.
    tx_receive_ack(&rx_coll, tr_a->p2p_remote.uid, coll_id);
    TEST_ASSERT_EQUAL_size_t(1, fb_a.count);
    TEST_ASSERT_EQUAL_size_t(0, count_transfers_by_id_and_kind(&tx_coll_rx, coll_id, frame_msg_reliable));
    udpard_tx_free(&tx_coll_rx);

    // Ack suppressed when coverage not improved.
    udpard_tx_t tx2 = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx2,
      11U,
      2U,
      4U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    tx_transfer_t* prior = mem_alloc(mem.transfer, sizeof(tx_transfer_t));
    mem_zero(sizeof(*prior), prior);
    prior->kind                    = frame_ack;
    prior->is_p2p                  = true;
    prior->transfer_id             = 8;
    prior->seq_no                  = 1;
    prior->deadline                = 100;
    prior->priority                = udpard_prio_fast;
    prior->p2p_remote.uid          = 9;
    prior->p2p_remote.endpoints[0] = make_ep(3);
    cavl2_find_or_insert(
      &tx2.index_deadline, prior, tx_cavl_compare_deadline, &prior->index_deadline, cavl2_trivial_factory);
    cavl2_find_or_insert(&tx2.index_transfer_id,
                         &(tx_key_transfer_id_t){ .transfer_id = prior->transfer_id, .seq_no = prior->seq_no },
                         tx_cavl_compare_transfer_id,
                         &prior->index_transfer_id,
                         cavl2_trivial_factory);
    enlist_head(&tx2.agewise, &prior->agewise);
    rx.errors_ack_tx = 0;
    rx.tx            = &tx2;
    tx_send_ack(&rx, 0, udpard_prio_fast, 8, (udpard_remote_t){ .uid = 9, .endpoints = { make_ep(3) } });
    TEST_ASSERT_EQUAL_UINT64(0, rx.errors_ack_tx);
    TEST_ASSERT_EQUAL_UINT32(0U, udpard_tx_pending_ifaces(&tx2));
    tx_transfer_retire(&tx2, prior, false);
    udpard_tx_free(&tx2);

    // Ack search skips prior with the same transfer-ID but different UID.
    udpard_tx_t tx_uid = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx_uid,
      11U,
      2U,
      4U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    rx.tx                    = &tx_uid;
    rx.errors_ack_tx         = 0;
    tx_transfer_t* prior_uid = mem_alloc(mem.transfer, sizeof(tx_transfer_t));
    mem_zero(sizeof(*prior_uid), prior_uid);
    prior_uid->kind                    = frame_ack;
    prior_uid->is_p2p                  = true;
    prior_uid->transfer_id             = 7;
    prior_uid->seq_no                  = 1;
    prior_uid->deadline                = 100;
    prior_uid->priority                = udpard_prio_fast;
    prior_uid->p2p_remote.uid          = 1;
    prior_uid->p2p_remote.endpoints[0] = make_ep(2);
    cavl2_find_or_insert(
      &tx_uid.index_deadline, prior_uid, tx_cavl_compare_deadline, &prior_uid->index_deadline, cavl2_trivial_factory);
    cavl2_find_or_insert(&tx_uid.index_transfer_id,
                         &(tx_key_transfer_id_t){ .transfer_id = prior_uid->transfer_id, .seq_no = prior_uid->seq_no },
                         tx_cavl_compare_transfer_id,
                         &prior_uid->index_transfer_id,
                         cavl2_trivial_factory);
    enlist_head(&tx_uid.agewise, &prior_uid->agewise);
    tx_send_ack(&rx, 0, udpard_prio_fast, 7, (udpard_remote_t){ .uid = 2, .endpoints = { make_ep(3) } });
    TEST_ASSERT_EQUAL_size_t(2, count_transfers_by_id_and_kind(&tx_uid, 7, frame_ack));
    udpard_tx_free(&tx_uid);

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
    tx_send_ack(&rx, 0, udpard_prio_fast, 9, (udpard_remote_t){ .uid = 11, .endpoints = { make_ep(4) } });
    tx_send_ack(&rx, 0, udpard_prio_fast, 9, (udpard_remote_t){ .uid = 11, .endpoints = { make_ep(4), make_ep(5) } });
    TEST_ASSERT_NOT_EQUAL(0U, udpard_tx_pending_ifaces(&tx3));
    udpard_tx_free(&tx3);

    // Ack search ignores prior with different transfer-ID.
    udpard_tx_t tx_mismatch = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx_mismatch,
      12U,
      3U,
      4U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    rx.tx                    = &tx_mismatch;
    rx.errors_ack_tx         = 0;
    tx_transfer_t* prior_ack = mem_alloc(mem.transfer, sizeof(tx_transfer_t));
    mem_zero(sizeof(*prior_ack), prior_ack);
    prior_ack->kind                    = frame_ack;
    prior_ack->is_p2p                  = true;
    prior_ack->transfer_id             = 100;
    prior_ack->seq_no                  = 1;
    prior_ack->deadline                = 100;
    prior_ack->priority                = udpard_prio_fast;
    prior_ack->p2p_remote.uid          = 9;
    prior_ack->p2p_remote.endpoints[0] = make_ep(3);
    cavl2_find_or_insert(&tx_mismatch.index_deadline,
                         prior_ack,
                         tx_cavl_compare_deadline,
                         &prior_ack->index_deadline,
                         cavl2_trivial_factory);
    cavl2_find_or_insert(&tx_mismatch.index_transfer_id,
                         &(tx_key_transfer_id_t){ .transfer_id = prior_ack->transfer_id, .seq_no = prior_ack->seq_no },
                         tx_cavl_compare_transfer_id,
                         &prior_ack->index_transfer_id,
                         cavl2_trivial_factory);
    enlist_head(&tx_mismatch.agewise, &prior_ack->agewise);
    tx_send_ack(&rx, 0, udpard_prio_fast, 99, (udpard_remote_t){ .uid = 9, .endpoints = { make_ep(4) } });
    TEST_ASSERT_EQUAL_UINT64(0, rx.errors_ack_tx);
    TEST_ASSERT_EQUAL_size_t(1, count_transfers_by_id_and_kind(&tx_mismatch, 100, frame_ack));
    TEST_ASSERT_EQUAL_size_t(1, count_transfers_by_id_and_kind(&tx_mismatch, 99, frame_ack));
    udpard_tx_free(&tx_mismatch);

    // Ack emission ignores colliding non-ack transfers.
    udpard_tx_t tx_coll_ack = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx_coll_ack,
      12U,
      3U,
      4U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    rx.tx            = &tx_coll_ack;
    rx.errors_ack_tx = 0;
    TEST_ASSERT_TRUE(udpard_tx_push(&tx_coll_ack,
                                    0,
                                    1000,
                                    iface_bitmap_01,
                                    udpard_prio_fast,
                                    60,
                                    make_scattered(NULL, 0),
                                    record_feedback,
                                    make_user_context(&fstate)));
    TEST_ASSERT_EQUAL_size_t(1, count_transfers_by_id_and_kind(&tx_coll_ack, 60, frame_msg_reliable));
    tx_send_ack(&rx, 0, udpard_prio_fast, 60, (udpard_remote_t){ .uid = 77, .endpoints = { make_ep(7) } });
    TEST_ASSERT_EQUAL_UINT64(0, rx.errors_ack_tx);
    TEST_ASSERT_EQUAL_size_t(1, count_transfers_by_id_and_kind(&tx_coll_ack, 60, frame_msg_reliable));
    TEST_ASSERT_EQUAL_size_t(1, count_transfers_by_id_and_kind(&tx_coll_ack, 60, frame_ack));
    udpard_tx_free(&tx_coll_ack);

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
    tx_send_ack(&rx, 0, udpard_prio_fast, 2, (udpard_remote_t){ .uid = 1, .endpoints = { make_ep(6) } });
    TEST_ASSERT_GREATER_THAN_UINT64(0, rx.errors_ack_tx);
    udpard_tx_free(&tx6);

    // Ack push failure increments error.
    udpard_rx_t rx_fail = { .tx = NULL };
    tx_send_ack(&rx_fail, 0, udpard_prio_fast, 1, (udpard_remote_t){ 0 });
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
    exp->transfer_id = 66;
    exp->seq_no      = 1;
    exp->kind        = frame_msg_reliable;
    exp->user        = make_user_context(&fstate);
    exp->feedback    = record_feedback;
    // Insert into deadline index with stable key.
    (void)cavl2_find_or_insert(
      &tx4.index_deadline, exp, tx_cavl_compare_deadline, &exp->index_deadline, cavl2_trivial_factory);
    (void)cavl2_find_or_insert(&tx4.index_transfer_id,
                               &(tx_key_transfer_id_t){ .transfer_id = exp->transfer_id, .seq_no = exp->seq_no },
                               tx_cavl_compare_transfer_id,
                               &exp->index_transfer_id,
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
    staged.staged_until    = 0;
    staged.deadline        = 100;
    staged.priority        = udpard_prio_fast;
    staged.seq_no          = 1;
    staged.transfer_id     = 7;
    staged.kind            = frame_msg_reliable;
    tx_frame_t dummy_frame = { 0 };
    staged.head[0] = staged.cursor[0] = &dummy_frame;
    // Insert into staged index with stable key.
    cavl2_find_or_insert(
      &tx5.index_staged, &staged, tx_cavl_compare_staged, &staged.index_staged, cavl2_trivial_factory);
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
    tr.kind         = frame_msg_reliable;

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

static void test_tx_push_p2p_success(void)
{
    // Successful P2P push uses valid endpoints and returns a transfer-ID.
    instrumented_allocator_t alloc = { 0 };
    instrumented_allocator_new(&alloc);
    udpard_tx_mem_resources_t mem = { .transfer = instrumented_allocator_make_resource(&alloc) };
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        mem.payload[i] = instrumented_allocator_make_resource(&alloc);
    }
    udpard_tx_t tx = { 0 };
    TEST_ASSERT_TRUE(udpard_tx_new(
      &tx,
      1U,
      2U,
      8U,
      mem,
      &(udpard_tx_vtable_t){ .eject_subject = eject_subject_with_flag, .eject_p2p = eject_p2p_with_flag }));
    const udpard_remote_t remote  = { .uid = 42, .endpoints = { make_ep(11) } };
    uint64_t              out_tid = 0;
    TEST_ASSERT_TRUE(udpard_tx_push_p2p(
      &tx, 0, 10, udpard_prio_fast, remote, make_scattered(NULL, 0), NULL, UDPARD_USER_CONTEXT_NULL, &out_tid));
    TEST_ASSERT_NOT_EQUAL(0U, out_tid);
    TEST_ASSERT_TRUE(udpard_tx_cancel(&tx, out_tid, false));
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
                                                   make_scattered(NULL, 0),
                                                   record_feedback,
                                                   make_user_context(&fstate)));
    TEST_ASSERT_NOT_NULL(find_transfer_by_id(&tx, 200));
    TEST_ASSERT_TRUE(udpard_tx_cancel(&tx, 200, true));
    TEST_ASSERT_NULL(find_transfer_by_id(&tx, 200));
    TEST_ASSERT_EQUAL_size_t(1, fstate.count);
    TEST_ASSERT_EQUAL_UINT32(0, fstate.last.acknowledgements);
    TEST_ASSERT_EQUAL_size_t(0, tx.enqueued_frames_count);
    TEST_ASSERT_FALSE(udpard_tx_cancel(&tx, 200, true));

    // Best-effort transfer cancels quietly.
    TEST_ASSERT_GREATER_THAN_UINT32(
      0,
      udpard_tx_push(
        &tx, 0, 100, iface_bitmap_1, udpard_prio_fast, 201, make_scattered(NULL, 0), NULL, UDPARD_USER_CONTEXT_NULL));
    TEST_ASSERT_TRUE(udpard_tx_cancel(&tx, 201, false));
    TEST_ASSERT_EQUAL_size_t(0, tx.enqueued_frames_count);

    // Collisions cancel all reliable transfers with the same ID.
    fstate.count           = 0;
    const uint64_t coll_id = 300;
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    100,
                                    iface_bitmap_1,
                                    udpard_prio_fast,
                                    coll_id,
                                    make_scattered(NULL, 0),
                                    record_feedback,
                                    make_user_context(&fstate)));
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    100,
                                    iface_bitmap_1,
                                    udpard_prio_fast,
                                    coll_id,
                                    make_scattered(NULL, 0),
                                    record_feedback,
                                    make_user_context(&fstate)));
    TEST_ASSERT_EQUAL_size_t(2, count_transfers_by_id_and_kind(&tx, coll_id, frame_msg_reliable));
    TEST_ASSERT_TRUE(udpard_tx_cancel(&tx, coll_id, true));
    TEST_ASSERT_EQUAL_size_t(0, count_transfers_by_id_and_kind(&tx, coll_id, frame_msg_reliable));
    TEST_ASSERT_EQUAL_size_t(2, fstate.count);

    // Best-effort collisions do not cancel reliable transfers.
    fstate.count            = 0;
    const uint64_t coll_id2 = 301;
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    100,
                                    iface_bitmap_1,
                                    udpard_prio_fast,
                                    coll_id2,
                                    make_scattered(NULL, 0),
                                    record_feedback,
                                    make_user_context(&fstate)));
    TEST_ASSERT_TRUE(udpard_tx_push(&tx,
                                    0,
                                    100,
                                    iface_bitmap_1,
                                    udpard_prio_fast,
                                    coll_id2,
                                    make_scattered(NULL, 0),
                                    NULL,
                                    UDPARD_USER_CONTEXT_NULL));
    TEST_ASSERT_EQUAL_size_t(1, count_transfers_by_id_and_kind(&tx, coll_id2, frame_msg_reliable));
    TEST_ASSERT_EQUAL_size_t(1, count_transfers_by_id_and_kind(&tx, coll_id2, frame_msg_best));
    TEST_ASSERT_TRUE(udpard_tx_cancel(&tx, coll_id2, false));
    TEST_ASSERT_EQUAL_size_t(1, count_transfers_by_id_and_kind(&tx, coll_id2, frame_msg_reliable));
    TEST_ASSERT_EQUAL_size_t(0, count_transfers_by_id_and_kind(&tx, coll_id2, frame_msg_best));
    TEST_ASSERT_TRUE(udpard_tx_cancel(&tx, coll_id2, true));
    TEST_ASSERT_EQUAL_size_t(0, count_transfers_by_id_and_kind(&tx, coll_id2, frame_msg_reliable));

    // Cancel misses when ID is not present but tree is non-empty.
    TEST_ASSERT_TRUE(udpard_tx_push(
      &tx, 0, 100, iface_bitmap_1, udpard_prio_fast, 400, make_scattered(NULL, 0), NULL, UDPARD_USER_CONTEXT_NULL));
    TEST_ASSERT_FALSE(udpard_tx_cancel(&tx, 399, false));
    TEST_ASSERT_NOT_NULL(find_transfer_by_id(&tx, 400));
    TEST_ASSERT_TRUE(udpard_tx_cancel(&tx, 400, false));
    TEST_ASSERT_NULL(find_transfer_by_id(&tx, 400));

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
      &tx, 0, 1000, iface_bitmap_1, udpard_prio_fast, 100, make_scattered(NULL, 0), NULL, UDPARD_USER_CONTEXT_NULL));
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
    TEST_ASSERT_TRUE(udpard_tx_push(
      &tx, 0, 1000, iface_bitmap_1, udpard_prio_nominal, 200, make_scattered(NULL, 0), NULL, UDPARD_USER_CONTEXT_NULL));
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
    RUN_TEST(test_tx_push_p2p_success);
    RUN_TEST(test_tx_cancel);
    RUN_TEST(test_tx_spool_deduplication);
    RUN_TEST(test_tx_eject_only_from_poll);
    RUN_TEST(test_tx_ack_and_scheduler);
    return UNITY_END();
}
