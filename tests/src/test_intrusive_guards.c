/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c> // NOLINT(bugprone-suspicious-include)
#include <unity.h>

// Minimal helpers to avoid heap use in guard paths.
static void free_noop(void* const user, const size_t size, void* const pointer)
{
    (void)user;
    (void)size;
    (void)pointer;
}

static void* alloc_stub(void* const user, const size_t size)
{
    (void)size;
    return (size > 0U) ? user : NULL;
}

static void* alloc_alt(void* const user, const size_t size)
{
    (void)size;
    return (byte_t*)user + 1;
}

// Minimal vtables for guard-path allocators.
static const udpard_mem_vtable_t     mem_vtable_stub = { .base = { .free = free_noop }, .alloc = alloc_stub };
static const udpard_mem_vtable_t     mem_vtable_alt  = { .base = { .free = free_noop }, .alloc = alloc_alt };
static const udpard_deleter_vtable_t deleter_vtable  = { .free = free_noop };

static udpard_mem_t make_mem(void* const tag)
{
    const udpard_mem_t out = { .vtable = &mem_vtable_stub, .context = tag };
    return out;
}

static bool eject_subject_stub(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection)
{
    (void)tx;
    (void)ejection;
    return true;
}

static bool eject_p2p_stub(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection, udpard_udpip_ep_t dest)
{
    (void)tx;
    (void)ejection;
    (void)dest;
    return true;
}

static void on_message_stub(udpard_rx_t* const rx, udpard_rx_port_t* const port, udpard_rx_transfer_t transfer)
{
    (void)rx;
    (void)port;
    (void)transfer;
}

static void test_mem_endpoint_list_guards(void)
{
    // mem_same covers identical and divergent resources.
    static char        tag_a;
    static char        tag_b;
    const udpard_mem_t mem_a = make_mem(&tag_a);
    const udpard_mem_t mem_b = make_mem(&tag_b);
    const udpard_mem_t mem_c = { .vtable = &mem_vtable_alt, .context = &tag_a };
    TEST_ASSERT_TRUE(mem_same(mem_a, mem_a));
    TEST_ASSERT_FALSE(mem_same(mem_a, mem_b));
    TEST_ASSERT_FALSE(mem_same(mem_a, mem_c));

    // Endpoint validation handles invalid inputs.
    TEST_ASSERT_TRUE(udpard_is_valid_endpoint((udpard_udpip_ep_t){ .ip = 1U, .port = UDP_PORT }));
    TEST_ASSERT_FALSE(udpard_is_valid_endpoint((udpard_udpip_ep_t){ .ip = 0U, .port = UDP_PORT }));
    TEST_ASSERT_FALSE(udpard_is_valid_endpoint((udpard_udpip_ep_t){ .ip = UINT32_MAX, .port = UDP_PORT }));
    TEST_ASSERT_FALSE(udpard_is_valid_endpoint((udpard_udpip_ep_t){ .ip = 1U, .port = 0U }));

    // is_listed covers empty and populated state.
    udpard_list_t   list   = { 0 };
    udpard_listed_t member = { 0 };
    TEST_ASSERT_FALSE(is_listed(&list, &member));
    enlist_head(&list, &member);
    TEST_ASSERT_TRUE(is_listed(&list, &member));
    // is_listed returns true for non-head members too.
    udpard_listed_t tail = { 0 };
    enlist_head(&list, &tail);
    TEST_ASSERT_TRUE(is_listed(&list, &member));
    // is_listed returns true when next is populated.
    TEST_ASSERT_TRUE(is_listed(&list, &tail));

    // NULL endpoint list yields empty bitmap.
    TEST_ASSERT_EQUAL_UINT16(0U, valid_ep_bitmap(NULL));
}

static void test_fragment_guards(void)
{
    // Null fragments return NULL paths cleanly.
    TEST_ASSERT_NULL(udpard_fragment_seek(NULL, 0));
    TEST_ASSERT_NULL(udpard_fragment_next(NULL));

    // Offsets past the end yield no data.
    static const byte_t      payload[] = { 1U, 2U };
    udpard_fragment_t        frag      = { .index_offset    = { NULL, { NULL, NULL }, 0 },
                                           .offset          = 4U,
                                           .view            = { .size = sizeof(payload), .data = payload },
                                           .origin          = { .size = 0U, .data = NULL },
                                           .payload_deleter = { 0 } };
    const udpard_fragment_t* cursor    = &frag;
    byte_t                   out[2]    = { 0 };
    TEST_ASSERT_NULL(udpard_fragment_seek(&frag, frag.offset + frag.view.size));
    TEST_ASSERT_EQUAL_UINT(0, udpard_fragment_gather(NULL, 0, 1, out));
    TEST_ASSERT_EQUAL_UINT(0, udpard_fragment_gather(&cursor, frag.offset + frag.view.size, 1, out));
    // Offsets inside yield the fragment.
    TEST_ASSERT_EQUAL_PTR(&frag, udpard_fragment_seek(&frag, frag.offset));
}

static void test_header_guard(void)
{
    // Deserializer rejects missing payload pointers.
    meta_t         meta = { 0 };
    udpard_bytes_t payload;
    uint32_t       frame_index  = 0;
    uint32_t       frame_offset = 0;
    uint32_t       prefix_crc   = 0;
    TEST_ASSERT_FALSE(header_deserialize((udpard_bytes_mut_t){ .size = HEADER_SIZE_BYTES, .data = NULL },
                                         &meta,
                                         &frame_index,
                                         &frame_offset,
                                         &prefix_crc,
                                         &payload));
}

static void test_tx_guards(void)
{
    // Prepare reusable TX resources.
    static char               tx_tag;
    static char               payload_tags[UDPARD_IFACE_COUNT_MAX];
    udpard_tx_mem_resources_t mem = { .transfer = make_mem(&tx_tag) };
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        mem.payload[i] = make_mem(&payload_tags[i]);
    }
    const udpard_tx_vtable_t vt_ok = { .eject_subject = eject_subject_stub, .eject_p2p = eject_p2p_stub };

    // Reject bad initialization inputs.
    udpard_tx_t tx = { 0 };
    TEST_ASSERT_FALSE(udpard_tx_new(NULL, 1U, 0U, 1U, mem, &vt_ok));
    TEST_ASSERT_FALSE(udpard_tx_new(&tx, 0U, 0U, 1U, mem, &vt_ok));
    TEST_ASSERT_FALSE(udpard_tx_new(&tx, 1U, 0U, 1U, mem, NULL));
    udpard_tx_mem_resources_t mem_bad = mem;
    mem_bad.payload[0].vtable         = NULL;
    TEST_ASSERT_FALSE(udpard_tx_new(&tx, 1U, 0U, 1U, mem_bad, &vt_ok));
    const udpard_tx_vtable_t vt_bad_subject = { .eject_subject = NULL, .eject_p2p = eject_p2p_stub };
    TEST_ASSERT_FALSE(udpard_tx_new(&tx, 1U, 0U, 1U, mem, &vt_bad_subject));
    const udpard_tx_vtable_t vt_bad_p2p = { .eject_subject = eject_subject_stub, .eject_p2p = NULL };
    TEST_ASSERT_FALSE(udpard_tx_new(&tx, 1U, 0U, 1U, mem, &vt_bad_p2p));
    TEST_ASSERT_TRUE(udpard_tx_new(&tx, 1U, 0U, 2U, mem, &vt_ok));

    // Push helpers reject invalid timing and null handles.
    const uint16_t                 iface_bitmap_1 = (1U << 0U);
    const udpard_bytes_scattered_t empty_payload  = { .bytes = { .size = 0U, .data = NULL }, .next = NULL };
    const udpard_remote_t          remote_ok      = { .uid = 1, .endpoints = { { .ip = 1U, .port = UDP_PORT } } };
    TEST_ASSERT_FALSE(
      udpard_tx_push(&tx, 10, 5, iface_bitmap_1, udpard_prio_fast, 1U, empty_payload, NULL, UDPARD_USER_CONTEXT_NULL));
    TEST_ASSERT_FALSE(
      udpard_tx_push(NULL, 0, 0, iface_bitmap_1, udpard_prio_fast, 1U, empty_payload, NULL, UDPARD_USER_CONTEXT_NULL));
    TEST_ASSERT_FALSE(
      udpard_tx_push_p2p(NULL, 0, 0, udpard_prio_fast, remote_ok, empty_payload, NULL, UDPARD_USER_CONTEXT_NULL, NULL));
    // P2P pushes reject expired deadlines.
    TEST_ASSERT_FALSE(
      udpard_tx_push_p2p(&tx, 2, 1, udpard_prio_fast, remote_ok, empty_payload, NULL, UDPARD_USER_CONTEXT_NULL, NULL));
    // P2P pushes reject negative timestamps.
    TEST_ASSERT_FALSE(
      udpard_tx_push_p2p(&tx, -1, 0, udpard_prio_fast, remote_ok, empty_payload, NULL, UDPARD_USER_CONTEXT_NULL, NULL));
    // Reject invalid payload pointer and empty interface bitmap.
    const udpard_bytes_scattered_t bad_payload = { .bytes = { .size = 1U, .data = NULL }, .next = NULL };
    TEST_ASSERT_FALSE(
      udpard_tx_push(&tx, 0, 1, iface_bitmap_1, udpard_prio_fast, 1U, bad_payload, NULL, UDPARD_USER_CONTEXT_NULL));
    TEST_ASSERT_FALSE(
      udpard_tx_push(&tx, 0, 1, 0U, udpard_prio_fast, 1U, empty_payload, NULL, UDPARD_USER_CONTEXT_NULL));
    const udpard_remote_t remote_bad = { .uid = 1, .endpoints = { { 0 } } };
    TEST_ASSERT_FALSE(
      udpard_tx_push_p2p(&tx, 0, 1, udpard_prio_fast, remote_bad, empty_payload, NULL, UDPARD_USER_CONTEXT_NULL, NULL));

    // Reject invalid timestamps and priority.
    TEST_ASSERT_FALSE(
      udpard_tx_push(&tx, -1, 0, iface_bitmap_1, udpard_prio_fast, 1U, empty_payload, NULL, UDPARD_USER_CONTEXT_NULL));
    // Use an out-of-range priority without a constant enum cast.
    udpard_prio_t  bad_prio     = udpard_prio_optional;
    const unsigned bad_prio_raw = UDPARD_PRIORITY_COUNT;
    memcpy(&bad_prio, &bad_prio_raw, sizeof(bad_prio));
    TEST_ASSERT_FALSE(
      udpard_tx_push(&tx, 0, 1, iface_bitmap_1, bad_prio, 1U, empty_payload, NULL, UDPARD_USER_CONTEXT_NULL));

    // Reject zero local UID.
    const uint64_t saved_uid = tx.local_uid;
    tx.local_uid             = 0U;
    TEST_ASSERT_FALSE(
      udpard_tx_push(&tx, 0, 1, iface_bitmap_1, udpard_prio_fast, 1U, empty_payload, NULL, UDPARD_USER_CONTEXT_NULL));
    tx.local_uid = saved_uid;

    // P2P guard paths cover local UID, priority, and payload pointer.
    uint64_t out_tid = 0;
    tx.local_uid     = 0U;
    TEST_ASSERT_FALSE(udpard_tx_push_p2p(
      &tx, 0, 1, udpard_prio_fast, remote_ok, empty_payload, NULL, UDPARD_USER_CONTEXT_NULL, &out_tid));
    tx.local_uid = saved_uid;
    TEST_ASSERT_FALSE(
      udpard_tx_push_p2p(&tx, 0, 1, bad_prio, remote_ok, empty_payload, NULL, UDPARD_USER_CONTEXT_NULL, &out_tid));
    TEST_ASSERT_FALSE(udpard_tx_push_p2p(
      &tx, 0, 1, udpard_prio_fast, remote_ok, bad_payload, NULL, UDPARD_USER_CONTEXT_NULL, &out_tid));

    // Poll and refcount no-ops on null data.
    udpard_tx_poll(NULL, 0, 0);
    udpard_tx_poll(&tx, (udpard_us_t)-1, 0);
    // Pending ifaces are zero for NULL.
    TEST_ASSERT_EQUAL_UINT16(0U, udpard_tx_pending_ifaces(NULL));
    udpard_tx_refcount_inc((udpard_bytes_t){ .size = 0U, .data = NULL });
    udpard_tx_refcount_dec((udpard_bytes_t){ .size = 0U, .data = NULL });
    udpard_tx_free(NULL);
    udpard_tx_free(&tx);
}

static void test_tx_predictor_sharing(void)
{
    // Shared spool suppresses duplicate frame counts.
    static char        shared_tag[2];
    const udpard_mem_t mem_shared                      = make_mem(&shared_tag[0]);
    const udpard_mem_t mem_arr[UDPARD_IFACE_COUNT_MAX] = { mem_shared, mem_shared, make_mem(&shared_tag[1]) };
    const size_t       mtu[UDPARD_IFACE_COUNT_MAX]     = { 64U, 64U, 128U };
    const uint16_t     iface_bitmap_12                 = (1U << 0U) | (1U << 1U);
    TEST_ASSERT_EQUAL_size_t(1U, tx_predict_frame_count(mtu, mem_arr, iface_bitmap_12, 16U));
    // Non-shared spool counts each interface.
    const udpard_mem_t mem_arr_split[UDPARD_IFACE_COUNT_MAX] = { make_mem(&shared_tag[0]),
                                                                 make_mem(&shared_tag[1]),
                                                                 make_mem(&shared_tag[1]) };
    TEST_ASSERT_EQUAL_size_t(2U, tx_predict_frame_count(mtu, mem_arr_split, iface_bitmap_12, 16U));

    // Shared spool when payload fits smaller MTU despite mismatch.
    const size_t   mtu_mixed[UDPARD_IFACE_COUNT_MAX] = { 64U, 128U, 128U };
    const uint16_t iface_bitmap_01                   = (1U << 0U) | (1U << 1U);
    TEST_ASSERT_EQUAL_size_t(1U, tx_predict_frame_count(mtu_mixed, mem_arr, iface_bitmap_01, 32U));

    // Gapped bitmap exercises the unset-bit branch.
    static char        gap_tag[3];
    const udpard_mem_t mem_gap[UDPARD_IFACE_COUNT_MAX] = { make_mem(&gap_tag[0]),
                                                           make_mem(&gap_tag[1]),
                                                           make_mem(&gap_tag[2]) };
    const size_t       mtu_gap[UDPARD_IFACE_COUNT_MAX] = { 64U, 64U, 64U };
    const uint16_t     iface_bitmap_02                 = (1U << 0U) | (1U << 2U);
    TEST_ASSERT_EQUAL_size_t(2U, tx_predict_frame_count(mtu_gap, mem_gap, iface_bitmap_02, 16U));
}

static void test_rx_guards(void)
{
    // RX port creation guards reject invalid parameters.
    static char                     rx_tag_a;
    static char                     rx_tag_b;
    const udpard_rx_mem_resources_t rx_mem = { .session  = make_mem(&rx_tag_a),
                                               .slot     = make_mem(&rx_tag_a),
                                               .fragment = make_mem(&rx_tag_b) };
    const udpard_rx_port_vtable_t   rx_vtb = { .on_message = on_message_stub };
    udpard_rx_port_t                port;
    TEST_ASSERT_FALSE(udpard_rx_port_new(NULL, 0, rx_mem, &rx_vtb));
    TEST_ASSERT_FALSE(udpard_rx_port_new(&port, 0, rx_mem, NULL));
    const udpard_rx_port_vtable_t rx_vtb_no_msg = { .on_message = NULL };
    TEST_ASSERT_FALSE(udpard_rx_port_new(&port, 0, rx_mem, &rx_vtb_no_msg));
    udpard_rx_mem_resources_t bad_rx_mem = rx_mem;
    bad_rx_mem.session.vtable            = NULL;
    TEST_ASSERT_FALSE(udpard_rx_port_new(&port, 0, bad_rx_mem, &rx_vtb));
    // rx_validate_mem_resources rejects missing hooks.
    const udpard_mem_vtable_t vtable_no_free  = { .base = { .free = NULL }, .alloc = alloc_stub };
    const udpard_mem_vtable_t vtable_no_alloc = { .base = { .free = free_noop }, .alloc = NULL };
    udpard_rx_mem_resources_t bad_session     = rx_mem;
    bad_session.session.vtable                = &vtable_no_free;
    TEST_ASSERT_FALSE(rx_validate_mem_resources(bad_session));
    bad_session.session.vtable = &vtable_no_alloc;
    TEST_ASSERT_FALSE(rx_validate_mem_resources(bad_session));
    udpard_rx_mem_resources_t bad_slot = rx_mem;
    bad_slot.slot.vtable               = &vtable_no_free;
    TEST_ASSERT_FALSE(rx_validate_mem_resources(bad_slot));
    bad_slot.slot.vtable = &vtable_no_alloc;
    TEST_ASSERT_FALSE(rx_validate_mem_resources(bad_slot));
    udpard_rx_mem_resources_t bad_fragment = rx_mem;
    bad_fragment.fragment.vtable           = &vtable_no_free;
    TEST_ASSERT_FALSE(rx_validate_mem_resources(bad_fragment));
    bad_fragment.fragment.vtable = &vtable_no_alloc;
    TEST_ASSERT_FALSE(rx_validate_mem_resources(bad_fragment));
    bad_fragment.fragment.vtable = NULL;
    TEST_ASSERT_FALSE(rx_validate_mem_resources(bad_fragment));
    TEST_ASSERT_TRUE(udpard_rx_port_new_stateless(&port, 8U, rx_mem, &rx_vtb));
    TEST_ASSERT_FALSE(udpard_rx_port_new_stateless(&port, 8U, bad_fragment, &rx_vtb));
    TEST_ASSERT_FALSE(udpard_rx_port_new_p2p(&port, 8U, bad_fragment, &rx_vtb));

    // Invalid datagram inputs are rejected without processing.
    udpard_rx_t rx;
    udpard_rx_new(&rx, NULL);
    TEST_ASSERT_FALSE(udpard_rx_port_push(&rx,
                                          &port,
                                          0,
                                          (udpard_udpip_ep_t){ 0U, 0U },
                                          (udpard_bytes_mut_t){ .size = 0U, .data = NULL },
                                          (udpard_deleter_t){ .vtable = NULL, .context = NULL },
                                          UDPARD_IFACE_COUNT_MAX));
    const udpard_bytes_mut_t small_payload = { .size = 1U, .data = (void*)1 };
    TEST_ASSERT_FALSE(
      udpard_rx_port_push(&rx,
                          &port,
                          0,
                          (udpard_udpip_ep_t){ .ip = 1U, .port = 1U },
                          small_payload,
                          (udpard_deleter_t){ .vtable = &(udpard_deleter_vtable_t){ .free = NULL }, .context = NULL },
                          0));
    // Cover each guard term with a valid baseline payload.
    const udpard_deleter_t deleter_ok = { .vtable = &deleter_vtable, .context = NULL };
    byte_t                 dgram[HEADER_SIZE_BYTES];
    const meta_t           meta = { .priority              = udpard_prio_nominal,
                                    .kind                  = frame_msg_best,
                                    .transfer_payload_size = 0,
                                    .transfer_id           = 1,
                                    .sender_uid            = 2 };
    header_serialize(dgram, meta, 0, 0, crc_full(0, NULL));
    const udpard_bytes_mut_t dgram_view = { .size = sizeof(dgram), .data = dgram };
    const udpard_udpip_ep_t  ep_ok      = { .ip = 1U, .port = UDP_PORT };
    TEST_ASSERT_FALSE(udpard_rx_port_push(NULL, &port, 0, ep_ok, dgram_view, deleter_ok, 0));
    TEST_ASSERT_FALSE(udpard_rx_port_push(&rx, NULL, 0, ep_ok, dgram_view, deleter_ok, 0));
    TEST_ASSERT_FALSE(udpard_rx_port_push(&rx, &port, -1, ep_ok, dgram_view, deleter_ok, 0));
    TEST_ASSERT_FALSE(
      udpard_rx_port_push(&rx, &port, 0, (udpard_udpip_ep_t){ .ip = 0U, .port = UDP_PORT }, dgram_view, deleter_ok, 0));
    TEST_ASSERT_FALSE(
      udpard_rx_port_push(&rx, &port, 0, ep_ok, (udpard_bytes_mut_t){ .size = 1U, .data = NULL }, deleter_ok, 0));
    TEST_ASSERT_FALSE(udpard_rx_port_push(&rx, &port, 0, ep_ok, dgram_view, deleter_ok, UDPARD_IFACE_COUNT_MAX));
    TEST_ASSERT_FALSE(
      udpard_rx_port_push(&rx, &port, 0, ep_ok, dgram_view, (udpard_deleter_t){ .vtable = NULL, .context = NULL }, 0));
    TEST_ASSERT_FALSE(
      udpard_rx_port_push(&rx,
                          &port,
                          0,
                          ep_ok,
                          dgram_view,
                          (udpard_deleter_t){ .vtable = &(udpard_deleter_vtable_t){ .free = NULL }, .context = NULL },
                          0));

    // ACK frames are accepted on P2P ports.
    udpard_rx_port_t port_p2p;
    TEST_ASSERT_TRUE(udpard_rx_port_new_p2p(&port_p2p, 8U, rx_mem, &rx_vtb));
    const meta_t ack_meta = { .priority              = udpard_prio_nominal,
                              .kind                  = frame_ack,
                              .transfer_payload_size = 0,
                              .transfer_id           = 2,
                              .sender_uid            = 3 };
    header_serialize(dgram, ack_meta, 0, 0, crc_full(0, NULL));
    TEST_ASSERT_TRUE(udpard_rx_port_push(&rx, &port_p2p, 0, ep_ok, dgram_view, deleter_ok, 0));

    // ACK frames are rejected on non-P2P ports.
    const uint64_t errors_before_ack = rx.errors_frame_malformed;
    header_serialize(dgram, ack_meta, 0, 0, crc_full(0, NULL));
    TEST_ASSERT_TRUE(udpard_rx_port_push(&rx, &port, 0, ep_ok, dgram_view, deleter_ok, 0));
    TEST_ASSERT_EQUAL_UINT64(errors_before_ack + 1U, rx.errors_frame_malformed);

    // Malformed frames are rejected after parsing.
    const uint64_t errors_before_bad = rx.errors_frame_malformed;
    header_serialize(dgram, meta, 0, 0, crc_full(0, NULL));
    dgram[HEADER_SIZE_BYTES - 1] ^= 0xFFU;
    TEST_ASSERT_TRUE(udpard_rx_port_push(&rx, &port, 0, ep_ok, dgram_view, deleter_ok, 0));
    TEST_ASSERT_EQUAL_UINT64(errors_before_bad + 1U, rx.errors_frame_malformed);

    // Port freeing should tolerate null rx.
    udpard_rx_port_free(NULL, &port);
    udpard_rx_port_free(&rx, NULL);

    // Fragments past extent are discarded early.
    udpard_tree_t*         root    = NULL;
    byte_t                 buf[1]  = { 0 };
    size_t                 covered = 0;
    const rx_frame_base_t  frame   = { .offset  = 1U,
                                       .payload = { .size = sizeof(buf), .data = buf },
                                       .origin  = { .size = sizeof(buf), .data = buf } };
    static char            frag_tag;
    const udpard_mem_t     frag_mem = make_mem(&frag_tag);
    const udpard_deleter_t deleter  = { .vtable = &deleter_vtable, .context = NULL };
    TEST_ASSERT_EQUAL(rx_fragment_tree_rejected,
                      rx_fragment_tree_update(&root, frag_mem, deleter, frame, 0U, 0U, &covered));
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_mem_endpoint_list_guards);
    RUN_TEST(test_fragment_guards);
    RUN_TEST(test_header_guard);
    RUN_TEST(test_tx_guards);
    RUN_TEST(test_tx_predictor_sharing);
    RUN_TEST(test_rx_guards);
    return UNITY_END();
}
