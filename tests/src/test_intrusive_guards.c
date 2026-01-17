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

static void on_collision_stub(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_remote_t remote)
{
    (void)rx;
    (void)port;
    (void)remote;
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
    udpard_list_t        list   = { 0 };
    udpard_list_member_t member = { 0 };
    TEST_ASSERT_FALSE(is_listed(&list, &member));
    enlist_head(&list, &member);
    TEST_ASSERT_TRUE(is_listed(&list, &member));
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
    TEST_ASSERT_FALSE(udpard_tx_push(
      &tx, 10, 5, iface_bitmap_1, udpard_prio_fast, 1U, 1U, empty_payload, NULL, UDPARD_USER_CONTEXT_NULL));
    TEST_ASSERT_FALSE(udpard_tx_push(
      NULL, 0, 0, iface_bitmap_1, udpard_prio_fast, 1U, 1U, empty_payload, NULL, UDPARD_USER_CONTEXT_NULL));
    TEST_ASSERT_FALSE(udpard_tx_push_p2p(NULL,
                                         0,
                                         0,
                                         udpard_prio_fast,
                                         1U,
                                         1U,
                                         (udpard_remote_t){ 0 },
                                         empty_payload,
                                         NULL,
                                         UDPARD_USER_CONTEXT_NULL,
                                         NULL));

    // Poll and refcount no-ops on null data.
    udpard_tx_poll(NULL, 0, 0);
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
}

static void test_rx_guards(void)
{
    // RX port creation guards reject invalid parameters.
    static char                     rx_tag_a;
    static char                     rx_tag_b;
    const udpard_rx_mem_resources_t rx_mem = { .session = make_mem(&rx_tag_a), .fragment = make_mem(&rx_tag_b) };
    const udpard_rx_port_vtable_t   rx_vtb = { .on_message = on_message_stub, .on_collision = on_collision_stub };
    udpard_rx_port_t                port;
    TEST_ASSERT_FALSE(udpard_rx_port_new(NULL, 0, 0, 0, rx_mem, &rx_vtb));
    udpard_rx_mem_resources_t bad_rx_mem = rx_mem;
    bad_rx_mem.session.vtable            = NULL;
    TEST_ASSERT_FALSE(udpard_rx_port_new(&port, 0, 0, UDPARD_RX_REORDERING_WINDOW_UNORDERED, bad_rx_mem, &rx_vtb));
    TEST_ASSERT_FALSE(udpard_rx_port_new(&port, 0, 0, (udpard_us_t)-3, rx_mem, &rx_vtb));
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 0xAA, 8U, UDPARD_RX_REORDERING_WINDOW_STATELESS, rx_mem, &rx_vtb));

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

    // Guard paths for P2P port creation and port freeing.
    udpard_rx_port_p2p_t        p2p;
    udpard_rx_port_p2p_vtable_t p2p_vt = { .on_message = NULL };
    TEST_ASSERT_FALSE(udpard_rx_port_new_p2p(&p2p, 1U, 0, rx_mem, &p2p_vt));
    udpard_rx_port_free(NULL, &port);

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
