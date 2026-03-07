/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c> // NOLINT(bugprone-suspicious-include)
#include "helpers.h"
#include <unity.h>
#include <string.h>

// Allocates one standalone fragment for intrusive fragment-tree checks.
static udpard_fragment_t* make_fragment(const udpard_mem_t     fragment_memory,
                                        const udpard_mem_t     payload_memory,
                                        const udpard_deleter_t payload_deleter,
                                        const size_t           offset,
                                        const void* const      data,
                                        const size_t           size)
{
    udpard_fragment_t* const out = mem_res_alloc(fragment_memory, sizeof(udpard_fragment_t));
    TEST_ASSERT_NOT_NULL(out);
    void* payload = NULL;
    if (size > 0U) {
        payload = mem_res_alloc(payload_memory, size);
        TEST_ASSERT_NOT_NULL(payload);
        (void)memcpy(payload, data, size);
    }
    mem_zero(sizeof(*out), out);
    out->offset          = offset;
    out->view            = (udpard_bytes_t){ .size = size, .data = payload };
    out->origin          = (udpard_bytes_mut_t){ .size = size, .data = payload };
    out->payload_deleter = payload_deleter;
    return out;
}

static void test_crc_streamed(void)
{
    uint32_t crc = crc_add(CRC_INITIAL, 3, "123");
    crc          = crc_add(crc, 6, "456789");
    TEST_ASSERT_EQUAL_UINT32(0x1CF96D7CUL, crc);
    TEST_ASSERT_EQUAL_UINT32(0xE3069283UL, crc ^ CRC_OUTPUT_XOR);
    crc = crc_add(crc, 4, "\x83\x92\x06\xE3"); // Least significant byte first.
    TEST_ASSERT_EQUAL_UINT32(CRC_RESIDUE_BEFORE_OUTPUT_XOR, crc);
    TEST_ASSERT_EQUAL_UINT32(CRC_RESIDUE_AFTER_OUTPUT_XOR, crc ^ CRC_OUTPUT_XOR);
}

static void test_list(void)
{
    typedef struct test_node_t
    {
        int             value;
        udpard_listed_t link;
    } test_node_t;

    udpard_list_t list = { .head = NULL, .tail = NULL };

    // Test 1: Empty list state
    TEST_ASSERT_NULL(list.head);
    TEST_ASSERT_NULL(list.tail);

    // Test 2: Enlist single item
    test_node_t node1 = { .value = 1, .link = { .next = NULL, .prev = NULL } };
    enlist_head(&list, &node1.link);
    TEST_ASSERT_EQUAL(&node1.link, list.head);
    TEST_ASSERT_EQUAL(&node1.link, list.tail);
    TEST_ASSERT_NULL(node1.link.next);
    TEST_ASSERT_NULL(node1.link.prev);

    // Test 3: Enlist second item (should become head)
    test_node_t node2 = { .value = 2, .link = { .next = NULL, .prev = NULL } };
    enlist_head(&list, &node2.link);
    TEST_ASSERT_EQUAL(&node2.link, list.head);
    TEST_ASSERT_EQUAL(&node1.link, list.tail);
    TEST_ASSERT_EQUAL(&node1.link, node2.link.next);
    TEST_ASSERT_NULL(node2.link.prev);
    TEST_ASSERT_NULL(node1.link.next);
    TEST_ASSERT_EQUAL(&node2.link, node1.link.prev);

    // Test 4: Enlist third item (should become new head)
    test_node_t node3 = { .value = 3, .link = { .next = NULL, .prev = NULL } };
    enlist_head(&list, &node3.link);
    TEST_ASSERT_EQUAL(&node3.link, list.head);
    TEST_ASSERT_EQUAL(&node1.link, list.tail);
    TEST_ASSERT_EQUAL(&node2.link, node3.link.next);
    TEST_ASSERT_NULL(node3.link.prev);
    TEST_ASSERT_EQUAL(&node1.link, node2.link.next);
    TEST_ASSERT_EQUAL(&node3.link, node2.link.prev);

    // Test 5: Delist middle item
    delist(&list, &node2.link);
    TEST_ASSERT_EQUAL(&node3.link, list.head);
    TEST_ASSERT_EQUAL(&node1.link, list.tail);
    TEST_ASSERT_EQUAL(&node1.link, node3.link.next);
    TEST_ASSERT_NULL(node3.link.prev);
    TEST_ASSERT_NULL(node1.link.next);
    TEST_ASSERT_EQUAL(&node3.link, node1.link.prev);
    TEST_ASSERT_NULL(node2.link.next);
    TEST_ASSERT_NULL(node2.link.prev);

    // Test 6: Re-enlist previously delisted item (should become head)
    enlist_head(&list, &node2.link);
    TEST_ASSERT_EQUAL(&node2.link, list.head);
    TEST_ASSERT_EQUAL(&node1.link, list.tail);
    TEST_ASSERT_EQUAL(&node3.link, node2.link.next);
    TEST_ASSERT_NULL(node2.link.prev);

    // Test 7: Move existing item to head (enlist_head can be used for moving)
    enlist_head(&list, &node1.link);
    TEST_ASSERT_EQUAL(&node1.link, list.head);
    TEST_ASSERT_EQUAL(&node3.link, list.tail);
    TEST_ASSERT_EQUAL(&node2.link, node1.link.next);
    TEST_ASSERT_NULL(node1.link.prev);
    TEST_ASSERT_EQUAL(&node3.link, node2.link.next);
    TEST_ASSERT_EQUAL(&node1.link, node2.link.prev);
    TEST_ASSERT_NULL(node3.link.next);
    TEST_ASSERT_EQUAL(&node2.link, node3.link.prev);

    // Test 8: Delist head
    delist(&list, &node1.link);
    TEST_ASSERT_EQUAL(&node2.link, list.head);
    TEST_ASSERT_EQUAL(&node3.link, list.tail);
    TEST_ASSERT_NULL(node1.link.next);
    TEST_ASSERT_NULL(node1.link.prev);

    // Test 9: Delist tail
    delist(&list, &node3.link);
    TEST_ASSERT_EQUAL(&node2.link, list.head);
    TEST_ASSERT_EQUAL(&node2.link, list.tail);
    TEST_ASSERT_NULL(node2.link.next);
    TEST_ASSERT_NULL(node2.link.prev);
    TEST_ASSERT_NULL(node3.link.next);
    TEST_ASSERT_NULL(node3.link.prev);

    // Test 10: Delist last item
    delist(&list, &node2.link);
    TEST_ASSERT_NULL(list.head);
    TEST_ASSERT_NULL(list.tail);
    TEST_ASSERT_NULL(node2.link.next);
    TEST_ASSERT_NULL(node2.link.prev);

    // Test 11: Delist from empty list (should be safe)
    delist(&list, &node1.link);
    TEST_ASSERT_NULL(list.head);
    TEST_ASSERT_NULL(list.tail);

    // Test 12: LIST_MEMBER macro
    enlist_head(&list, &node1.link);
    enlist_head(&list, &node2.link);
    enlist_head(&list, &node3.link);
    test_node_t* owner = LIST_MEMBER(list.head, test_node_t, link);
    TEST_ASSERT_EQUAL(&node3, owner);
    TEST_ASSERT_EQUAL(3, owner->value);

    // Test 13: LIST_TAIL macro
    test_node_t* tail_owner = LIST_TAIL(list, test_node_t, link);
    TEST_ASSERT_EQUAL(&node1, tail_owner);
    TEST_ASSERT_EQUAL(1, tail_owner->value);

    // Test 14: LIST_MEMBER with NULL
    test_node_t* null_owner = LIST_MEMBER(NULL, test_node_t, link);
    TEST_ASSERT_NULL(null_owner);

    // Test 15: Traverse list from head to tail
    test_node_t* current = LIST_MEMBER(list.head, test_node_t, link);
    TEST_ASSERT_EQUAL(3, current->value);
    current = LIST_MEMBER(current->link.next, test_node_t, link);
    TEST_ASSERT_EQUAL(2, current->value);
    current = LIST_MEMBER(current->link.next, test_node_t, link);
    TEST_ASSERT_EQUAL(1, current->value);
    current = LIST_MEMBER(current->link.next, test_node_t, link);
    TEST_ASSERT_NULL(current);

    // Clean up
    delist(&list, &node1.link);
    delist(&list, &node2.link);
    delist(&list, &node3.link);
    TEST_ASSERT_NULL(list.head);
    TEST_ASSERT_NULL(list.tail);
}

static void test_misc_helpers(void)
{
    instrumented_allocator_t alloc_frag    = { 0 };
    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_frag);
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_t     mem_frag    = instrumented_allocator_make_resource(&alloc_frag);
    const udpard_mem_t     mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_deleter_t del_payload = instrumented_allocator_make_deleter(&alloc_payload);

    // Check trivial helper branches directly.
    udpard_udpip_ep_t endpoints[UDPARD_IFACE_COUNT_MAX] = { 0 };
    endpoints[1]                                        = (udpard_udpip_ep_t){ .ip = 0x0A000001U, .port = 9999U };
    TEST_ASSERT_TRUE(mem_same(mem_frag, mem_frag));
    TEST_ASSERT_FALSE(mem_same(mem_frag, mem_payload));
    // Use same context with different vtables to force the second mem_same() predicate.
    const udpard_mem_vtable_t alt_vtable              = { .base  = { .free = instrumented_allocator_free },
                                                          .alloc = instrumented_allocator_alloc };
    const udpard_mem_t        alt_vtable_same_context = { .vtable = &alt_vtable, .context = mem_frag.context };
    TEST_ASSERT_FALSE(mem_same(mem_frag, alt_vtable_same_context));
    TEST_ASSERT_EQUAL_UINT16(0U, valid_ep_bitmap(NULL));
    TEST_ASSERT_EQUAL_UINT16((uint16_t)(1U << 1U), valid_ep_bitmap(endpoints));
    mem_free_payload(del_payload, (udpard_bytes_mut_t){ 0 });

    // Exercise memory-resource validation failures.
    const udpard_mem_vtable_t missing_alloc = { .base = { .free = instrumented_allocator_free }, .alloc = NULL };
    const udpard_mem_vtable_t missing_free  = { .base = { .free = NULL }, .alloc = instrumented_allocator_alloc };
    TEST_ASSERT_FALSE(mem_validate((udpard_mem_t){ 0 }));
    TEST_ASSERT_FALSE(mem_validate((udpard_mem_t){ .vtable = &missing_alloc, .context = &alloc_payload }));
    TEST_ASSERT_FALSE(mem_validate((udpard_mem_t){ .vtable = &missing_free, .context = &alloc_payload }));
    TEST_ASSERT_TRUE(mem_validate(mem_payload));

    // Read across an empty fragment to cover the scattered-reader fast path.
    const udpard_bytes_scattered_t tail   = { .bytes = { .size = 2U, .data = "CD" }, .next = NULL };
    const udpard_bytes_scattered_t mid    = { .bytes = { .size = 0U, .data = "" }, .next = &tail };
    const udpard_bytes_scattered_t head   = { .bytes = { .size = 2U, .data = "AB" }, .next = &mid };
    bytes_scattered_reader_t       rdr    = { .cursor = &head, .position = 0U };
    char                           out[4] = { 0 };
    TEST_ASSERT_EQUAL_size_t(4U, bytes_scattered_size(head));
    bytes_scattered_read(&rdr, sizeof(out), out);
    TEST_ASSERT_EQUAL_MEMORY("ABCD", out, sizeof(out));

    // Compare fragment ends explicitly.
    udpard_fragment_t probe = { 0 };
    probe.offset            = 5U;
    probe.view.size         = 3U;
    size_t key              = 7U;
    TEST_ASSERT_EQUAL_INT32(-1, cavl_compare_fragment_end(&key, &probe.index_offset));
    key = 8U;
    TEST_ASSERT_EQUAL_INT32(0, cavl_compare_fragment_end(&key, &probe.index_offset));
    key = 9U;
    TEST_ASSERT_EQUAL_INT32(+1, cavl_compare_fragment_end(&key, &probe.index_offset));

    // Exercise fragment helpers on null inputs.
    char                     sink        = 0;
    const udpard_fragment_t* null_cursor = NULL;
    TEST_ASSERT_NULL(udpard_fragment_seek(NULL, 0U));
    TEST_ASSERT_NULL(udpard_fragment_next(NULL));
    TEST_ASSERT_EQUAL_size_t(0U, udpard_fragment_gather(NULL, 0U, 1U, &sink));
    TEST_ASSERT_EQUAL_size_t(0U, udpard_fragment_gather(&null_cursor, 0U, 1U, &sink));

    // Drive each disjunct in is_listed().
    udpard_list_t   list   = { .head = NULL, .tail = NULL };
    udpard_listed_t member = { .next = NULL, .prev = NULL };
    TEST_ASSERT_FALSE(is_listed(&list, &member));
    member.next = &member;
    TEST_ASSERT_TRUE(is_listed(&list, &member));
    member.next = NULL;
    member.prev = &member;
    TEST_ASSERT_TRUE(is_listed(&list, &member));
    member.prev = NULL;
    list.head   = &member;
    TEST_ASSERT_TRUE(is_listed(&list, &member));

    // Free a small tree starting from a child to cover descent and ascent.
    udpard_fragment_t* const root = make_fragment(mem_frag, mem_payload, del_payload, 2U, "BB", 2U);
    udpard_fragment_t* const left = make_fragment(mem_frag, mem_payload, del_payload, 0U, "AA", 2U);
    udpard_fragment_t* const rght = make_fragment(mem_frag, mem_payload, del_payload, 4U, "CC", 2U);
    root->index_offset.lr[0]      = &left->index_offset;
    root->index_offset.lr[1]      = &rght->index_offset;
    left->index_offset.up         = &root->index_offset;
    rght->index_offset.up         = &root->index_offset;
    udpard_fragment_free_all(left, udpard_make_deleter(mem_frag));
    TEST_ASSERT_EQUAL_size_t(0U, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0U, alloc_payload.allocated_fragments);
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_crc_streamed);
    RUN_TEST(test_list);
    RUN_TEST(test_misc_helpers);
    return UNITY_END();
}
