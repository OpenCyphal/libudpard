/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.c> // NOLINT(bugprone-suspicious-include)
#include "helpers.h"
#include <unity.h>

static size_t tree_count(udpard_tree_t* const root) // how many make a forest?
{
    size_t count = 0;
    for (udpard_tree_t* p = cavl2_min(root); p != NULL; p = cavl2_next_greater(p)) {
        count++;
    }
    return count;
}

static udpard_fragment_t* fragment_at(udpard_tree_t* const root, uint32_t index)
{
    for (udpard_fragment_t* it = (udpard_fragment_t*)cavl2_min(root); it != NULL;
         it                    = (udpard_fragment_t*)cavl2_next_greater(&it->index_offset)) {
        if (index-- == 0U) {
            return it;
        }
    }
    return NULL;
}

/// Allocates the payload on the heap, emulating normal frame reception.
static rx_frame_base_t make_frame_base(const udpard_mem_resource_t mem,
                                       const size_t                offset,
                                       const size_t                size,
                                       const void* const           payload)
{
    void* data = mem.alloc(mem.user, size);
    if (size > 0) {
        memcpy(data, payload, size);
    }
    return (rx_frame_base_t){ .offset  = offset,
                              .payload = { .data = data, .size = size },
                              .origin  = { .data = data, .size = size } };
}
/// The payload string cannot contain NUL characters.
static rx_frame_base_t make_frame_base_str(const udpard_mem_resource_t mem,
                                           const size_t                offset,
                                           const char* const           payload)
{
    return make_frame_base(mem, offset, (payload != NULL) ? (strlen(payload) + 1) : 0U, payload);
}

static void test_rx_fragment_tree_update_a(void)
{
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    const udpard_mem_resource_t mem_frag = instrumented_allocator_make_resource(&alloc_frag);

    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_resource_t mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_mem_deleter_t  del_payload = instrumented_allocator_make_deleter(&alloc_payload);

    // Empty payload test
    {
        udpard_tree_t*                   root = NULL;
        size_t                           cov  = 0;
        rx_fragment_tree_update_result_t res  = rx_fragment_tree_not_done;
        //
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base_str(mem_payload, 0, NULL),
                                      0,
                                      0,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_done, res);
        TEST_ASSERT_EQUAL_size_t(0, cov);
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT_EQUAL(1, tree_count(root));
        // Check the retained payload.
        TEST_ASSERT_EQUAL_size_t(0, fragment_at(root, 0)->offset);
        TEST_ASSERT_EQUAL_size_t(0, fragment_at(root, 0)->view.size);
        TEST_ASSERT_NULL(fragment_at(root, 1));
        // Check the heap.
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments); // bc payload empty
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.count_alloc);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.count_alloc);
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.count_free);
        // Free the tree.
        udpard_fragment_free_all((udpard_fragment_t*)root, mem_frag);
        // Check the heap.
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.count_alloc);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.count_alloc);
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.count_free); // bc payload empty
    }

    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Non-empty payload test with zero extent.
    {
        udpard_tree_t*                   root = NULL;
        size_t                           cov  = 0;
        rx_fragment_tree_update_result_t res  = rx_fragment_tree_not_done;
        // Add fragment.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base_str(mem_payload, 0, "abc"),
                                      4,
                                      0,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_done, res);
        TEST_ASSERT_EQUAL_size_t(4, cov);
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT_EQUAL(1, tree_count(root));
        // Check the retained payload.
        TEST_ASSERT_EQUAL_size_t(0, fragment_at(root, 0)->offset);
        TEST_ASSERT_EQUAL_size_t(4, fragment_at(root, 0)->view.size);
        TEST_ASSERT_NULL(fragment_at(root, 1));
        // Check the heap.
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.count_alloc);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.count_alloc);
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.count_free);
        // Free the tree (as in freedom).
        udpard_fragment_free_all((udpard_fragment_t*)root, mem_frag);
        // Check the heap.
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.count_alloc);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.count_alloc);
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.count_free);
    }

    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Non-empty payload with non-zero extent.
    {
        udpard_tree_t*                   root = NULL;
        size_t                           cov  = 0;
        rx_fragment_tree_update_result_t res  = rx_fragment_tree_not_done;
        // Add fragment.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base_str(mem_payload, 0, "abcdef"),
                                      7,
                                      3,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_done, res);
        TEST_ASSERT_EQUAL_size_t(7, cov);
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT_EQUAL(1, tree_count(root));
        // Check the retained payload.
        TEST_ASSERT_EQUAL_size_t(0, fragment_at(root, 0)->offset);
        TEST_ASSERT_EQUAL_size_t(7, fragment_at(root, 0)->view.size);
        TEST_ASSERT_EQUAL_STRING("abcdef", fragment_at(root, 0)->view.data);
        TEST_ASSERT_NULL(fragment_at(root, 1));
        // Check the heap.
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.count_alloc);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.count_alloc);
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.count_free);
        // Free the tree (as in freedom).
        udpard_fragment_free_all((udpard_fragment_t*)root, mem_frag);
        // Check the heap.
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.count_alloc);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.count_alloc);
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.count_free);
    }

    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Multi-frame reassembly test: "abc def xyz "; the last nul is beyond the extent.
    {
        udpard_tree_t*                   root = NULL;
        size_t                           cov  = 0;
        rx_fragment_tree_update_result_t res  = rx_fragment_tree_not_done;
        // Add fragment.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base_str(mem_payload, 0, "abc"),
                                      100,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_not_done, res);
        TEST_ASSERT_EQUAL_size_t(4, cov);
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT_EQUAL(1, tree_count(root));
        // Add fragment.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base_str(mem_payload, 8, "xyz"),
                                      100,
                                      11,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_not_done, res);
        TEST_ASSERT_EQUAL_size_t(4, cov); // not extended due to the gap in the middle.
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT_EQUAL(2, tree_count(root));
        // Add fragment.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base_str(mem_payload, 4, "def"),
                                      100,
                                      11,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_done, res);
        TEST_ASSERT_EQUAL_size_t(12, cov); // extended to cover the two remaining frames.
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT_EQUAL(3, tree_count(root));
        // Check the retained payload.
        TEST_ASSERT_EQUAL_size_t(0, fragment_at(root, 0)->offset);
        TEST_ASSERT_EQUAL_size_t(4, fragment_at(root, 0)->view.size);
        TEST_ASSERT_EQUAL_STRING("abc", fragment_at(root, 0)->view.data);
        TEST_ASSERT_EQUAL_size_t(4, fragment_at(root, 1)->offset);
        TEST_ASSERT_EQUAL_size_t(4, fragment_at(root, 1)->view.size);
        TEST_ASSERT_EQUAL_STRING("def", fragment_at(root, 1)->view.data);
        TEST_ASSERT_EQUAL_size_t(8, fragment_at(root, 2)->offset);
        TEST_ASSERT_EQUAL_size_t(4, fragment_at(root, 2)->view.size);
        TEST_ASSERT_EQUAL_STRING("xyz", fragment_at(root, 2)->view.data);
        TEST_ASSERT_NULL(fragment_at(root, 3));
        // Check the heap.
        TEST_ASSERT_EQUAL_size_t(3, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(3, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(3, alloc_frag.count_alloc);
        TEST_ASSERT_EQUAL_size_t(3, alloc_payload.count_alloc);
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.count_free);
        // Free the tree (as in freedom).
        udpard_fragment_free_all((udpard_fragment_t*)root, mem_frag);
        // Check the heap.
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(3, alloc_frag.count_alloc);
        TEST_ASSERT_EQUAL_size_t(3, alloc_payload.count_alloc);
        TEST_ASSERT_EQUAL_size_t(3, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(3, alloc_payload.count_free);
    }

    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Multi-frame reassembly test with defragmentation: "0123456789".
    {
        udpard_tree_t*                   root = NULL;
        size_t                           cov  = 0;
        rx_fragment_tree_update_result_t res  = rx_fragment_tree_not_done;
        // Add fragment.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 0, 2, "01"),
                                      100,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_not_done, res);
        TEST_ASSERT_EQUAL_size_t(2, cov);
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT_EQUAL(1, tree_count(root));
        // Add fragment.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 4, 2, "45"),
                                      100,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_not_done, res);
        TEST_ASSERT_EQUAL_size_t(2, cov); // not extended
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT_EQUAL(2, tree_count(root));
        // Add fragment.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 3, 2, "34"),
                                      100,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_not_done, res);
        TEST_ASSERT_EQUAL_size_t(2, cov); // not extended
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT_EQUAL(3, tree_count(root));
        // Intermediate check on the current state of the tree so far.
        TEST_ASSERT_EQUAL_size_t(0, fragment_at(root, 0)->offset);
        TEST_ASSERT_EQUAL_size_t(2, fragment_at(root, 0)->view.size);
        TEST_ASSERT_EQUAL_STRING_LEN("01", fragment_at(root, 0)->view.data, 2);
        TEST_ASSERT_EQUAL_size_t(3, fragment_at(root, 1)->offset);
        TEST_ASSERT_EQUAL_size_t(2, fragment_at(root, 1)->view.size);
        TEST_ASSERT_EQUAL_STRING_LEN("34", fragment_at(root, 1)->view.data, 2);
        TEST_ASSERT_EQUAL_size_t(4, fragment_at(root, 2)->offset);
        TEST_ASSERT_EQUAL_size_t(2, fragment_at(root, 2)->view.size);
        TEST_ASSERT_EQUAL_STRING_LEN("45", fragment_at(root, 2)->view.data, 2);
        TEST_ASSERT_NULL(fragment_at(root, 3));
        TEST_ASSERT_EQUAL_size_t(3, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(3, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(3, alloc_frag.count_alloc);
        TEST_ASSERT_EQUAL_size_t(3, alloc_payload.count_alloc);
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.count_free);
        // Add fragment. BRIDGE THE LEFT GAP, EVICT `34` FRAGMENT AS REDUNDANT.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 2, 2, "23"),
                                      100,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_not_done, res);
        TEST_ASSERT_EQUAL_size_t(6, cov); // extended!
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT_EQUAL(3, tree_count(root));
        // Check the updated tree state after the eviction. Fragment `34` should be gone.
        TEST_ASSERT_EQUAL_size_t(0, fragment_at(root, 0)->offset);
        TEST_ASSERT_EQUAL_size_t(2, fragment_at(root, 0)->view.size);
        TEST_ASSERT_EQUAL_STRING_LEN("01", fragment_at(root, 0)->view.data, 2);
        TEST_ASSERT_EQUAL_size_t(2, fragment_at(root, 1)->offset);
        TEST_ASSERT_EQUAL_size_t(2, fragment_at(root, 1)->view.size);
        TEST_ASSERT_EQUAL_STRING_LEN("23", fragment_at(root, 1)->view.data, 2);
        TEST_ASSERT_EQUAL_size_t(4, fragment_at(root, 2)->offset);
        TEST_ASSERT_EQUAL_size_t(2, fragment_at(root, 2)->view.size);
        TEST_ASSERT_EQUAL_STRING_LEN("45", fragment_at(root, 2)->view.data, 2);
        TEST_ASSERT_NULL(fragment_at(root, 3));
        TEST_ASSERT_EQUAL_size_t(3, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(3, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(4, alloc_frag.count_alloc);
        TEST_ASSERT_EQUAL_size_t(4, alloc_payload.count_alloc);
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.count_free);
        // Add a fully-contained (redundant) fragment. Should be discarded.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 1, 1, "z"),
                                      100,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_not_done, res);
        TEST_ASSERT_EQUAL_size_t(6, cov); // no new information is added
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT_EQUAL(3, tree_count(root));                      // no new frames added
        TEST_ASSERT_EQUAL_size_t(3, alloc_frag.allocated_fragments); // no new allocations
        TEST_ASSERT_EQUAL_size_t(3, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(4, alloc_frag.count_alloc);
        TEST_ASSERT_EQUAL_size_t(5, alloc_payload.count_alloc); // the payload was briefly allocated and discarded
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(2, alloc_payload.count_free); // yeah, discarded
        // Add fragment. Slight overlap on the right, candidate for eviction in the future.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 5, 2, "56"),
                                      100,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_not_done, res);
        TEST_ASSERT_EQUAL_size_t(7, cov); // extended by 1 byte
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT_EQUAL(4, tree_count(root));
        // Check the updated tree state.
        TEST_ASSERT_EQUAL_size_t(0, fragment_at(root, 0)->offset);
        TEST_ASSERT_EQUAL_size_t(2, fragment_at(root, 0)->view.size);
        TEST_ASSERT_EQUAL_STRING_LEN("01", fragment_at(root, 0)->view.data, 2);
        TEST_ASSERT_EQUAL_size_t(2, fragment_at(root, 1)->offset);
        TEST_ASSERT_EQUAL_size_t(2, fragment_at(root, 1)->view.size);
        TEST_ASSERT_EQUAL_STRING_LEN("23", fragment_at(root, 1)->view.data, 2);
        TEST_ASSERT_EQUAL_size_t(4, fragment_at(root, 2)->offset);
        TEST_ASSERT_EQUAL_size_t(2, fragment_at(root, 2)->view.size);
        TEST_ASSERT_EQUAL_STRING_LEN("45", fragment_at(root, 2)->view.data, 2);
        TEST_ASSERT_EQUAL_size_t(5, fragment_at(root, 3)->offset);
        TEST_ASSERT_EQUAL_size_t(2, fragment_at(root, 3)->view.size);
        TEST_ASSERT_EQUAL_STRING_LEN("56", fragment_at(root, 3)->view.data, 2);
        TEST_ASSERT_NULL(fragment_at(root, 4));
        TEST_ASSERT_EQUAL_size_t(4, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(4, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(5, alloc_frag.count_alloc);
        TEST_ASSERT_EQUAL_size_t(6, alloc_payload.count_alloc);
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(2, alloc_payload.count_free);
        // Add fragment. Completes the transfer and evicts redundant `45` and `56` fragments.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 4, 8, "456789--"),
                                      100,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_done, res);
        TEST_ASSERT_EQUAL_size_t(12, cov); // extended all the way, beyond the extent.
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT_EQUAL(3, tree_count(root)); // the tree shrunk due to evictions
        // Check the updated tree state.
        TEST_ASSERT_EQUAL_size_t(0, fragment_at(root, 0)->offset);
        TEST_ASSERT_EQUAL_size_t(2, fragment_at(root, 0)->view.size);
        TEST_ASSERT_EQUAL_STRING_LEN("01", fragment_at(root, 0)->view.data, 2);
        TEST_ASSERT_EQUAL_size_t(2, fragment_at(root, 1)->offset);
        TEST_ASSERT_EQUAL_size_t(2, fragment_at(root, 1)->view.size);
        TEST_ASSERT_EQUAL_STRING_LEN("23", fragment_at(root, 1)->view.data, 2);
        TEST_ASSERT_EQUAL_size_t(4, fragment_at(root, 2)->offset);
        TEST_ASSERT_EQUAL_size_t(8, fragment_at(root, 2)->view.size);
        TEST_ASSERT_EQUAL_STRING_LEN("456789--", fragment_at(root, 2)->view.data, 8);
        TEST_ASSERT_NULL(fragment_at(root, 3));
        TEST_ASSERT_EQUAL_size_t(3, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(3, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(6, alloc_frag.count_alloc);
        TEST_ASSERT_EQUAL_size_t(7, alloc_payload.count_alloc);
        TEST_ASSERT_EQUAL_size_t(3, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(4, alloc_payload.count_free);
        // Free the tree (as in freedom). The free tree is free to manifest its own destiny.
        udpard_fragment_free_all((udpard_fragment_t*)root, mem_frag);
        // Check the heap.
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(6, alloc_frag.count_alloc);
        TEST_ASSERT_EQUAL_size_t(7, alloc_payload.count_alloc);
        TEST_ASSERT_EQUAL_size_t(6, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(7, alloc_payload.count_free);
    }
}

static void test_rx_transfer_id_forward_distance(void)
{
    // Test 1: Same value (distance is 0)
    TEST_ASSERT_EQUAL_UINT64(0, rx_transfer_id_forward_distance(0, 0));
    TEST_ASSERT_EQUAL_UINT64(0, rx_transfer_id_forward_distance(100, 100));
    TEST_ASSERT_EQUAL_UINT64(0, rx_transfer_id_forward_distance(UINT64_MAX, UINT64_MAX));

    // Test 2: Simple forward distance (no wraparound)
    TEST_ASSERT_EQUAL_UINT64(1, rx_transfer_id_forward_distance(0, 1));
    TEST_ASSERT_EQUAL_UINT64(10, rx_transfer_id_forward_distance(5, 15));
    TEST_ASSERT_EQUAL_UINT64(100, rx_transfer_id_forward_distance(200, 300));
    TEST_ASSERT_EQUAL_UINT64(1000, rx_transfer_id_forward_distance(1000, 2000));

    // Test 3: Wraparound at UINT64_MAX
    TEST_ASSERT_EQUAL_UINT64(1, rx_transfer_id_forward_distance(UINT64_MAX, 0));
    TEST_ASSERT_EQUAL_UINT64(2, rx_transfer_id_forward_distance(UINT64_MAX, 1));
    TEST_ASSERT_EQUAL_UINT64(10, rx_transfer_id_forward_distance(UINT64_MAX - 5, 4));
    TEST_ASSERT_EQUAL_UINT64(100, rx_transfer_id_forward_distance(UINT64_MAX - 49, 50));

    // Test 4: Large forward distances
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, rx_transfer_id_forward_distance(0, UINT64_MAX));
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, rx_transfer_id_forward_distance(1, 0));
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX - 1, rx_transfer_id_forward_distance(0, UINT64_MAX - 1));
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, rx_transfer_id_forward_distance(2, 1));

    // Test 5: Half-way point (2^63)
    const uint64_t half = 1ULL << 63U;
    TEST_ASSERT_EQUAL_UINT64(half, rx_transfer_id_forward_distance(0, half));
    TEST_ASSERT_EQUAL_UINT64(half, rx_transfer_id_forward_distance(100, 100 + half));
    TEST_ASSERT_EQUAL_UINT64(half, rx_transfer_id_forward_distance(UINT64_MAX, half - 1));

    // Test 6: Backward is interpreted as large forward distance
    // Going from 10 to 5 is actually going forward by UINT64_MAX - 4
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX - 4, rx_transfer_id_forward_distance(10, 5));
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX - 9, rx_transfer_id_forward_distance(100, 90));

    // Test 7: Edge cases around 0
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, rx_transfer_id_forward_distance(1, 0));
    TEST_ASSERT_EQUAL_UINT64(1, rx_transfer_id_forward_distance(0, 1));

    // Test 8: Random large numbers
    TEST_ASSERT_EQUAL_UINT64(0x123456789ABCDEF0ULL - 0x0FEDCBA987654321ULL,
                             rx_transfer_id_forward_distance(0x0FEDCBA987654321ULL, 0x123456789ABCDEF0ULL));
}

static void test_rx_transfer_id_window_slide(void)
{
    rx_transfer_id_window_t obj = { 0 };

    // Test 1: Shift by 0 (no change)
    obj.head      = 100;
    obj.bitset[0] = 0x0000000001000001ULL;
    obj.bitset[1] = 0xF000000010000000ULL;
    obj.bitset[2] = 0x8000000100000002ULL;
    obj.bitset[3] = 0x3000001000000003ULL;
    rx_transfer_id_window_slide(&obj, 100);
    TEST_ASSERT_EQUAL_UINT64(100, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000001000001ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0xF000000010000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x8000000100000002ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x3000001000000003ULL, obj.bitset[3]);

    // Test 2: Shift by 1 bit (within same word)
    obj.head      = 100;
    obj.bitset[0] = 0x0000000001000001ULL;
    obj.bitset[1] = 0xF000000010000000ULL;
    obj.bitset[2] = 0x8000000100000002ULL;
    obj.bitset[3] = 0x3000001000000003ULL;
    rx_transfer_id_window_slide(&obj, 101);
    TEST_ASSERT_EQUAL_UINT64(101, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000002000002ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0xE000000020000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000200000005ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x6000002000000007ULL, obj.bitset[3]);

    // Test 3: Shift by multiple bits within word (shift by 5)
    obj.head      = 200;
    obj.bitset[0] = 0x0000000000000001ULL;
    obj.bitset[1] = 0x0000000000000002ULL;
    obj.bitset[2] = 0x0000000000000004ULL;
    obj.bitset[3] = 0x0000000000000008ULL;
    rx_transfer_id_window_slide(&obj, 205);
    TEST_ASSERT_EQUAL_UINT64(205, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000020ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000040ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000080ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000100ULL, obj.bitset[3]);

    // Test 4: Shift by 63 bits (maximum within word, with carry to next word)
    obj.head      = 300;
    obj.bitset[0] = 0x8000000000000001ULL;
    obj.bitset[1] = 0x8000000000000002ULL;
    obj.bitset[2] = 0x8000000000000004ULL;
    obj.bitset[3] = 0x8000000000000008ULL;
    rx_transfer_id_window_slide(&obj, 363);
    TEST_ASSERT_EQUAL_UINT64(363, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x8000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x4000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x4000000000000001ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x4000000000000002ULL, obj.bitset[3]);

    // Test 5: Shift by 64 (one full word)
    obj.head      = 100;
    obj.bitset[0] = 0x0000000002000002ULL;
    obj.bitset[1] = 0xE000000020000000ULL;
    obj.bitset[2] = 0x0000000200000005ULL;
    obj.bitset[3] = 0x6000002000000007ULL;
    rx_transfer_id_window_slide(&obj, 164);
    TEST_ASSERT_EQUAL_UINT64(164, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000002000002ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0xE000000020000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000200000005ULL, obj.bitset[3]);

    // Test 6: Shift by 65 bits (one word + 1 bit)
    obj.head      = 500;
    obj.bitset[0] = 0x0000000000000001ULL;
    obj.bitset[1] = 0x0000000000000003ULL;
    obj.bitset[2] = 0x0000000000000007ULL;
    obj.bitset[3] = 0x000000000000000FULL;
    rx_transfer_id_window_slide(&obj, 565);
    TEST_ASSERT_EQUAL_UINT64(565, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000002ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000006ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x000000000000000EULL, obj.bitset[3]);

    // Test 7: Shift by 128 (two full words)
    obj.head      = 1000;
    obj.bitset[0] = 0x1111111111111111ULL;
    obj.bitset[1] = 0x2222222222222222ULL;
    obj.bitset[2] = 0x3333333333333333ULL;
    obj.bitset[3] = 0x4444444444444444ULL;
    rx_transfer_id_window_slide(&obj, 1128);
    TEST_ASSERT_EQUAL_UINT64(1128, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x1111111111111111ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x2222222222222222ULL, obj.bitset[3]);

    // Test 8: Shift by 192 (three full words)
    obj.head      = 2000;
    obj.bitset[0] = 0xAAAAAAAAAAAAAAAAULL;
    obj.bitset[1] = 0xBBBBBBBBBBBBBBBBULL;
    obj.bitset[2] = 0xCCCCCCCCCCCCCCCCULL;
    obj.bitset[3] = 0xDDDDDDDDDDDDDDDDULL;
    rx_transfer_id_window_slide(&obj, 2192);
    TEST_ASSERT_EQUAL_UINT64(2192, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0xAAAAAAAAAAAAAAAAULL, obj.bitset[3]);

    // Test 9: Shift by exactly 256 bits (clears everything)
    obj.head      = 5000;
    obj.bitset[0] = 0x1234567890ABCDEFULL;
    obj.bitset[1] = 0xFEDCBA0987654321ULL;
    obj.bitset[2] = 0xAAAAAAAAAAAAAAAAULL;
    obj.bitset[3] = 0x5555555555555555ULL;
    rx_transfer_id_window_slide(&obj, 5256);
    TEST_ASSERT_EQUAL_UINT64(5256, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);

    // Test 10: Large shift (> 256 bits, erases everything)
    obj.head      = 10000;
    obj.bitset[0] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[1] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[2] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[3] = 0xFFFFFFFFFFFFFFFFULL;
    rx_transfer_id_window_slide(&obj, 10500);
    TEST_ASSERT_EQUAL_UINT64(10500, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);

    // Test 11: Shift from 0 to small value
    obj.head      = 0;
    obj.bitset[0] = 0x0000000000000001ULL;
    obj.bitset[1] = 0x0000000000000000ULL;
    obj.bitset[2] = 0x0000000000000000ULL;
    obj.bitset[3] = 0x0000000000000000ULL;
    rx_transfer_id_window_slide(&obj, 10);
    TEST_ASSERT_EQUAL_UINT64(10, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000400ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);

    // Test 12: Shift with wraparound (UINT64_MAX to 0)
    obj.head      = UINT64_MAX;
    obj.bitset[0] = 0x0000000000000001ULL;
    obj.bitset[1] = 0x0000000000000002ULL;
    obj.bitset[2] = 0x0000000000000004ULL;
    obj.bitset[3] = 0x0000000000000008ULL;
    rx_transfer_id_window_slide(&obj, 0);
    TEST_ASSERT_EQUAL_UINT64(0, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000002ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000004ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000008ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000010ULL, obj.bitset[3]);

    // Test 13: Shift with wraparound (UINT64_MAX - 5 to 5)
    obj.head      = UINT64_MAX - 5;
    obj.bitset[0] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[1] = 0x0000000000000000ULL;
    obj.bitset[2] = 0x0000000000000000ULL;
    obj.bitset[3] = 0x0000000000000000ULL;
    rx_transfer_id_window_slide(&obj, 5);
    TEST_ASSERT_EQUAL_UINT64(5, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFF800ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000000007FFULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);

    // Test 14: Shift by 32 bits (partial word shift with carries)
    obj.head      = 1000;
    obj.bitset[0] = 0xFFFFFFFF00000000ULL;
    obj.bitset[1] = 0xFFFFFFFF00000000ULL;
    obj.bitset[2] = 0xFFFFFFFF00000000ULL;
    obj.bitset[3] = 0xFFFFFFFF00000000ULL;
    rx_transfer_id_window_slide(&obj, 1032);
    TEST_ASSERT_EQUAL_UINT64(1032, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000FFFFFFFFULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000FFFFFFFFULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000FFFFFFFFULL, obj.bitset[3]);

    // Test 15: All bits set, shift by 1
    obj.head      = 7777;
    obj.bitset[0] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[1] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[2] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[3] = 0xFFFFFFFFFFFFFFFFULL;
    rx_transfer_id_window_slide(&obj, 7778);
    TEST_ASSERT_EQUAL_UINT64(7778, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFEULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFFULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFFULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFFULL, obj.bitset[3]);
}

static void test_rx_transfer_id_window_manip(void)
{
    rx_transfer_id_window_t obj = { 100, { 0 } };
    rx_transfer_id_window_set(&obj, 100);
    TEST_ASSERT_EQUAL_UINT64(100, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000001ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);
    rx_transfer_id_window_set(&obj, 98);
    TEST_ASSERT_EQUAL_UINT64(100, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000005ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);
    rx_transfer_id_window_set(&obj, 0xFFFFFFFFFFFFFFA4ULL);
    TEST_ASSERT_EQUAL_UINT64(100, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000005ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000001ULL, obj.bitset[3]); // 192 bits back

    TEST_ASSERT_TRUE(rx_transfer_id_window_test(&obj, 100));
    TEST_ASSERT_TRUE(rx_transfer_id_window_test(&obj, 98));
    TEST_ASSERT_TRUE(rx_transfer_id_window_test(&obj, 0xFFFFFFFFFFFFFFA4ULL));
    TEST_ASSERT_FALSE(rx_transfer_id_window_test(&obj, 99));
    TEST_ASSERT_FALSE(rx_transfer_id_window_test(&obj, 97));
    TEST_ASSERT_FALSE(rx_transfer_id_window_test(&obj, 0xFFFFFFFFFFFFFFA3ULL));
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_rx_fragment_tree_update_a);
    RUN_TEST(test_rx_transfer_id_forward_distance);
    RUN_TEST(test_rx_transfer_id_window_slide);
    RUN_TEST(test_rx_transfer_id_window_manip);
    return UNITY_END();
}
