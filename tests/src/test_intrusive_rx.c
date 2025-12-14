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

/// Allocates the payload on the heap, emulating normal frame reception.
static rx_frame_base_t make_frame_base(const udpard_mem_resource_t mem_payload,
                                       const size_t                offset,
                                       const size_t                size,
                                       const void* const           payload)
{
    void* data = mem_payload.alloc(mem_payload.user, size);
    if (size > 0) {
        memcpy(data, payload, size);
    }
    return (rx_frame_base_t){ .offset  = offset,
                              .payload = { .data = data, .size = size },
                              .origin  = { .data = data, .size = size } };
}
/// The payload string cannot contain NUL characters.
static rx_frame_base_t make_frame_base_str(const udpard_mem_resource_t mem_payload,
                                           const size_t                offset,
                                           const char* const           payload)
{
    return make_frame_base(mem_payload, offset, (payload != NULL) ? (strlen(payload) + 1) : 0U, payload);
}

/// The created frame will copy the given full transfer payload at the specified offset, of the specified size.
/// The full transfer payload can be invalidated after this call. It is needed here so that we could compute the
/// CRC prefix correctly, which covers the transfer payload bytes in [0,(offset+size)].
static rx_frame_t make_frame(const meta_t                meta,
                             const udpard_mem_resource_t mem_payload,
                             const void* const           full_transfer_payload,
                             const size_t                frame_payload_offset,
                             const size_t                frame_payload_size)
{
    rx_frame_base_t base = make_frame_base(mem_payload,
                                           frame_payload_offset,
                                           frame_payload_size,
                                           (const uint8_t*)full_transfer_payload + frame_payload_offset);
    base.crc             = crc_full(frame_payload_offset + frame_payload_size, (const uint8_t*)full_transfer_payload);
    return (rx_frame_t){ .base = base, .meta = meta };
}

/// Scans the transfer payload ensuring that its payload exactly matches the reference.
/// The node can be any node in the tree.
static bool transfer_payload_verify(udpard_rx_transfer_t* const transfer,
                                    const size_t                payload_size_stored,
                                    const void* const           payload,
                                    const size_t                payload_size_wire)
{
    udpard_fragment_t* frag   = transfer->payload_head;
    size_t             offset = 0;
    while (frag != NULL) {
        if (frag->offset != offset) {
            return false;
        }
        if ((offset + frag->view.size) > payload_size_stored) {
            return false;
        }
        if (memcmp(frag->view.data, (const uint8_t*)payload + offset, frag->view.size) != 0) {
            return false;
        }
        offset += frag->view.size;
        frag = frag->next;
    }
    return (transfer->payload_size_wire == payload_size_wire) && (offset == payload_size_stored);
}

// ---------------------------------------------  FRAGMENT TREE  ---------------------------------------------

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

static bool fragment_equals(udpard_fragment_t* const frag,
                            const size_t             offset,
                            const size_t             size,
                            const void* const        payload)
{
    if ((frag == NULL) || (frag->offset != offset) || (frag->view.size != size)) {
        return false;
    }
    return (size == 0U) || (memcmp(frag->view.data, payload, size) == 0);
}

/// Scans the fragment tree ensuring that its payload exactly matches the reference.
/// The node can be any node in the tree.
static bool fragment_tree_verify(udpard_tree_t* const root,
                                 const size_t         payload_size,
                                 const void* const    payload,
                                 const uint32_t       crc)
{
    // Remove redundancies from the payload tree and check the CRC.
    if (!rx_fragment_tree_finalize(root, crc)) {
        return false;
    }
    // Scan the payload tree.
    size_t offset = 0;
    for (const udpard_fragment_t* it = (udpard_fragment_t*)cavl2_min(root); it != NULL; it = it->next) {
        if (it->offset != offset) {
            return false;
        }
        if ((offset + it->view.size) > payload_size) {
            return false;
        }
        if ((it->view.size > 0) && (memcmp(it->view.data, (const uint8_t*)payload + offset, it->view.size) != 0)) {
            return false;
        }
        offset += it->view.size;
    }
    return offset == payload_size;
}

/// Reference CRC calculation:
///     >>> from pycyphal.transport.commons.crc import CRC32C
///     >>> hex(CRC32C.new(b"abc\0").value) + "UL"
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
        rx_fragment_tree_update_result_t res  = rx_fragment_tree_rejected;
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
        // Verify the payload and free the tree.
        TEST_ASSERT(fragment_tree_verify(root, 0, "", 0));
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
        rx_fragment_tree_update_result_t res  = rx_fragment_tree_rejected;
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
        // Verify and free the tree (as in freedom).
        TEST_ASSERT(fragment_tree_verify(root, 4, "abc", 0x34940e4cUL));
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
        rx_fragment_tree_update_result_t res  = rx_fragment_tree_rejected;
        // Add fragment beyond the extent, dropped early.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base_str(mem_payload, 3, "abcdef"),
                                      8,
                                      3,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_rejected, res);
        TEST_ASSERT_EQUAL_size_t(0, cov);
        TEST_ASSERT_NULL(root);
        TEST_ASSERT_EQUAL(0, tree_count(root));
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
        TEST_ASSERT_EQUAL_size_t(2, alloc_payload.count_alloc);
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.count_free);
        // Free the tree (as in freedom).
        TEST_ASSERT(fragment_tree_verify(root, 7, "abcdef", 0x532b03c8UL));
        udpard_fragment_free_all((udpard_fragment_t*)root, mem_frag);
        // Check the heap.
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.count_alloc);
        TEST_ASSERT_EQUAL_size_t(2, alloc_payload.count_alloc);
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(2, alloc_payload.count_free);
    }
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Multi-frame reassembly test: "abc def xyz "; the last nul is beyond the extent.
    {
        udpard_tree_t*                   root = NULL;
        size_t                           cov  = 0;
        rx_fragment_tree_update_result_t res  = rx_fragment_tree_rejected;
        // Add fragment.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base_str(mem_payload, 0, "abc"),
                                      100,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
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
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
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
        TEST_ASSERT(fragment_tree_verify(root, 12, "abc\0def\0xyz", 0x2758cbe6UL));
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
        rx_fragment_tree_update_result_t res  = rx_fragment_tree_rejected;
        // Add fragment.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 0, 2, "01"),
                                      100,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
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
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
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
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
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
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
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
        TEST_ASSERT_EQUAL(rx_fragment_tree_rejected, res);
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
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
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
        TEST_ASSERT(fragment_tree_verify(root, 12, "0123456789--", 0xc73f3ad8UL));
        udpard_fragment_free_all((udpard_fragment_t*)root, mem_frag);
        // Check the heap.
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(6, alloc_frag.count_alloc);
        TEST_ASSERT_EQUAL_size_t(7, alloc_payload.count_alloc);
        TEST_ASSERT_EQUAL_size_t(6, alloc_frag.count_free);
        TEST_ASSERT_EQUAL_size_t(7, alloc_payload.count_free);
    }
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Multi-frame reassembly test with defragmentation: "abcdefghijklmnopqrst". Split with various MTU:
    //
    //  MTU 4:  abcd  efgh  ijkl mnop  qrst
    //          0     4     8    12    16
    //
    //  MTU 5:  abcde  fghij  klmno   pqrst
    //          0      5      10      15
    //
    //  MTU 11: abcdefghijk    lmnopqrst
    //          0              11
    //
    // Offset helper:
    //      abcdefghijklmnopqrst
    //      01234567890123456789
    //      00000000001111111111
    {
        udpard_tree_t*                   root = NULL;
        size_t                           cov  = 0;
        rx_fragment_tree_update_result_t res  = rx_fragment_tree_rejected;

        // Add fragment.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 0, 5, "abcde"),
                                      21,
                                      21,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
        TEST_ASSERT_EQUAL_size_t(5, cov);
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT(fragment_equals(fragment_at(root, 0), 0, 5, "abcde"));
        TEST_ASSERT_NULL(fragment_at(root, 1));

        // Add fragment. Rejected because contained by existing.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 0, 4, "abcd"),
                                      21,
                                      21,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_rejected, res);
        TEST_ASSERT_EQUAL_size_t(5, cov);
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT(fragment_equals(fragment_at(root, 0), 0, 5, "abcde"));
        TEST_ASSERT_NULL(fragment_at(root, 1));

        // Add 2 fragments. They cover new ground with a gap but they are small, to be replaced later.
        // Resulting state:
        //     0    |abcde               |
        //     1    |        ijkl        |
        //     2    |            mnop    |
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 8, 4, "ijkl"),
                                      21,
                                      21,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 12, 4, "mnop"),
                                      21,
                                      21,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
        TEST_ASSERT_EQUAL_size_t(5, cov); // not extended due to a gap
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT(fragment_equals(fragment_at(root, 0), 0, 5, "abcde"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 1), 8, 4, "ijkl"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 2), 12, 4, "mnop"));
        TEST_ASSERT_NULL(fragment_at(root, 3));
        TEST_ASSERT_EQUAL_size_t(3, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(3, alloc_payload.allocated_fragments);

        // Add another fragment that doesn't add any new information but is accepted anyway because it is larger.
        // This may enable defragmentation in the future.
        // Resulting state:
        //     0    |abcde               |
        //     1    |        ijkl        |
        //     2    |          klmno     |
        //     3    |            mnop    |
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 10, 5, "klmno"),
                                      21,
                                      21,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
        TEST_ASSERT_EQUAL_size_t(5, cov); // not extended due to a gap
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT(fragment_equals(fragment_at(root, 0), 0, 5, "abcde"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 1), 8, 4, "ijkl"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 2), 10, 5, "klmno"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 3), 12, 4, "mnop"));
        TEST_ASSERT_NULL(fragment_at(root, 4));
        TEST_ASSERT_EQUAL_size_t(4, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(4, alloc_payload.allocated_fragments);

        // Add another fragment that bridges the gap and allows removing ijkl.
        // Resulting state:
        //     0    |abcde               |
        //     1    |     fghij          |  replaces the old 1
        //     2    |          klmno     |
        //     3    |            mnop    |  kept because it has 'p'
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 5, 5, "fghij"),
                                      21,
                                      21,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
        TEST_ASSERT_EQUAL_size_t(16, cov); // jumps to the end because the gap is covered
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT(fragment_equals(fragment_at(root, 0), 0, 5, "abcde"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 1), 5, 5, "fghij"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 2), 10, 5, "klmno"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 3), 12, 4, "mnop"));
        TEST_ASSERT_NULL(fragment_at(root, 4));
        TEST_ASSERT_EQUAL_size_t(4, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(4, alloc_payload.allocated_fragments);

        // Add the last smallest fragment. The transfer is not detected as complete because it is set to 21 bytes.
        // Resulting state:
        //     0    |abcde               |
        //     1    |     fghij          |  replaces the old 1
        //     2    |          klmno     |
        //     3    |            mnop    |  kept because it has 'p'
        //     4    |                qrst|
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 16, 4, "qrst"),
                                      21,
                                      21,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
        TEST_ASSERT_EQUAL_size_t(20, cov); // updated
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT(fragment_equals(fragment_at(root, 0), 0, 5, "abcde"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 1), 5, 5, "fghij"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 2), 10, 5, "klmno"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 3), 12, 4, "mnop"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 4), 16, 4, "qrst"));
        TEST_ASSERT_NULL(fragment_at(root, 5));
        TEST_ASSERT_EQUAL_size_t(5, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(5, alloc_payload.allocated_fragments);

        // Send redundant fragments. State unchanged.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 4, 4, "efgh"),
                                      21,
                                      21,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_rejected, res);
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 5, 5, "fghij"),
                                      21,
                                      21,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_rejected, res);
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 0, 5, "abcde"),
                                      21,
                                      21,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_rejected, res);
        TEST_ASSERT_EQUAL_size_t(20, cov); // no change
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT(fragment_equals(fragment_at(root, 0), 0, 5, "abcde"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 1), 5, 5, "fghij"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 2), 10, 5, "klmno"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 3), 12, 4, "mnop"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 4), 16, 4, "qrst"));
        TEST_ASSERT_NULL(fragment_at(root, 5));
        TEST_ASSERT_EQUAL_size_t(5, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(5, alloc_payload.allocated_fragments);

        // Add the first max-MTU fragment. Replaces the smaller initial fragments.
        // Resulting state:
        //     0    |abcdefghijk         |  replaces 0 and 1
        //     1    |          klmno     |  kept because it has 'lmno'
        //     2    |            mnop    |  kept because it has 'p'
        //     3    |                qrst|
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 0, 11, "abcdefghijk"),
                                      21,
                                      21,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
        TEST_ASSERT_EQUAL_size_t(20, cov);
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT(fragment_equals(fragment_at(root, 0), 0, 11, "abcdefghijk"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 1), 10, 5, "klmno"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 2), 12, 4, "mnop"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 3), 16, 4, "qrst"));
        TEST_ASSERT_NULL(fragment_at(root, 4));
        TEST_ASSERT_EQUAL_size_t(4, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(4, alloc_payload.allocated_fragments);

        // Add the last MTU 5 fragment. Replaces the last two MTU 4 fragments.
        // Resulting state:
        //     0    |abcdefghijk         |
        //     1    |          klmno     |  kept because it has 'lmno'
        //     2    |               pqrst|
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 15, 5, "pqrst"),
                                      21,
                                      21,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
        TEST_ASSERT_EQUAL_size_t(20, cov);
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT(fragment_equals(fragment_at(root, 0), 0, 11, "abcdefghijk"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 1), 10, 5, "klmno"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 2), 15, 5, "pqrst"));
        TEST_ASSERT_NULL(fragment_at(root, 3));
        TEST_ASSERT_EQUAL_size_t(3, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(3, alloc_payload.allocated_fragments);

        // Add the last max-MTU fragment. Replaces the last two fragments.
        // Resulting state:
        //     0    |abcdefghijk         |
        //     1    |           lmnopqrst|
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 11, 9, "lmnopqrst"),
                                      21,
                                      21,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
        TEST_ASSERT_EQUAL_size_t(20, cov);
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT(fragment_equals(fragment_at(root, 0), 0, 11, "abcdefghijk"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 1), 11, 9, "lmnopqrst"));
        TEST_ASSERT_NULL(fragment_at(root, 2));
        TEST_ASSERT_EQUAL_size_t(2, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(2, alloc_payload.allocated_fragments);

        // Replace everything with a single huge fragment.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 0, 20, "abcdefghijklmnopqrst"),
                                      21,
                                      21,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
        TEST_ASSERT_EQUAL_size_t(20, cov);
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT(fragment_equals(fragment_at(root, 0), 0, 20, "abcdefghijklmnopqrst"));
        TEST_ASSERT_NULL(fragment_at(root, 1));
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.allocated_fragments);

        // One tiny boi will complete the transfer.
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 19, 2, "t-"),
                                      21,
                                      21,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_done, res);
        TEST_ASSERT_EQUAL_size_t(21, cov);
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT(fragment_equals(fragment_at(root, 0), 0, 20, "abcdefghijklmnopqrst"));
        TEST_ASSERT(fragment_equals(fragment_at(root, 1), 19, 2, "t-"));
        TEST_ASSERT_NULL(fragment_at(root, 2));
        TEST_ASSERT_EQUAL_size_t(2, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(2, alloc_payload.allocated_fragments);

        // Verify the final state.
        TEST_ASSERT(fragment_tree_verify(root, 21, "abcdefghijklmnopqrst-", 0xe7a60f1eUL));

        // Cleanup.
        udpard_fragment_free_all((udpard_fragment_t*)root, mem_frag);
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
    }
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);
}

/// Exhaustive test for rx_fragment_tree_update with random fragmentation patterns.
/// Tests a fixed payload split into every possible non-empty substring,
/// fed in random order with possible duplicates, and verifies correct completion detection.
static void test_rx_fragment_tree_update_exhaustive(void)
{
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    const udpard_mem_resource_t mem_frag = instrumented_allocator_make_resource(&alloc_frag);

    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_resource_t mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_mem_deleter_t  del_payload = instrumented_allocator_make_deleter(&alloc_payload);

    const char   payload[]      = "0123456789";
    const size_t payload_length = strlen(payload);

    // Generate all possible non-empty substrings (offset, length pairs).
    // For a string of length N, there are N*(N+1)/2 possible substrings.
    typedef struct
    {
        size_t offset;
        size_t length;
    } substring_t;

    const size_t max_substrings = (payload_length * (payload_length + 1)) / 2;
    substring_t  substrings[max_substrings];
    size_t       substring_count = 0;

    for (size_t offset = 0; offset < payload_length; offset++) {
        for (size_t length = 1; length <= (payload_length - offset); length++) {
            substrings[substring_count].offset = offset;
            substrings[substring_count].length = length;
            substring_count++;
        }
    }
    TEST_ASSERT_EQUAL_size_t(max_substrings, substring_count);

    // Run multiple randomized test iterations to explore different orderings.
    // We use fewer iterations to keep test time reasonable.
    const size_t num_iterations = 10000;

    for (size_t iteration = 0; iteration < num_iterations; iteration++) {
        udpard_tree_t* root = NULL;
        size_t         cov  = 0;

        // Create a randomized schedule of fragments to feed.
        // We'll randomly select which substrings to use and in what order.
        // Some may be duplicated, some may be omitted initially.

        // Track which bytes have been covered by submitted fragments.
        bool byte_covered[10]  = { false };
        bool transfer_complete = false;

        // Shuffle the substring indices to get a random order.
        size_t schedule[substring_count];
        for (size_t i = 0; i < substring_count; i++) {
            schedule[i] = i;
        }

        // Fisher-Yates shuffle
        for (size_t i = substring_count - 1; i > 0; i--) {
            const size_t j   = (size_t)(rand() % (int)(i + 1));
            const size_t tmp = schedule[i];
            schedule[i]      = schedule[j];
            schedule[j]      = tmp;
        }

        // Feed fragments in the shuffled order.
        // We stop after we've seen every byte at least once.
        for (size_t sched_idx = 0; sched_idx < substring_count; sched_idx++) {
            const substring_t sub = substrings[schedule[sched_idx]];

            // Allocate and copy the substring payload.
            char* const frag_data = mem_payload.alloc(mem_payload.user, sub.length);
            memcpy(frag_data, payload + sub.offset, sub.length);

            const rx_frame_base_t frame = { .offset  = sub.offset,
                                            .payload = { .data = frag_data, .size = sub.length },
                                            .origin  = { .data = frag_data, .size = sub.length } };

            const rx_fragment_tree_update_result_t res =
              rx_fragment_tree_update(&root, mem_frag, del_payload, frame, payload_length, payload_length, &cov);

            // Update our tracking of covered bytes.
            for (size_t i = 0; i < sub.length; i++) {
                byte_covered[sub.offset + i] = true;
            }

            // Check if all bytes are covered.
            bool all_covered = true;
            for (size_t i = 0; i < payload_length; i++) {
                if (!byte_covered[i]) {
                    all_covered = false;
                    break;
                }
            }
            if (all_covered) {
                TEST_ASSERT_EQUAL(rx_fragment_tree_done, res);
                transfer_complete = true;
                break;
            }
            TEST_ASSERT((res == rx_fragment_tree_accepted) || (res == rx_fragment_tree_rejected));
        }
        TEST_ASSERT_TRUE(transfer_complete);
        TEST_ASSERT_EQUAL_size_t(payload_length, cov);

        // Verify the final state.
        TEST_ASSERT(fragment_tree_verify(root, 10, "0123456789", 0x280c069eUL));
        udpard_fragment_free_all((udpard_fragment_t*)root, mem_frag);
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
    }
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);

    // Test with duplicates: feed the same fragments multiple times.
    for (size_t iteration = 0; iteration < num_iterations; iteration++) {
        udpard_tree_t* root = NULL;
        size_t         cov  = 0;

        bool byte_covered[10]  = { false };
        bool transfer_complete = false;

        // Create a schedule with duplicates.
        const size_t schedule_length = substring_count * 3; // 3x duplication factor
        size_t       schedule[schedule_length];
        for (size_t i = 0; i < schedule_length; i++) {
            schedule[i] = (size_t)(rand() % (int)substring_count);
        }

        // Feed fragments with duplicates.
        for (size_t sched_idx = 0; sched_idx < schedule_length; sched_idx++) {
            const substring_t sub = substrings[schedule[sched_idx]];

            char* const frag_data = mem_payload.alloc(mem_payload.user, sub.length);
            memcpy(frag_data, payload + sub.offset, sub.length);

            const rx_frame_base_t frame = { .offset  = sub.offset,
                                            .payload = { .data = frag_data, .size = sub.length },
                                            .origin  = { .data = frag_data, .size = sub.length } };

            const rx_fragment_tree_update_result_t res =
              rx_fragment_tree_update(&root, mem_frag, del_payload, frame, payload_length, payload_length, &cov);

            // Update tracking.
            for (size_t i = 0; i < sub.length; i++) {
                byte_covered[sub.offset + i] = true;
            }

            // Check completion.
            bool all_covered = true;
            for (size_t i = 0; i < payload_length; i++) {
                if (!byte_covered[i]) {
                    all_covered = false;
                    break;
                }
            }
            if (all_covered) {
                TEST_ASSERT_EQUAL(rx_fragment_tree_done, res);
                transfer_complete = true;
                break;
            }
            TEST_ASSERT((res == rx_fragment_tree_accepted) || (res == rx_fragment_tree_rejected));
        }
        TEST_ASSERT_TRUE(transfer_complete);
        TEST_ASSERT_EQUAL_size_t(payload_length, cov);

        // Verify the final state.
        TEST_ASSERT(fragment_tree_verify(root, 10, "0123456789", 0x280c069eUL));
        udpard_fragment_free_all((udpard_fragment_t*)root, mem_frag);
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
    }
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
}

static void test_rx_fragment_tree_oom(void)
{
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    const udpard_mem_resource_t mem_frag = instrumented_allocator_make_resource(&alloc_frag);

    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_resource_t mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_mem_deleter_t  del_payload = instrumented_allocator_make_deleter(&alloc_payload);

    // Test OOM during fragment allocation
    {
        udpard_tree_t*                   root = NULL;
        size_t                           cov  = 0;
        rx_fragment_tree_update_result_t res  = rx_fragment_tree_rejected;

        // Set fragment allocation limit to zero - fragment allocation will fail
        alloc_frag.limit_fragments = 0;

        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base_str(mem_payload, 0, "abc"),
                                      100,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_oom, res);
        TEST_ASSERT_EQUAL_size_t(0, cov);
        TEST_ASSERT_NULL(root);
        // Payload should have been freed
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.count_alloc); // payload was allocated by make_frame_base_str
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.count_free);  // but freed due to OOM
    }
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Test OOM during multi-fragment reassembly
    {
        udpard_tree_t*                   root = NULL;
        size_t                           cov  = 0;
        rx_fragment_tree_update_result_t res  = rx_fragment_tree_rejected;

        // First fragment succeeds
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base_str(mem_payload, 0, "abc"),
                                      100,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
        TEST_ASSERT_EQUAL_size_t(4, cov);
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT_EQUAL(1, tree_count(root));
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.allocated_fragments);

        // Second fragment fails due to OOM
        alloc_frag.limit_fragments = 1;                             // Already used the limit
        res                        = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base_str(mem_payload, 4, "def"),
                                      100,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_oom, res);
        TEST_ASSERT_EQUAL_size_t(4, cov); // Coverage unchanged
        TEST_ASSERT_NOT_NULL(root);
        TEST_ASSERT_EQUAL(1, tree_count(root)); // Still only one fragment
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(2, alloc_payload.count_alloc); // second payload was allocated
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.count_free);  // but freed due to OOM

        // Reset limit and add the second fragment successfully
        alloc_frag.limit_fragments = SIZE_MAX;
        res                        = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base_str(mem_payload, 4, "def"),
                                      100,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
        TEST_ASSERT_EQUAL_size_t(8, cov);
        TEST_ASSERT_EQUAL(2, tree_count(root));
        TEST_ASSERT_EQUAL_size_t(2, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(2, alloc_payload.allocated_fragments);

        // Cleanup
        udpard_fragment_free_all((udpard_fragment_t*)root, mem_frag);
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
    }
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Test OOM recovery: fragment allocation fails, then succeeds on retry
    {
        udpard_tree_t*                   root = NULL;
        size_t                           cov  = 0;
        rx_fragment_tree_update_result_t res  = rx_fragment_tree_rejected;

        // First attempt fails
        alloc_frag.limit_fragments = 0;
        res                        = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base_str(mem_payload, 0, "abcdef"),
                                      7,
                                      3,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_oom, res);
        TEST_ASSERT_EQUAL_size_t(0, cov);
        TEST_ASSERT_NULL(root);

        // Second attempt succeeds
        alloc_frag.limit_fragments = SIZE_MAX;
        res                        = rx_fragment_tree_update(&root, //
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
        TEST_ASSERT_EQUAL_size_t(1, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(1, alloc_payload.allocated_fragments);

        // Cleanup
        udpard_fragment_free_all((udpard_fragment_t*)root, mem_frag);
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
    }
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);
}

// ---------------------------------------------  TRANSFER-ID WINDOW  ---------------------------------------------

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
    obj.bitset[4] = 0x0000000000000004ULL;
    obj.bitset[5] = 0x0000000000000005ULL;
    obj.bitset[6] = 0x0000000000000006ULL;
    obj.bitset[7] = 0x0000000000000007ULL;
    rx_transfer_id_window_slide(&obj, 100);
    TEST_ASSERT_EQUAL_UINT64(100, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000001000001ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0xF000000010000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x8000000100000002ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x3000001000000003ULL, obj.bitset[3]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000004ULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000005ULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000006ULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000007ULL, obj.bitset[7]);

    // Test 2: Shift by 1 bit (within same word)
    obj.head      = 100;
    obj.bitset[0] = 0x0000000001000001ULL;
    obj.bitset[1] = 0xF000000010000000ULL;
    obj.bitset[2] = 0x8000000100000002ULL;
    obj.bitset[3] = 0x3000001000000003ULL;
    obj.bitset[4] = 0x0000000000000004ULL;
    obj.bitset[5] = 0x0000000000000005ULL;
    obj.bitset[6] = 0x0000000000000006ULL;
    obj.bitset[7] = 0x0000000000000007ULL;
    rx_transfer_id_window_slide(&obj, 101);
    TEST_ASSERT_EQUAL_UINT64(101, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000002000002ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0xE000000020000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000200000005ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x6000002000000007ULL, obj.bitset[3]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000008ULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0x000000000000000AULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0x000000000000000CULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0x000000000000000EULL, obj.bitset[7]);

    // Test 3: Shift by multiple bits within word (shift by 5)
    obj.head      = 200;
    obj.bitset[0] = 0x0000000000000001ULL;
    obj.bitset[1] = 0x0000000000000002ULL;
    obj.bitset[2] = 0x0000000000000004ULL;
    obj.bitset[3] = 0x0000000000000008ULL;
    obj.bitset[4] = 0x0000000000000010ULL;
    obj.bitset[5] = 0x0000000000000020ULL;
    obj.bitset[6] = 0x0000000000000040ULL;
    obj.bitset[7] = 0x0000000000000080ULL;
    rx_transfer_id_window_slide(&obj, 205);
    TEST_ASSERT_EQUAL_UINT64(205, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000020ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000040ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000080ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000100ULL, obj.bitset[3]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000200ULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000400ULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000800ULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000001000ULL, obj.bitset[7]);

    // Test 4: Shift by 63 bits (maximum within word, with carry to next word)
    obj.head      = 300;
    obj.bitset[0] = 0x8000000000000001ULL;
    obj.bitset[1] = 0x8000000000000002ULL;
    obj.bitset[2] = 0x8000000000000004ULL;
    obj.bitset[3] = 0x8000000000000008ULL;
    obj.bitset[4] = 0x8000000000000010ULL;
    obj.bitset[5] = 0x8000000000000020ULL;
    obj.bitset[6] = 0x8000000000000040ULL;
    obj.bitset[7] = 0x8000000000000080ULL;
    rx_transfer_id_window_slide(&obj, 363);
    TEST_ASSERT_EQUAL_UINT64(363, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x8000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x4000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x4000000000000001ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x4000000000000002ULL, obj.bitset[3]);
    TEST_ASSERT_EQUAL_UINT64(0x4000000000000004ULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0x4000000000000008ULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0x4000000000000010ULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0x4000000000000020ULL, obj.bitset[7]);

    // Test 5: Shift by 64 (one full word)
    obj.head      = 100;
    obj.bitset[0] = 0x0000000002000002ULL;
    obj.bitset[1] = 0xE000000020000000ULL;
    obj.bitset[2] = 0x0000000200000005ULL;
    obj.bitset[3] = 0x6000002000000007ULL;
    obj.bitset[4] = 0x0000000000000008ULL;
    obj.bitset[5] = 0x0000000000000009ULL;
    obj.bitset[6] = 0x000000000000000AULL;
    obj.bitset[7] = 0x000000000000000BULL;
    rx_transfer_id_window_slide(&obj, 164);
    TEST_ASSERT_EQUAL_UINT64(164, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000002000002ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0xE000000020000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000200000005ULL, obj.bitset[3]);
    TEST_ASSERT_EQUAL_UINT64(0x6000002000000007ULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000008ULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000009ULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0x000000000000000AULL, obj.bitset[7]);

    // Test 6: Shift by 65 bits (one word + 1 bit)
    obj.head      = 500;
    obj.bitset[0] = 0x0000000000000001ULL;
    obj.bitset[1] = 0x0000000000000003ULL;
    obj.bitset[2] = 0x0000000000000007ULL;
    obj.bitset[3] = 0x000000000000000FULL;
    obj.bitset[4] = 0x000000000000001FULL;
    obj.bitset[5] = 0x000000000000003FULL;
    obj.bitset[6] = 0x000000000000007FULL;
    obj.bitset[7] = 0x00000000000000FFULL;
    rx_transfer_id_window_slide(&obj, 565);
    TEST_ASSERT_EQUAL_UINT64(565, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000002ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000006ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x000000000000000EULL, obj.bitset[3]);
    TEST_ASSERT_EQUAL_UINT64(0x000000000000001EULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0x000000000000003EULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0x000000000000007EULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000000000FEULL, obj.bitset[7]);

    // Test 7: Shift by 128 (two full words)
    obj.head      = 1000;
    obj.bitset[0] = 0x1111111111111111ULL;
    obj.bitset[1] = 0x2222222222222222ULL;
    obj.bitset[2] = 0x3333333333333333ULL;
    obj.bitset[3] = 0x4444444444444444ULL;
    obj.bitset[4] = 0x5555555555555555ULL;
    obj.bitset[5] = 0x6666666666666666ULL;
    obj.bitset[6] = 0x7777777777777777ULL;
    obj.bitset[7] = 0x8888888888888888ULL;
    rx_transfer_id_window_slide(&obj, 1128);
    TEST_ASSERT_EQUAL_UINT64(1128, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x1111111111111111ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x2222222222222222ULL, obj.bitset[3]);
    TEST_ASSERT_EQUAL_UINT64(0x3333333333333333ULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0x4444444444444444ULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0x5555555555555555ULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0x6666666666666666ULL, obj.bitset[7]);

    // Test 8: Shift by 192 (three full words)
    obj.head      = 2000;
    obj.bitset[0] = 0xAAAAAAAAAAAAAAAAULL;
    obj.bitset[1] = 0xBBBBBBBBBBBBBBBBULL;
    obj.bitset[2] = 0xCCCCCCCCCCCCCCCCULL;
    obj.bitset[3] = 0xDDDDDDDDDDDDDDDDULL;
    obj.bitset[4] = 0xEEEEEEEEEEEEEEEEULL;
    obj.bitset[5] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[6] = 0x1111111111111111ULL;
    obj.bitset[7] = 0x2222222222222222ULL;
    rx_transfer_id_window_slide(&obj, 2192);
    TEST_ASSERT_EQUAL_UINT64(2192, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0xAAAAAAAAAAAAAAAAULL, obj.bitset[3]);
    TEST_ASSERT_EQUAL_UINT64(0xBBBBBBBBBBBBBBBBULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0xCCCCCCCCCCCCCCCCULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0xDDDDDDDDDDDDDDDDULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0xEEEEEEEEEEEEEEEEULL, obj.bitset[7]);

    // Test 9: Shift by exactly 512 bits (clears everything)
    obj.head      = 5000;
    obj.bitset[0] = 0x1234567890ABCDEFULL;
    obj.bitset[1] = 0xFEDCBA0987654321ULL;
    obj.bitset[2] = 0xAAAAAAAAAAAAAAAAULL;
    obj.bitset[3] = 0x5555555555555555ULL;
    obj.bitset[4] = 0x1111111111111111ULL;
    obj.bitset[5] = 0x2222222222222222ULL;
    obj.bitset[6] = 0x3333333333333333ULL;
    obj.bitset[7] = 0x4444444444444444ULL;
    rx_transfer_id_window_slide(&obj, 5512);
    TEST_ASSERT_EQUAL_UINT64(5512, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[7]);

    // Test 10: Large shift (> 512 bits, erases everything)
    obj.head      = 10000;
    obj.bitset[0] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[1] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[2] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[3] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[4] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[5] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[6] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[7] = 0xFFFFFFFFFFFFFFFFULL;
    rx_transfer_id_window_slide(&obj, 10600);
    TEST_ASSERT_EQUAL_UINT64(10600, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[7]);

    // Test 11: Shift from 0 to small value
    obj.head      = 0;
    obj.bitset[0] = 0x0000000000000001ULL;
    obj.bitset[1] = 0x0000000000000000ULL;
    obj.bitset[2] = 0x0000000000000000ULL;
    obj.bitset[3] = 0x0000000000000000ULL;
    obj.bitset[4] = 0x0000000000000000ULL;
    obj.bitset[5] = 0x0000000000000000ULL;
    obj.bitset[6] = 0x0000000000000000ULL;
    obj.bitset[7] = 0x0000000000000000ULL;
    rx_transfer_id_window_slide(&obj, 10);
    TEST_ASSERT_EQUAL_UINT64(10, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000400ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[7]);

    // Test 12: Shift with wraparound (UINT64_MAX to 0)
    obj.head      = UINT64_MAX;
    obj.bitset[0] = 0x0000000000000001ULL;
    obj.bitset[1] = 0x0000000000000002ULL;
    obj.bitset[2] = 0x0000000000000004ULL;
    obj.bitset[3] = 0x0000000000000008ULL;
    obj.bitset[4] = 0x0000000000000010ULL;
    obj.bitset[5] = 0x0000000000000020ULL;
    obj.bitset[6] = 0x0000000000000040ULL;
    obj.bitset[7] = 0x0000000000000080ULL;
    rx_transfer_id_window_slide(&obj, 0);
    TEST_ASSERT_EQUAL_UINT64(0, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000002ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000004ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000008ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000010ULL, obj.bitset[3]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000020ULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000040ULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000080ULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000100ULL, obj.bitset[7]);

    // Test 13: Shift with wraparound (UINT64_MAX - 5 to 5)
    obj.head      = UINT64_MAX - 5;
    obj.bitset[0] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[1] = 0x0000000000000000ULL;
    obj.bitset[2] = 0x0000000000000000ULL;
    obj.bitset[3] = 0x0000000000000000ULL;
    obj.bitset[4] = 0x0000000000000000ULL;
    obj.bitset[5] = 0x0000000000000000ULL;
    obj.bitset[6] = 0x0000000000000000ULL;
    obj.bitset[7] = 0x0000000000000000ULL;
    rx_transfer_id_window_slide(&obj, 5);
    TEST_ASSERT_EQUAL_UINT64(5, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFF800ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000000007FFULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[7]);

    // Test 14: Shift by 32 bits (partial word shift with carries)
    obj.head      = 1000;
    obj.bitset[0] = 0xFFFFFFFF00000000ULL;
    obj.bitset[1] = 0xFFFFFFFF00000000ULL;
    obj.bitset[2] = 0xFFFFFFFF00000000ULL;
    obj.bitset[3] = 0xFFFFFFFF00000000ULL;
    obj.bitset[4] = 0xFFFFFFFF00000000ULL;
    obj.bitset[5] = 0xFFFFFFFF00000000ULL;
    obj.bitset[6] = 0xFFFFFFFF00000000ULL;
    obj.bitset[7] = 0xFFFFFFFF00000000ULL;
    rx_transfer_id_window_slide(&obj, 1032);
    TEST_ASSERT_EQUAL_UINT64(1032, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000FFFFFFFFULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000FFFFFFFFULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000FFFFFFFFULL, obj.bitset[3]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000FFFFFFFFULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000FFFFFFFFULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000FFFFFFFFULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0x00000000FFFFFFFFULL, obj.bitset[7]);

    // Test 15: All bits set, shift by 1
    obj.head      = 7777;
    obj.bitset[0] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[1] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[2] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[3] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[4] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[5] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[6] = 0xFFFFFFFFFFFFFFFFULL;
    obj.bitset[7] = 0xFFFFFFFFFFFFFFFFULL;
    rx_transfer_id_window_slide(&obj, 7778);
    TEST_ASSERT_EQUAL_UINT64(7778, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFEULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFFULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFFULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFFULL, obj.bitset[3]);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFFULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFFULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFFULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFFULL, obj.bitset[7]);
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
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[7]);
    rx_transfer_id_window_set(&obj, 98);
    TEST_ASSERT_EQUAL_UINT64(100, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000005ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[3]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[7]);
    rx_transfer_id_window_set(&obj, 0xFFFFFFFFFFFFFFA4ULL);
    TEST_ASSERT_EQUAL_UINT64(100, obj.head);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000005ULL, obj.bitset[0]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[1]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[2]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000001ULL, obj.bitset[3]); // 192 bits back
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[4]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[5]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[6]);
    TEST_ASSERT_EQUAL_UINT64(0x0000000000000000ULL, obj.bitset[7]);

    TEST_ASSERT_TRUE(rx_transfer_id_window_test(&obj, 100));
    TEST_ASSERT_TRUE(rx_transfer_id_window_test(&obj, 98));
    TEST_ASSERT_TRUE(rx_transfer_id_window_test(&obj, 0xFFFFFFFFFFFFFFA4ULL));
    TEST_ASSERT_FALSE(rx_transfer_id_window_test(&obj, 99));
    TEST_ASSERT_FALSE(rx_transfer_id_window_test(&obj, 97));
    TEST_ASSERT_FALSE(rx_transfer_id_window_test(&obj, 0xFFFFFFFFFFFFFFA3ULL));

    // Test rx_transfer_id_window_contains with various scenarios
    // The window contains transfer IDs from (head - 511) to head (512 IDs total)

    // Test with head=100: window contains [100-511 wrapping, ..., 100]
    obj.head = 100;
    TEST_ASSERT_TRUE(rx_transfer_id_window_contains(&obj, 100));              // at head
    TEST_ASSERT_TRUE(rx_transfer_id_window_contains(&obj, 99));               // 1 behind
    TEST_ASSERT_TRUE(rx_transfer_id_window_contains(&obj, 50));               // 50 behind
    TEST_ASSERT_TRUE(rx_transfer_id_window_contains(&obj, 0));                // 100 behind
    TEST_ASSERT_TRUE(rx_transfer_id_window_contains(&obj, 100ULL - 511ULL));  // 511 behind (wraps, edge of window)
    TEST_ASSERT_FALSE(rx_transfer_id_window_contains(&obj, 100ULL - 512ULL)); // 512 behind (wraps, outside)
    TEST_ASSERT_FALSE(rx_transfer_id_window_contains(&obj, 101));             // ahead (outside)
    TEST_ASSERT_FALSE(rx_transfer_id_window_contains(&obj, 200));             // far ahead (outside)

    // Test with head=0: window contains [UINT64_MAX-510, ..., 0]
    obj.head = 0;
    TEST_ASSERT_TRUE(rx_transfer_id_window_contains(&obj, 0));                 // at head
    TEST_ASSERT_TRUE(rx_transfer_id_window_contains(&obj, UINT64_MAX));        // 1 behind (wraps)
    TEST_ASSERT_TRUE(rx_transfer_id_window_contains(&obj, UINT64_MAX - 100));  // 101 behind
    TEST_ASSERT_TRUE(rx_transfer_id_window_contains(&obj, UINT64_MAX - 510));  // 511 behind (edge)
    TEST_ASSERT_FALSE(rx_transfer_id_window_contains(&obj, UINT64_MAX - 511)); // 512 behind (outside)
    TEST_ASSERT_FALSE(rx_transfer_id_window_contains(&obj, 1));                // ahead (outside)

    // Test with head=UINT64_MAX
    obj.head = UINT64_MAX;
    TEST_ASSERT_TRUE(rx_transfer_id_window_contains(&obj, UINT64_MAX));        // at head
    TEST_ASSERT_TRUE(rx_transfer_id_window_contains(&obj, UINT64_MAX - 1));    // 1 behind
    TEST_ASSERT_TRUE(rx_transfer_id_window_contains(&obj, UINT64_MAX - 511));  // 511 behind (edge)
    TEST_ASSERT_FALSE(rx_transfer_id_window_contains(&obj, UINT64_MAX - 512)); // 512 behind (outside)
    TEST_ASSERT_FALSE(rx_transfer_id_window_contains(&obj, 0));                // ahead (wraps forward, outside)

    // Test boundary at exactly 512 positions
    obj.head = 1000;
    TEST_ASSERT_TRUE(rx_transfer_id_window_contains(&obj, 1000));  // at head
    TEST_ASSERT_TRUE(rx_transfer_id_window_contains(&obj, 489));   // 511 behind (edge, inside)
    TEST_ASSERT_FALSE(rx_transfer_id_window_contains(&obj, 488));  // 512 behind (outside)
    TEST_ASSERT_FALSE(rx_transfer_id_window_contains(&obj, 1001)); // ahead (outside)
}

// ---------------------------------------------  SLOT  ---------------------------------------------

static void test_rx_slot_update(void)
{
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    const udpard_mem_resource_t mem_frag = instrumented_allocator_make_resource(&alloc_frag);

    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_resource_t mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_mem_deleter_t  del_payload = instrumented_allocator_make_deleter(&alloc_payload);

    uint64_t errors_oom                = 0;
    uint64_t errors_transfer_malformed = 0;

    // Test 1: Initialize slot from idle state (slot->state != rx_slot_busy branch)
    {
        rx_slot_t slot = { 0 };
        slot.state     = rx_slot_idle;

        rx_frame_t frame                 = { 0 };
        frame.base                       = make_frame_base(mem_payload, 0, 5, "hello");
        frame.base.crc                   = 0x9a71bb4cUL; // CRC32C for "hello"
        frame.meta.transfer_id           = 123;
        frame.meta.transfer_payload_size = 5;

        const udpard_us_t ts = 1000;

        rx_slot_update(&slot, ts, mem_frag, del_payload, frame, 5, &errors_oom, &errors_transfer_malformed);

        // Verify slot was initialized
        TEST_ASSERT_EQUAL(rx_slot_done, slot.state); // Single-frame transfer completes immediately
        TEST_ASSERT_EQUAL(123, slot.transfer_id);
        TEST_ASSERT_EQUAL(ts, slot.ts_min);
        TEST_ASSERT_EQUAL(ts, slot.ts_max);
        TEST_ASSERT_EQUAL_size_t(5, slot.covered_prefix);
        TEST_ASSERT_EQUAL(0, errors_oom);

        rx_slot_reset(&slot, mem_frag);
        rx_slot_reset(&slot, mem_frag); // idempotent
    }
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Test 2: Multi-frame transfer with timestamp updates (later/earlier branches)
    {
        rx_slot_t slot = { 0 };
        slot.state     = rx_slot_idle;

        // First frame at offset 0
        rx_frame_t frame1                 = { 0 };
        frame1.base                       = make_frame_base(mem_payload, 0, 3, "abc");
        frame1.base.crc                   = 0x12345678;
        frame1.meta.transfer_id           = 456;
        frame1.meta.transfer_payload_size = 10;

        const udpard_us_t ts1 = 2000;
        rx_slot_update(&slot, ts1, mem_frag, del_payload, frame1, 10, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_EQUAL(rx_slot_busy, slot.state);
        TEST_ASSERT_EQUAL(ts1, slot.ts_min);
        TEST_ASSERT_EQUAL(ts1, slot.ts_max);
        TEST_ASSERT_EQUAL_size_t(3, slot.covered_prefix);
        TEST_ASSERT_EQUAL(3, slot.crc_end);
        TEST_ASSERT_EQUAL(0x12345678, slot.crc);

        // Second frame at offset 5, with later timestamp
        rx_frame_t frame2                 = { 0 };
        frame2.base                       = make_frame_base(mem_payload, 5, 3, "def");
        frame2.base.crc                   = 0x87654321;
        frame2.meta.transfer_id           = 456;
        frame2.meta.transfer_payload_size = 10;

        const udpard_us_t ts2 = 3000; // Later than ts1
        rx_slot_update(&slot, ts2, mem_frag, del_payload, frame2, 10, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_EQUAL(rx_slot_busy, slot.state);
        TEST_ASSERT_EQUAL(ts1, slot.ts_min);              // Unchanged (ts2 is later)
        TEST_ASSERT_EQUAL(ts2, slot.ts_max);              // Updated to later time
        TEST_ASSERT_EQUAL_size_t(3, slot.covered_prefix); // Still 3 due to gap at [3-5)
        TEST_ASSERT_EQUAL(8, slot.crc_end);               // Updated to end of frame2
        TEST_ASSERT_EQUAL(0x87654321, slot.crc);          // Updated to frame2's CRC

        // Third frame at offset 3 (fills gap), with earlier timestamp
        rx_frame_t frame3                 = { 0 };
        frame3.base                       = make_frame_base(mem_payload, 3, 2, "XX");
        frame3.base.crc                   = 0xAABBCCDD;
        frame3.meta.transfer_id           = 456;
        frame3.meta.transfer_payload_size = 10;

        const udpard_us_t ts3 = 1500; // Earlier than ts1
        rx_slot_update(&slot, ts3, mem_frag, del_payload, frame3, 10, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_EQUAL(rx_slot_busy, slot.state);
        TEST_ASSERT_EQUAL(ts3, slot.ts_min);              // Updated to earlier time
        TEST_ASSERT_EQUAL(ts2, slot.ts_max);              // Unchanged (ts3 is earlier)
        TEST_ASSERT_EQUAL_size_t(8, slot.covered_prefix); // Now contiguous 0-8
        TEST_ASSERT_EQUAL(8, slot.crc_end);               // Unchanged (frame3 doesn't extend beyond frame2)
        TEST_ASSERT_EQUAL(0x87654321, slot.crc);          // Unchanged (crc_end didn't increase)

        rx_slot_reset(&slot, mem_frag);
    }
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Test 3: OOM handling (tree_res == rx_fragment_tree_oom branch)
    {
        rx_slot_t slot = { 0 };
        slot.state     = rx_slot_idle;
        errors_oom     = 0;

        // Limit allocations to trigger OOM
        alloc_frag.limit_fragments = 0;

        rx_frame_t frame                 = { 0 };
        frame.base                       = make_frame_base(mem_payload, 0, 5, "hello");
        frame.base.crc                   = 0x9a71bb4cUL; // CRC32C for "hello"
        frame.meta.transfer_id           = 789;
        frame.meta.transfer_payload_size = 5;

        rx_slot_update(&slot, 5000, mem_frag, del_payload, frame, 5, &errors_oom, &errors_transfer_malformed);

        // Verify OOM error was counted
        TEST_ASSERT_EQUAL(1, errors_oom);
        TEST_ASSERT_EQUAL(rx_slot_busy, slot.state);      // Slot initialized but fragment not added
        TEST_ASSERT_EQUAL_size_t(0, slot.covered_prefix); // No fragments accepted

        // Restore allocation limit
        alloc_frag.limit_fragments = SIZE_MAX;

        rx_slot_reset(&slot, mem_frag);
    }
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Test 4: Malformed transfer handling (CRC failure in rx_fragment_tree_finalize)
    {
        rx_slot_t slot            = { 0 };
        slot.state                = rx_slot_idle;
        errors_transfer_malformed = 0;

        // Single-frame transfer with incorrect CRC
        rx_frame_t frame                 = { 0 };
        frame.base                       = make_frame_base(mem_payload, 0, 4, "test");
        frame.base.crc                   = 0xDEADBEEF; // Incorrect CRC
        frame.meta.transfer_id           = 999;
        frame.meta.transfer_payload_size = 4;

        rx_slot_update(&slot, 6000, mem_frag, del_payload, frame, 4, &errors_oom, &errors_transfer_malformed);

        // Verify malformed error was counted and slot was reset
        TEST_ASSERT_EQUAL(1, errors_transfer_malformed);
        TEST_ASSERT_EQUAL(rx_slot_idle, slot.state); // Slot reset after CRC failure
        TEST_ASSERT_EQUAL_size_t(0, slot.covered_prefix);
        TEST_ASSERT_NULL(slot.fragments);

        rx_slot_reset(&slot, mem_frag);
    }
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Test 5: Successful completion with correct CRC (tree_res == rx_fragment_tree_done, CRC pass)
    {
        rx_slot_t slot            = { 0 };
        slot.state                = rx_slot_idle;
        errors_transfer_malformed = 0;
        errors_oom                = 0;

        // Single-frame transfer with correct CRC
        // CRC calculation for "test": using Python pycyphal.transport.commons.crc.CRC32C
        // >>> from pycyphal.transport.commons.crc import CRC32C
        // >>> hex(CRC32C.new(b"test").value)
        const uint32_t correct_crc = 0x86a072c0UL;

        rx_frame_t frame                 = { 0 };
        frame.base                       = make_frame_base(mem_payload, 0, 4, "test");
        frame.base.crc                   = correct_crc;
        frame.meta.transfer_id           = 1111;
        frame.meta.transfer_payload_size = 4;

        rx_slot_update(&slot, 7000, mem_frag, del_payload, frame, 4, &errors_oom, &errors_transfer_malformed);

        // Verify successful completion
        TEST_ASSERT_EQUAL(0, errors_transfer_malformed);
        TEST_ASSERT_EQUAL(rx_slot_done, slot.state); // Successfully completed
        TEST_ASSERT_EQUAL_size_t(4, slot.covered_prefix);
        TEST_ASSERT_NOT_NULL(slot.fragments);

        rx_slot_reset(&slot, mem_frag);
    }
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Test 6: CRC end update only when crc_end >= slot->crc_end
    {
        rx_slot_t slot            = { 0 };
        slot.state                = rx_slot_idle;
        errors_transfer_malformed = 0;
        errors_oom                = 0;

        // Frame 1 at offset 5 (will set crc_end to 10)
        rx_frame_t frame1                 = { 0 };
        frame1.base                       = make_frame_base(mem_payload, 5, 5, "world");
        frame1.base.crc                   = 0xAAAAAAAA;
        frame1.meta.transfer_id           = 2222;
        frame1.meta.transfer_payload_size = 20;

        rx_slot_update(&slot, 8000, mem_frag, del_payload, frame1, 20, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_EQUAL(10, slot.crc_end);
        TEST_ASSERT_EQUAL(0xAAAAAAAA, slot.crc);

        // Frame 2 at offset 0 (crc_end would be 3, less than current 10, so CRC shouldn't update)
        rx_frame_t frame2                 = { 0 };
        frame2.base                       = make_frame_base(mem_payload, 0, 3, "abc");
        frame2.base.crc                   = 0xBBBBBBBB;
        frame2.meta.transfer_id           = 2222;
        frame2.meta.transfer_payload_size = 20;

        rx_slot_update(&slot, 8100, mem_frag, del_payload, frame2, 20, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_EQUAL(10, slot.crc_end);     // Unchanged
        TEST_ASSERT_EQUAL(0xAAAAAAAA, slot.crc); // Unchanged (frame2 didn't update it)

        // Frame 3 at offset 10 (crc_end would be 15, greater than current 10, so CRC should update)
        rx_frame_t frame3                 = { 0 };
        frame3.base                       = make_frame_base(mem_payload, 10, 5, "hello");
        frame3.base.crc                   = 0xCCCCCCCC;
        frame3.meta.transfer_id           = 2222;
        frame3.meta.transfer_payload_size = 20;

        rx_slot_update(&slot, 8200, mem_frag, del_payload, frame3, 20, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_EQUAL(15, slot.crc_end);     // Updated
        TEST_ASSERT_EQUAL(0xCCCCCCCC, slot.crc); // Updated

        rx_slot_reset(&slot, mem_frag);
    }
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Test 7: Inconsistent frame fields; suspicious transfer rejected.
    {
        rx_slot_t slot            = { 0 };
        slot.state                = rx_slot_idle;
        errors_transfer_malformed = 0;
        errors_oom                = 0;

        // First frame initializes the slot with transfer_payload_size=20 and priority=udpard_prio_high
        rx_frame_t frame1                 = { 0 };
        frame1.base                       = make_frame_base(mem_payload, 0, 5, "hello");
        frame1.base.crc                   = 0x12345678;
        frame1.meta.transfer_id           = 3333;
        frame1.meta.transfer_payload_size = 20;
        frame1.meta.priority              = udpard_prio_high;

        rx_slot_update(&slot, 9000, mem_frag, del_payload, frame1, 20, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_EQUAL(rx_slot_busy, slot.state);
        TEST_ASSERT_EQUAL(20, slot.total_size);
        TEST_ASSERT_EQUAL(udpard_prio_high, slot.priority);
        TEST_ASSERT_EQUAL_size_t(5, slot.covered_prefix);
        TEST_ASSERT_EQUAL(0, errors_transfer_malformed);

        // Second frame with DIFFERENT transfer_payload_size (should trigger the branch and reset the slot)
        rx_frame_t frame2                 = { 0 };
        frame2.base                       = make_frame_base(mem_payload, 5, 5, "world");
        frame2.base.crc                   = 0xABCDEF00;
        frame2.meta.transfer_id           = 3333;
        frame2.meta.transfer_payload_size = 25; // DIFFERENT from frame1's 20
        frame2.meta.priority              = udpard_prio_high;

        rx_slot_update(&slot, 9100, mem_frag, del_payload, frame2, 25, &errors_oom, &errors_transfer_malformed);

        // Verify that the malformed error was counted and slot was reset
        TEST_ASSERT_EQUAL(1, errors_transfer_malformed);
        TEST_ASSERT_EQUAL(rx_slot_idle, slot.state); // Slot reset due to inconsistent total_size
        TEST_ASSERT_EQUAL_size_t(0, slot.covered_prefix);
        TEST_ASSERT_NULL(slot.fragments);

        // Reset counters
        errors_transfer_malformed = 0;

        // Third frame initializes the slot again with transfer_payload_size=30 and priority=udpard_prio_low
        rx_frame_t frame3                 = { 0 };
        frame3.base                       = make_frame_base(mem_payload, 0, 5, "test1");
        frame3.base.crc                   = 0x11111111;
        frame3.meta.transfer_id           = 4444;
        frame3.meta.transfer_payload_size = 30;
        frame3.meta.priority              = udpard_prio_low;

        rx_slot_update(&slot, 9200, mem_frag, del_payload, frame3, 30, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_EQUAL(rx_slot_busy, slot.state);
        TEST_ASSERT_EQUAL(30, slot.total_size);
        TEST_ASSERT_EQUAL(udpard_prio_low, slot.priority);
        TEST_ASSERT_EQUAL_size_t(5, slot.covered_prefix);
        TEST_ASSERT_EQUAL(0, errors_transfer_malformed);

        // Fourth frame with DIFFERENT priority (should trigger the branch and reset the slot)
        rx_frame_t frame4                 = { 0 };
        frame4.base                       = make_frame_base(mem_payload, 5, 5, "test2");
        frame4.base.crc                   = 0x22222222;
        frame4.meta.transfer_id           = 4444;
        frame4.meta.transfer_payload_size = 30;               // Same as frame3
        frame4.meta.priority              = udpard_prio_high; // DIFFERENT from frame3's udpard_prio_low

        rx_slot_update(&slot, 9300, mem_frag, del_payload, frame4, 30, &errors_oom, &errors_transfer_malformed);

        // Verify that the malformed error was counted and slot was reset
        TEST_ASSERT_EQUAL(1, errors_transfer_malformed);
        TEST_ASSERT_EQUAL(rx_slot_idle, slot.state); // Slot reset due to inconsistent priority
        TEST_ASSERT_EQUAL_size_t(0, slot.covered_prefix);
        TEST_ASSERT_NULL(slot.fragments);

        // Reset counters
        errors_transfer_malformed = 0;

        // Fifth frame initializes the slot again
        rx_frame_t frame5                 = { 0 };
        frame5.base                       = make_frame_base(mem_payload, 0, 5, "test3");
        frame5.base.crc                   = 0x33333333;
        frame5.meta.transfer_id           = 5555;
        frame5.meta.transfer_payload_size = 40;
        frame5.meta.priority              = udpard_prio_nominal;

        rx_slot_update(&slot, 9400, mem_frag, del_payload, frame5, 40, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_EQUAL(rx_slot_busy, slot.state);
        TEST_ASSERT_EQUAL(40, slot.total_size);
        TEST_ASSERT_EQUAL(udpard_prio_nominal, slot.priority);
        TEST_ASSERT_EQUAL_size_t(5, slot.covered_prefix);
        TEST_ASSERT_EQUAL(0, errors_transfer_malformed);

        // Sixth frame with BOTH different transfer_payload_size AND priority (should still trigger the branch)
        rx_frame_t frame6                 = { 0 };
        frame6.base                       = make_frame_base(mem_payload, 5, 5, "test4");
        frame6.base.crc                   = 0x44444444;
        frame6.meta.transfer_id           = 5555;
        frame6.meta.transfer_payload_size = 50;               // DIFFERENT from frame5's 40
        frame6.meta.priority              = udpard_prio_fast; // DIFFERENT from frame5's udpard_prio_nominal

        rx_slot_update(&slot, 9500, mem_frag, del_payload, frame6, 50, &errors_oom, &errors_transfer_malformed);

        // Verify that the malformed error was counted and slot was reset
        TEST_ASSERT_EQUAL(1, errors_transfer_malformed);
        TEST_ASSERT_EQUAL(rx_slot_idle, slot.state); // Slot reset due to both inconsistencies
        TEST_ASSERT_EQUAL_size_t(0, slot.covered_prefix);
        TEST_ASSERT_NULL(slot.fragments);

        rx_slot_reset(&slot, mem_frag);
    }
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Verify no memory leaks
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
}

// ---------------------------------------------  SESSION  ---------------------------------------------

typedef struct
{
    udpard_rx_t*              rx;
    udpard_rx_subscription_t* sub;
    struct
    {
        /// The most recently received transfer is at index #0; older transfers follow.
        /// The history is needed to allow batch ejection when multiple interned transfers are released.
        /// There cannot be more than RX_SLOT_COUNT transfers in the history because that is the maximum
        /// number of concurrent transfers that can be in-flight for a given session.
        udpard_rx_transfer_t history[RX_SLOT_COUNT];
        uint64_t             count;
    } message;
    struct
    {
        udpard_remote_t remote;
        uint64_t        count;
    } collision;
    struct
    {
        udpard_rx_ack_mandate_t am;
        uint64_t                count;
        /// We copy the payload head in here because the lifetime of the reference ends upon return from the callback.
        byte_t payload_head_storage[UDPARD_MTU_DEFAULT];
    } ack_mandate;
} callback_result_t;

static void on_message(udpard_rx_t* const rx, udpard_rx_subscription_t* const sub, const udpard_rx_transfer_t transfer)
{
    printf("on_message: ts=%lld transfer_id=%llu payload_size_stored=%zu\n",
           (long long)transfer.timestamp,
           (unsigned long long)transfer.transfer_id,
           transfer.payload_size_stored);
    callback_result_t* const cb_result = (callback_result_t* const)rx->user;
    cb_result->rx                      = rx;
    cb_result->sub                     = sub;
    for (size_t i = RX_SLOT_COUNT - 1; i > 0; i--) {
        cb_result->message.history[i] = cb_result->message.history[i - 1];
    }
    cb_result->message.history[0] = transfer;
    cb_result->message.count++;
}

static void on_collision(udpard_rx_t* const rx, udpard_rx_subscription_t* const sub, const udpard_remote_t remote)
{
    callback_result_t* const cb_result = (callback_result_t* const)rx->user;
    cb_result->rx                      = rx;
    cb_result->sub                     = sub;
    cb_result->collision.remote        = remote;
    cb_result->collision.count++;
}

static void on_ack_mandate(udpard_rx_t* const rx, udpard_rx_subscription_t* const sub, const udpard_rx_ack_mandate_t am)
{
    callback_result_t* const cb_result = (callback_result_t* const)rx->user;
    cb_result->rx                      = rx;
    cb_result->sub                     = sub;
    cb_result->ack_mandate.am          = am;
    cb_result->ack_mandate.count++;
    // Copy the payload head to our storage.
    TEST_PANIC_UNLESS(am.payload_head.size <= sizeof(cb_result->ack_mandate.payload_head_storage));
    memcpy(cb_result->ack_mandate.payload_head_storage, am.payload_head.data, am.payload_head.size);
    cb_result->ack_mandate.am.payload_head.data = cb_result->ack_mandate.payload_head_storage;
}

static void test_session_ordered_basic(void)
{
    // Initialize the memory resources.
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    const udpard_mem_resource_t mem_frag = instrumented_allocator_make_resource(&alloc_frag);

    instrumented_allocator_t alloc_session = { 0 };
    instrumented_allocator_new(&alloc_session);
    const udpard_mem_resource_t mem_session = instrumented_allocator_make_resource(&alloc_session);

    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_resource_t mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_mem_deleter_t  del_payload = instrumented_allocator_make_deleter(&alloc_payload);

    const udpard_rx_memory_resources_t rx_mem = { .fragment = mem_frag, .session = mem_session };

    // Initialize the shared RX instance.
    const uint64_t local_uid = 0xC3C8E4974254E1F5ULL;
    udpard_rx_t    rx;
    TEST_ASSERT(udpard_rx_new(&rx, local_uid, rx_mem, &on_message, &on_collision, &on_ack_mandate));
    callback_result_t cb_result = { 0 };
    rx.user                     = &cb_result;

    // Construct the session instance.
    udpard_us_t         now        = 0;
    const uint64_t      remote_uid = 0xA1B2C3D4E5F60718ULL;
    udpard_rx_port_t    port       = { .topic_hash                  = 0x4E81E200CB479D4CULL,
                                       .extent                      = 1000,
                                       .reordering_window           = 20 * KILO,
                                       .memory                      = rx_mem,
                                       .index_session_by_remote_uid = NULL };
    rx_session_t* const ses        = rx_session_new(&port, &rx.list_session_by_animation, remote_uid, now);

    // Verify construction outcome.
    TEST_ASSERT_NOT_NULL(ses);
    TEST_ASSERT_EQUAL_PTR(rx.list_session_by_animation.head, &ses->list_by_animation);
    TEST_ASSERT_EQUAL_PTR(port.index_session_by_remote_uid, &ses->index_remote_uid);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(sizeof(rx_session_t), alloc_session.allocated_bytes);

    // Feed a valid multi-frame transfer and ensure the callback is invoked and the states are updated.
    meta_t meta = { .priority              = udpard_prio_high,
                    .flag_ack              = true,
                    .transfer_payload_size = 10,
                    .transfer_id           = 42,
                    .sender_uid            = remote_uid,
                    .topic_hash            = port.topic_hash };
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                      make_frame(meta, mem_payload, "0123456789", 5, 5),
                      del_payload,
                      0);
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000002, .port = 0x4321 }, // different endpoint
                      make_frame(meta, mem_payload, "0123456789", 0, 5),
                      del_payload,
                      2); // different interface

    // Check the results and free the transfer.
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL_PTR(&rx, cb_result.rx);
    TEST_ASSERT_EQUAL_PTR(&port, cb_result.sub);
    TEST_ASSERT_EQUAL(1000, cb_result.message.history[0].timestamp);
    TEST_ASSERT_EQUAL(udpard_prio_high, cb_result.message.history[0].priority);
    TEST_ASSERT_EQUAL(42, cb_result.message.history[0].transfer_id);
    // Check the return path discovery.
    TEST_ASSERT_EQUAL(remote_uid, cb_result.message.history[0].remote.uid);
    TEST_ASSERT_EQUAL(0x0A000001, cb_result.message.history[0].remote.endpoints[0].ip);
    TEST_ASSERT_EQUAL(0x00000000, cb_result.message.history[0].remote.endpoints[1].ip);
    TEST_ASSERT_EQUAL(0x0A000002, cb_result.message.history[0].remote.endpoints[2].ip);
    TEST_ASSERT_EQUAL(0x1234, cb_result.message.history[0].remote.endpoints[0].port);
    TEST_ASSERT_EQUAL(0x0000, cb_result.message.history[0].remote.endpoints[1].port);
    TEST_ASSERT_EQUAL(0x4321, cb_result.message.history[0].remote.endpoints[2].port);
    // Check the payload.
    TEST_ASSERT_EQUAL(2, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(2 * sizeof(udpard_fragment_t), alloc_frag.allocated_bytes);
    TEST_ASSERT_EQUAL(2, alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(10, alloc_payload.allocated_bytes);
    TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[0], 10, "0123456789", 10));

    // Successful reception mandates sending an ACK.
    TEST_ASSERT_EQUAL(1, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(udpard_prio_high, cb_result.ack_mandate.am.priority);
    TEST_ASSERT_EQUAL(42, cb_result.ack_mandate.am.transfer_id);
    // Where to send the ack.
    TEST_ASSERT_EQUAL(remote_uid, cb_result.ack_mandate.am.remote.uid);
    TEST_ASSERT_EQUAL(0x0A000001, cb_result.ack_mandate.am.remote.endpoints[0].ip);
    TEST_ASSERT_EQUAL(0x00000000, cb_result.ack_mandate.am.remote.endpoints[1].ip);
    TEST_ASSERT_EQUAL(0x0A000002, cb_result.ack_mandate.am.remote.endpoints[2].ip);
    TEST_ASSERT_EQUAL(0x1234, cb_result.ack_mandate.am.remote.endpoints[0].port);
    TEST_ASSERT_EQUAL(0x0000, cb_result.ack_mandate.am.remote.endpoints[1].port);
    TEST_ASSERT_EQUAL(0x4321, cb_result.ack_mandate.am.remote.endpoints[2].port);
    // First frame payload is sometimes needed for ACK generation.
    TEST_ASSERT_EQUAL_size_t(5, cb_result.ack_mandate.am.payload_head.size);
    TEST_ASSERT_EQUAL_MEMORY("01234", cb_result.ack_mandate.am.payload_head.data, 5);

    // Free the transfer payload.
    udpard_fragment_free_all(cb_result.message.history[0].payload_head, mem_frag);
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);

    // Feed a repeated frame with the same transfer-ID.
    // Should be ignored except for the return path and ACK retransmission.
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000003, .port = 0x1111 }, // different endpoint
                      make_frame(meta, mem_payload, "abcdef", 0, 6),
                      del_payload,
                      1); // different interface
    TEST_ASSERT_EQUAL(0x0A000001, ses->remote.endpoints[0].ip);
    TEST_ASSERT_EQUAL(0x0A000003, ses->remote.endpoints[1].ip);
    TEST_ASSERT_EQUAL(0x0A000002, ses->remote.endpoints[2].ip);
    TEST_ASSERT_EQUAL(0x1234, ses->remote.endpoints[0].port);
    TEST_ASSERT_EQUAL(0x1111, ses->remote.endpoints[1].port);
    TEST_ASSERT_EQUAL(0x4321, ses->remote.endpoints[2].port);

    // Nothing happened except that we just generated another ACK mandate.
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(2, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments); // the new frame payload was freed by the session
    TEST_ASSERT_EQUAL(udpard_prio_high, cb_result.ack_mandate.am.priority);
    TEST_ASSERT_EQUAL(42, cb_result.ack_mandate.am.transfer_id);
    // Where to send the ack -- new address discovered.
    TEST_ASSERT_EQUAL(remote_uid, cb_result.ack_mandate.am.remote.uid);
    TEST_ASSERT_EQUAL(0x0A000001, cb_result.ack_mandate.am.remote.endpoints[0].ip);
    TEST_ASSERT_EQUAL(0x0A000003, cb_result.ack_mandate.am.remote.endpoints[1].ip); // updated!
    TEST_ASSERT_EQUAL(0x0A000002, cb_result.ack_mandate.am.remote.endpoints[2].ip);
    TEST_ASSERT_EQUAL(0x1234, cb_result.ack_mandate.am.remote.endpoints[0].port);
    TEST_ASSERT_EQUAL(0x1111, cb_result.ack_mandate.am.remote.endpoints[1].port); // updated!
    TEST_ASSERT_EQUAL(0x4321, cb_result.ack_mandate.am.remote.endpoints[2].port);
    // First frame payload is sometimes needed for ACK generation.
    TEST_ASSERT_EQUAL_size_t(6, cb_result.ack_mandate.am.payload_head.size);
    TEST_ASSERT_EQUAL_MEMORY("abcdef", cb_result.ack_mandate.am.payload_head.data, 6);

    // Feed a repeated frame with the same transfer-ID.
    // Should be ignored except for the return path update. No ACK needed because the frame does not request it.
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);
    meta.flag_ack = false;
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000004, .port = 0x2222 }, // different endpoint
                      make_frame(meta, mem_payload, "123", 0, 3),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(0x0A000004, ses->remote.endpoints[0].ip);
    TEST_ASSERT_EQUAL(0x0A000003, ses->remote.endpoints[1].ip);
    TEST_ASSERT_EQUAL(0x0A000002, ses->remote.endpoints[2].ip);
    TEST_ASSERT_EQUAL(0x2222, ses->remote.endpoints[0].port);
    TEST_ASSERT_EQUAL(0x1111, ses->remote.endpoints[1].port);
    TEST_ASSERT_EQUAL(0x4321, ses->remote.endpoints[2].port);
    // Nothing happened.
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(2, cb_result.ack_mandate.count);

    // Feed a repeated frame with the same transfer-ID.
    // Should be ignored except for the return path update. No ACK needed because the frame is not the first one.
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);
    meta.flag_ack = true;
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000004, .port = 0x2222 },
                      make_frame(meta, mem_payload, "123456", 3, 3),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(0x0A000004, ses->remote.endpoints[0].ip);
    TEST_ASSERT_EQUAL(0x0A000003, ses->remote.endpoints[1].ip);
    TEST_ASSERT_EQUAL(0x0A000002, ses->remote.endpoints[2].ip);
    TEST_ASSERT_EQUAL(0x2222, ses->remote.endpoints[0].port);
    TEST_ASSERT_EQUAL(0x1111, ses->remote.endpoints[1].port);
    TEST_ASSERT_EQUAL(0x4321, ses->remote.endpoints[2].port);
    // Nothing happened.
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(2, cb_result.ack_mandate.count);

    // Feed a repeated frame with an earlier transfer-ID.
    // Should be ignored except for the return path update. No ACK because we haven't actually received this TID.
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);
    meta.flag_ack    = true; // requested, but it will not be sent
    meta.transfer_id = 7;    // earlier TID that was not received
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000005, .port = 0x3333 }, // different endpoint
                      make_frame(meta, mem_payload, "123", 0, 3),
                      del_payload,
                      2);
    TEST_ASSERT_EQUAL(0x0A000004, ses->remote.endpoints[0].ip);
    TEST_ASSERT_EQUAL(0x0A000003, ses->remote.endpoints[1].ip);
    TEST_ASSERT_EQUAL(0x0A000005, ses->remote.endpoints[2].ip);
    TEST_ASSERT_EQUAL(0x2222, ses->remote.endpoints[0].port);
    TEST_ASSERT_EQUAL(0x1111, ses->remote.endpoints[1].port);
    TEST_ASSERT_EQUAL(0x3333, ses->remote.endpoints[2].port);
    // Nothing happened.
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(2, cb_result.ack_mandate.count);

    // Feed an out-of-order transfer. It will be interned in the reordering window, waiting for the missing transfer(s).
    // From now on we will be using single-frame transfers because at the session level they are not that different
    // from multi-frame ones except for the continuation slot lookup, which we've already covered.
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(2, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);
    meta.priority    = udpard_prio_low;
    meta.flag_ack    = true; // requested
    meta.transfer_id = 44;   // skips one transfer-ID, forcing a reordering delay.
    now += 1000;
    const udpard_us_t ts_44 = now;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000005, .port = 0x3333 },
                      make_frame(meta, mem_payload, "abcdefghij", 0, 10),
                      del_payload,
                      2);
    // We are asked to send an ACK, but the application hasn't seen the transfer yet -- it is interned.
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(3, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(1, alloc_frag.allocated_fragments); // the interned transfer
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_payload.allocated_fragments); // the interned transfer
    // Verify the ACK mandate.
    TEST_ASSERT_EQUAL(udpard_prio_low, cb_result.ack_mandate.am.priority);
    TEST_ASSERT_EQUAL(44, cb_result.ack_mandate.am.transfer_id);
    // Where to send the ack -- new address discovered.
    TEST_ASSERT_EQUAL(remote_uid, cb_result.ack_mandate.am.remote.uid);
    TEST_ASSERT_EQUAL(0x0A000004, cb_result.ack_mandate.am.remote.endpoints[0].ip);
    TEST_ASSERT_EQUAL(0x0A000003, cb_result.ack_mandate.am.remote.endpoints[1].ip); // updated!
    TEST_ASSERT_EQUAL(0x0A000005, cb_result.ack_mandate.am.remote.endpoints[2].ip);
    TEST_ASSERT_EQUAL(0x2222, cb_result.ack_mandate.am.remote.endpoints[0].port);
    TEST_ASSERT_EQUAL(0x1111, cb_result.ack_mandate.am.remote.endpoints[1].port); // updated!
    TEST_ASSERT_EQUAL(0x3333, cb_result.ack_mandate.am.remote.endpoints[2].port);
    // First frame payload is sometimes needed for ACK generation.
    TEST_ASSERT_EQUAL_size_t(10, cb_result.ack_mandate.am.payload_head.size);
    TEST_ASSERT_EQUAL_MEMORY("abcdefghij", cb_result.ack_mandate.am.payload_head.data, 10);

    // Repeat the same transfer. It must be rejected even though the reception head is still at 42.
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(3, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(1, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_payload.allocated_fragments);
    meta.flag_ack = false;
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000005, .port = 0x3333 },
                      make_frame(meta, mem_payload, "0123456789", 0, 10), // ignored anyway
                      del_payload,
                      2);
    // Nothing happened.
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(3, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(1, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_payload.allocated_fragments);

    // Feed another out-of-order transfer.
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(3, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(1, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_payload.allocated_fragments);
    meta.priority    = udpard_prio_fast;
    meta.flag_ack    = false;
    meta.transfer_id = 46; // after this one, we will have: received: 42, interned: 44, 46. Waiting for 43, 45.
    now += 1000;
    const udpard_us_t ts_46 = now;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000005, .port = 0x3333 },
                      make_frame(meta, mem_payload, "klmnopqrst", 0, 10),
                      del_payload,
                      2);
    // Nothing happened, the transfer added to the interned set.
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(3, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(2, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(2, alloc_payload.allocated_fragments);

    // Feed the missing transfer 45. It will not, however, release anything because 43 is still missing.
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(3, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(2, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(2, alloc_payload.allocated_fragments);
    meta.priority    = udpard_prio_optional;
    meta.flag_ack    = true;
    meta.transfer_id = 45;
    now += 1000;
    const udpard_us_t ts_45 = now;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000005, .port = 0x3333 },
                      make_frame(meta, mem_payload, "9876543210", 0, 10),
                      del_payload,
                      2);
    // ACK requested and the transfer is added to the interned set: 44, 45, 46.
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(3, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(3, alloc_payload.allocated_fragments);
    // Verify the ACK mandate.
    TEST_ASSERT_EQUAL(udpard_prio_optional, cb_result.ack_mandate.am.priority);
    TEST_ASSERT_EQUAL(45, cb_result.ack_mandate.am.transfer_id);
    TEST_ASSERT_EQUAL_size_t(10, cb_result.ack_mandate.am.payload_head.size);
    TEST_ASSERT_EQUAL_MEMORY("9876543210", cb_result.ack_mandate.am.payload_head.data, 10);

    // Receive another out-of-order transfer 500. It will likewise be interned.
    // The reception bitmask will still stay at the old head, allowing us to continue providing ACK retransmission
    // and duplicate rejection until the reordering timeout for 500 has expired. At that moment, the head will be
    // moved and the old ack/duplicate state will be discarded as being too old.
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(3, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(3, alloc_payload.allocated_fragments);
    meta.priority    = udpard_prio_optional;
    meta.flag_ack    = false;
    meta.transfer_id = 500;
    now += 1000;
    const udpard_us_t ts_500 = now;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000005, .port = 0x3333 },
                      make_frame(meta, mem_payload, "9876543210", 0, 10),
                      del_payload,
                      2);
    // Nothing happened, the transfer added to the interned set.
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(4, alloc_frag.allocated_fragments); // 44, 45, 46, 500.
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(4, alloc_payload.allocated_fragments);

    // Now, emit the missing transfer 43. This will release 43, 44, 45, and 46 to the application.
    // The head will be moved. ACKs have already been transmitted for all of them.
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(4, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(4, alloc_payload.allocated_fragments);
    meta.priority    = udpard_prio_optional;
    meta.flag_ack    = false;
    meta.transfer_id = 43;
    now += 1000;
    const udpard_us_t ts_43 = now;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000005, .port = 0x3333 },
                      make_frame(meta, mem_payload, "0123443210", 0, 10),
                      del_payload,
                      2);
    // 4 transfers released.
    TEST_ASSERT_EQUAL(5, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);    // no new mandates.
    TEST_ASSERT_EQUAL(5, alloc_frag.allocated_fragments); // not freed yet, see below.
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(5, alloc_payload.allocated_fragments);
    // The return path is the same for all transfers because it's taken from the shared session state during ejection.
    for (size_t i = 0; i < 4; i++) {
        udpard_remote_t* const rem = &cb_result.message.history[i].remote;
        TEST_ASSERT_EQUAL(remote_uid, rem->uid);
        TEST_ASSERT_EQUAL(0x0A000004, rem->endpoints[0].ip);
        TEST_ASSERT_EQUAL(0x0A000003, rem->endpoints[1].ip);
        TEST_ASSERT_EQUAL(0x0A000005, rem->endpoints[2].ip);
        TEST_ASSERT_EQUAL(0x2222, rem->endpoints[0].port);
        TEST_ASSERT_EQUAL(0x1111, rem->endpoints[1].port);
        TEST_ASSERT_EQUAL(0x3333, rem->endpoints[2].port);
    }
    // Verify transfer 43. It was released first so it's currently at index 3, then 44->#2, 45->#1, 46->#0.
    TEST_ASSERT_EQUAL(ts_43, cb_result.message.history[3].timestamp);
    TEST_ASSERT_EQUAL(udpard_prio_optional, cb_result.message.history[3].priority);
    TEST_ASSERT_EQUAL(43, cb_result.message.history[3].transfer_id);
    TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[3], 10, "0123443210", 10));
    // Verify transfer 44.
    TEST_ASSERT_EQUAL(ts_44, cb_result.message.history[2].timestamp);
    TEST_ASSERT_EQUAL(udpard_prio_low, cb_result.message.history[2].priority);
    TEST_ASSERT_EQUAL(44, cb_result.message.history[2].transfer_id);
    TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[2], 10, "abcdefghij", 10));
    // Verify transfer 45.
    TEST_ASSERT_EQUAL(ts_45, cb_result.message.history[1].timestamp);
    TEST_ASSERT_EQUAL(udpard_prio_optional, cb_result.message.history[1].priority);
    TEST_ASSERT_EQUAL(45, cb_result.message.history[1].transfer_id);
    TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[1], 10, "9876543210", 10));
    // Verify transfer 46.
    TEST_ASSERT_EQUAL(ts_46, cb_result.message.history[0].timestamp);
    TEST_ASSERT_EQUAL(udpard_prio_fast, cb_result.message.history[0].priority);
    TEST_ASSERT_EQUAL(46, cb_result.message.history[0].transfer_id);
    TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[0], 10, "klmnopqrst", 10));
    // Free all received transfer payloads. We still have transfer 500 interned though.
    TEST_ASSERT_EQUAL(5, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(5, alloc_payload.allocated_fragments);
    for (size_t i = 0; i < 4; i++) {
        udpard_fragment_free_all(cb_result.message.history[i].payload_head, mem_frag);
    }
    TEST_ASSERT_EQUAL(1, alloc_frag.allocated_fragments); // 500 is still there
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_payload.allocated_fragments);

    // Now, we are going to partially complete 499 and wait for the reordering window to close on 500.
    // As a result, 500 will be ejected and 499 will be reset because in the ORDERED mode it cannot follow 500.
    TEST_ASSERT_EQUAL(5, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(1, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_payload.allocated_fragments);
    meta.priority    = udpard_prio_optional;
    meta.flag_ack    = true; // requested but obviously it won't be sent since it's incomplete
    meta.transfer_id = 499;
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000005, .port = 0x3333 },
                      make_frame(meta, mem_payload, "abc", 0, 3), // incomplete
                      del_payload,
                      2);
    TEST_ASSERT_EQUAL(5, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(2, alloc_frag.allocated_fragments); // 499 incomplete
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(2, alloc_payload.allocated_fragments);
    // Advance time beyond the reordering window for transfer 500 and poll the global rx state.
    now = ts_500 + port.reordering_window;
    udpard_rx_poll(&rx, now);
    TEST_ASSERT_EQUAL(6, cb_result.message.count); // 500 ejected!
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(1, alloc_frag.allocated_fragments); // 499 reset!
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_payload.allocated_fragments);
    // Verify transfer 500.
    TEST_ASSERT_EQUAL(ts_500, cb_result.message.history[0].timestamp);
    TEST_ASSERT_EQUAL(udpard_prio_optional, cb_result.message.history[0].priority);
    TEST_ASSERT_EQUAL(500, cb_result.message.history[0].transfer_id);
    TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[0], 10, "9876543210", 10));
    udpard_fragment_free_all(cb_result.message.history[0].payload_head, mem_frag);
    // All transfers processed, nothing is interned.
    TEST_ASSERT_EQUAL(6, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);

    // The head is currently set to 500.
    // Now, feed a large number of transfers to occupy all available slots.
    // The last transfer will force an early closure of the reordering window on TID 1000.
    const udpard_udpip_ep_t ep = { .ip = 0x0A000005, .port = 0x3333 };
    TEST_ASSERT_EQUAL(6, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);
    meta.transfer_payload_size = 2;
    meta.flag_ack              = false;
    now += 1000;
    const udpard_us_t ts_1000 = now;
    for (size_t i = 0; i < RX_SLOT_COUNT; i++) {
        meta.transfer_id = 1000 + i;
        now              = ts_1000 + (udpard_us_t)i;
        char data[2]     = { '0', (char)('0' + i) };
        rx_session_update(ses, &rx, now, ep, make_frame(meta, mem_payload, data, 0, 2), del_payload, 2);
    }
    now = ts_1000 + 1000;
    // 8 transfers are interned.
    TEST_ASSERT_EQUAL(6, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(8, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(8, alloc_payload.allocated_fragments);
    // Pushing a repeat transfer doesn't do anything, it's just dropped.
    rx_session_update(ses, &rx, now, ep, make_frame(meta, mem_payload, "zz", 0, 2), del_payload, 2);
    // Yeah, it's just dropped.
    TEST_ASSERT_EQUAL(6, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(8, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(8, alloc_payload.allocated_fragments);
    // Send another transfer. This time we make it multi-frame and incomplete. The entire interned set is released.
    meta.transfer_id = 2000;
    now += 1000;
    rx_session_update(ses, &rx, now, ep, make_frame(meta, mem_payload, "20", 0, 1), del_payload, 2);
    // We should get RX_SLOT_COUNT callbacks.
    TEST_ASSERT_EQUAL(14, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(9, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(9, alloc_payload.allocated_fragments);
    // Check and free the received transfers from the callback.
    for (size_t i = 0; i < RX_SLOT_COUNT; i++) {
        udpard_rx_transfer_t* const tr = &cb_result.message.history[RX_SLOT_COUNT - (i + 1)]; // reverse order
        TEST_ASSERT_EQUAL_INT64(ts_1000 + (udpard_us_t)i, tr->timestamp);
        TEST_ASSERT_EQUAL(udpard_prio_optional, tr->priority);
        TEST_ASSERT_EQUAL(1000 + i, tr->transfer_id);
        TEST_ASSERT(transfer_payload_verify(tr, 2, (char[]){ '0', (char)('0' + i) }, 2));
        udpard_fragment_free_all(tr->payload_head, mem_frag);
    }
    TEST_ASSERT_EQUAL(14, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(1, alloc_frag.allocated_fragments); // 2000 incomplete
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_payload.allocated_fragments);

    // Send more than RX_SLOT_COUNT incomplete transfers to evict the incomplete 2000.
    // Afterward, complete some of them out of order and ensure they are received in the correct order.
    meta.transfer_id          = 3000;
    const udpard_us_t ts_3000 = now + 1000;
    for (size_t i = 0; i < RX_SLOT_COUNT; i++) {
        meta.transfer_id = 3000 + i;
        now              = ts_3000 + (udpard_us_t)i;
        rx_session_update(ses, &rx, now, ep, make_frame(meta, mem_payload, "30", 0, 1), del_payload, 2);
    }
    now = ts_3000 + 1000;
    // 8 transfers are in progress.
    TEST_ASSERT_EQUAL(14, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(8, alloc_frag.allocated_fragments); // all slots occupied
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(8, alloc_payload.allocated_fragments);
    // Complete 3001, 3000 out of order.
    meta.transfer_id = 3001;
    now += 1000;
    rx_session_update(ses, &rx, now, ep, make_frame(meta, mem_payload, "31", 1, 1), del_payload, 2);
    meta.transfer_id = 3000;
    now += 1000;
    rx_session_update(ses, &rx, now, ep, make_frame(meta, mem_payload, "30", 1, 1), del_payload, 2);
    // Wait for the reordering window to close on 3000. Then 3000 and 3001 will be ejected.
    now = ts_3000 + port.reordering_window;
    udpard_rx_poll(&rx, now);
    // 2 transfers ejected. The remaining 3002..3007 are still in-progress. 2000 is lost to slot starvation.
    TEST_ASSERT_EQUAL(16, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(10, alloc_frag.allocated_fragments); // 8 transfers, of them 2 keep two frames each.
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(10, alloc_payload.allocated_fragments); // ditto
    // Verify the ejected transfers: 3000->#1, 3001->#0.
    TEST_ASSERT_EQUAL_INT64(ts_3000, cb_result.message.history[1].timestamp);
    TEST_ASSERT_EQUAL(3000, cb_result.message.history[1].transfer_id);
    TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[1], 2, "30", 2));
    udpard_fragment_free_all(cb_result.message.history[1].payload_head, mem_frag);
    // Now 3001.
    TEST_ASSERT_EQUAL_INT64(ts_3000 + 1, cb_result.message.history[0].timestamp);
    TEST_ASSERT_EQUAL(3001, cb_result.message.history[0].transfer_id);
    TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[0], 2, "31", 2));
    udpard_fragment_free_all(cb_result.message.history[0].payload_head, mem_frag);
    // We still have 3002..3007 in progress. They will be freed once the session has expired.
    TEST_ASSERT_EQUAL(16, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(6, alloc_frag.allocated_fragments); // 6 in-progress transfers, each holding one frame
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(6, alloc_payload.allocated_fragments); // ditto

    // Time out the session state.
    now += SESSION_LIFETIME;
    udpard_rx_poll(&rx, now);
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);
    instrumented_allocator_reset(&alloc_frag); // Will crash if there are leaks
    instrumented_allocator_reset(&alloc_payload);
}

// ---------------------------------------------  FRAGMENT  ---------------------------------------------

static void test_udpard_fragment_seek(void)
{
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    const udpard_mem_resource_t mem_frag = instrumented_allocator_make_resource(&alloc_frag);

    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_resource_t mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_mem_deleter_t  del_payload = instrumented_allocator_make_deleter(&alloc_payload);

    // Build a fragment tree with multiple fragments with gaps between them.
    // Using make_frame_base to control exact sizes (no null terminators).
    // Fragments at offsets: 0-3 (3 bytes), 5-8 (3 bytes), 10-14 (4 bytes)
    udpard_tree_t* root = NULL;
    size_t         cov  = 0;

    // Fragment 1: offset 0, size 3
    rx_fragment_tree_update(&root, mem_frag, del_payload, make_frame_base(mem_payload, 0, 3, "abc"), 14, 14, &cov);
    TEST_ASSERT_NOT_NULL(root);
    TEST_ASSERT_EQUAL_size_t(3, cov); // Coverage is only the contiguous prefix from offset 0.

    // Fragment 2: offset 5, size 3
    rx_fragment_tree_update(&root, mem_frag, del_payload, make_frame_base(mem_payload, 5, 3, "def"), 14, 14, &cov);
    TEST_ASSERT_EQUAL_size_t(3, cov); // Still 3, gap at [3-5).

    // Fragment 3: offset 10, size 4
    rx_fragment_tree_update(&root, mem_frag, del_payload, make_frame_base(mem_payload, 10, 4, "ghij"), 14, 14, &cov);

    TEST_ASSERT_EQUAL(3, tree_count(root));
    TEST_ASSERT_EQUAL_size_t(3, cov); // Still 3, gaps prevent full coverage.

    // Get references to the fragments for testing.
    udpard_fragment_t* frag0 = fragment_at(root, 0);
    udpard_fragment_t* frag1 = fragment_at(root, 1);
    udpard_fragment_t* frag2 = fragment_at(root, 2);
    TEST_ASSERT_NOT_NULL(frag0);
    TEST_ASSERT_NOT_NULL(frag1);
    TEST_ASSERT_NOT_NULL(frag2);

    // Test seeking to offset 0 (should return first fragment).
    TEST_ASSERT_EQUAL_PTR(frag0, udpard_fragment_seek(frag0, 0));
    TEST_ASSERT_EQUAL_PTR(frag0, udpard_fragment_seek(frag1, 0));
    TEST_ASSERT_EQUAL_PTR(frag0, udpard_fragment_seek(frag2, 0));

    // Test seeking within first fragment [0-3).
    TEST_ASSERT_EQUAL_PTR(frag0, udpard_fragment_seek(frag0, 0));
    TEST_ASSERT_EQUAL_PTR(frag0, udpard_fragment_seek(frag0, 1));
    TEST_ASSERT_EQUAL_PTR(frag0, udpard_fragment_seek(frag0, 2));

    // Test seeking in gap [3-5) - should return NULL.
    TEST_ASSERT_NULL(udpard_fragment_seek(frag0, 3));
    TEST_ASSERT_NULL(udpard_fragment_seek(frag1, 4));

    // Test seeking to start of second fragment [5-8).
    TEST_ASSERT_EQUAL_PTR(frag1, udpard_fragment_seek(frag0, 5));
    TEST_ASSERT_EQUAL_PTR(frag1, udpard_fragment_seek(frag1, 5));
    TEST_ASSERT_EQUAL_PTR(frag1, udpard_fragment_seek(frag2, 5));

    // Test seeking within second fragment.
    TEST_ASSERT_EQUAL_PTR(frag1, udpard_fragment_seek(frag0, 6));
    TEST_ASSERT_EQUAL_PTR(frag1, udpard_fragment_seek(frag1, 7));

    // Test seeking in gap [8-10) - should return NULL.
    TEST_ASSERT_NULL(udpard_fragment_seek(frag0, 8));
    TEST_ASSERT_NULL(udpard_fragment_seek(frag1, 9));

    // Test seeking to start of third fragment [10-14).
    TEST_ASSERT_EQUAL_PTR(frag2, udpard_fragment_seek(frag0, 10));
    TEST_ASSERT_EQUAL_PTR(frag2, udpard_fragment_seek(frag1, 10));
    TEST_ASSERT_EQUAL_PTR(frag2, udpard_fragment_seek(frag2, 10));

    // Test seeking within third fragment.
    TEST_ASSERT_EQUAL_PTR(frag2, udpard_fragment_seek(frag0, 11));
    TEST_ASSERT_EQUAL_PTR(frag2, udpard_fragment_seek(frag1, 12));
    TEST_ASSERT_EQUAL_PTR(frag2, udpard_fragment_seek(frag2, 13));

    // Test seeking beyond payload (should return NULL).
    TEST_ASSERT_NULL(udpard_fragment_seek(frag0, 14));
    TEST_ASSERT_NULL(udpard_fragment_seek(frag1, 14));
    TEST_ASSERT_NULL(udpard_fragment_seek(frag2, 14));
    TEST_ASSERT_NULL(udpard_fragment_seek(frag0, 100));

    // Cleanup.
    udpard_fragment_free_all((udpard_fragment_t*)root, mem_frag);
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);

    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Test with single fragment.
    root = NULL;
    cov  = 0;
    rx_fragment_tree_update(&root, mem_frag, del_payload, make_frame_base(mem_payload, 0, 5, "hello"), 5, 5, &cov);
    TEST_ASSERT_NOT_NULL(root);

    udpard_fragment_t* single = fragment_at(root, 0);
    TEST_ASSERT_NOT_NULL(single);

    // Seek within single fragment.
    TEST_ASSERT_EQUAL_PTR(single, udpard_fragment_seek(single, 0));
    TEST_ASSERT_EQUAL_PTR(single, udpard_fragment_seek(single, 1));
    TEST_ASSERT_EQUAL_PTR(single, udpard_fragment_seek(single, 2));
    TEST_ASSERT_EQUAL_PTR(single, udpard_fragment_seek(single, 4));

    // Seek beyond single fragment.
    TEST_ASSERT_NULL(udpard_fragment_seek(single, 5));

    // Cleanup.
    udpard_fragment_free_all((udpard_fragment_t*)root, mem_frag);
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_rx_fragment_tree_update_a);
    RUN_TEST(test_rx_fragment_tree_update_exhaustive);
    RUN_TEST(test_rx_fragment_tree_oom);

    RUN_TEST(test_rx_transfer_id_forward_distance);
    RUN_TEST(test_rx_transfer_id_window_slide);
    RUN_TEST(test_rx_transfer_id_window_manip);

    RUN_TEST(test_rx_slot_update);

    RUN_TEST(test_session_ordered_basic);

    RUN_TEST(test_udpard_fragment_seek);

    return UNITY_END();
}
