/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

// ReSharper disable CppDFATimeOver

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
/// A helper that creates a frame in static storage and returns a reference to it. This is a testing aid.
static rx_frame_t* make_frame_ptr(const meta_t                meta,
                                  const udpard_mem_resource_t mem_payload,
                                  const void* const           full_transfer_payload,
                                  const size_t                frame_payload_offset,
                                  const size_t                frame_payload_size)
{
    static rx_frame_t frame;
    frame = make_frame(meta, mem_payload, full_transfer_payload, frame_payload_offset, frame_payload_size);
    return &frame;
}

/// Scans the transfer payload ensuring that its payload exactly matches the reference.
/// The node can be any node in the tree.
static bool transfer_payload_verify(udpard_rx_transfer_t* const transfer,
                                    const size_t                payload_size_stored,
                                    const void* const           payload,
                                    const size_t                payload_size_wire)
{
    const udpard_fragment_t* frag   = udpard_fragment_seek(transfer->payload, 0);
    size_t                   offset = 0;
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
        frag = udpard_fragment_next(frag);
    }
    return (transfer->payload_size_wire == payload_size_wire) && (offset == payload_size_stored);
}

// ---------------------------------------------  RX FRAGMENT TREE  ---------------------------------------------

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
    for (udpard_fragment_t* it = (udpard_fragment_t*)cavl2_min(root); it != NULL;
         it                    = (udpard_fragment_t*)cavl2_next_greater(&it->index_offset)) {
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
        udpard_fragment_free_all(udpard_fragment_seek((udpard_fragment_t*)root, 0), mem_frag);
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

// ---------------------------------------------  RX SLOT  ---------------------------------------------

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

        rx_slot_update(&slot, ts, mem_frag, del_payload, &frame, 5, &errors_oom, &errors_transfer_malformed);

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
        rx_slot_update(&slot, ts1, mem_frag, del_payload, &frame1, 10, &errors_oom, &errors_transfer_malformed);

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
        rx_slot_update(&slot, ts2, mem_frag, del_payload, &frame2, 10, &errors_oom, &errors_transfer_malformed);

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
        rx_slot_update(&slot, ts3, mem_frag, del_payload, &frame3, 10, &errors_oom, &errors_transfer_malformed);

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

        rx_slot_update(&slot, 5000, mem_frag, del_payload, &frame, 5, &errors_oom, &errors_transfer_malformed);

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

        rx_slot_update(&slot, 6000, mem_frag, del_payload, &frame, 4, &errors_oom, &errors_transfer_malformed);

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

        rx_slot_update(&slot, 7000, mem_frag, del_payload, &frame, 4, &errors_oom, &errors_transfer_malformed);

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

        rx_slot_update(&slot, 8000, mem_frag, del_payload, &frame1, 20, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_EQUAL(10, slot.crc_end);
        TEST_ASSERT_EQUAL(0xAAAAAAAA, slot.crc);

        // Frame 2 at offset 0 (crc_end would be 3, less than current 10, so CRC shouldn't update)
        rx_frame_t frame2                 = { 0 };
        frame2.base                       = make_frame_base(mem_payload, 0, 3, "abc");
        frame2.base.crc                   = 0xBBBBBBBB;
        frame2.meta.transfer_id           = 2222;
        frame2.meta.transfer_payload_size = 20;

        rx_slot_update(&slot, 8100, mem_frag, del_payload, &frame2, 20, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_EQUAL(10, slot.crc_end);     // Unchanged
        TEST_ASSERT_EQUAL(0xAAAAAAAA, slot.crc); // Unchanged (frame2 didn't update it)

        // Frame 3 at offset 10 (crc_end would be 15, greater than current 10, so CRC should update)
        rx_frame_t frame3                 = { 0 };
        frame3.base                       = make_frame_base(mem_payload, 10, 5, "hello");
        frame3.base.crc                   = 0xCCCCCCCC;
        frame3.meta.transfer_id           = 2222;
        frame3.meta.transfer_payload_size = 20;

        rx_slot_update(&slot, 8200, mem_frag, del_payload, &frame3, 20, &errors_oom, &errors_transfer_malformed);

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

        rx_slot_update(&slot, 9000, mem_frag, del_payload, &frame1, 20, &errors_oom, &errors_transfer_malformed);

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

        rx_slot_update(&slot, 9100, mem_frag, del_payload, &frame2, 25, &errors_oom, &errors_transfer_malformed);

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

        rx_slot_update(&slot, 9200, mem_frag, del_payload, &frame3, 30, &errors_oom, &errors_transfer_malformed);

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

        rx_slot_update(&slot, 9300, mem_frag, del_payload, &frame4, 30, &errors_oom, &errors_transfer_malformed);

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

        rx_slot_update(&slot, 9400, mem_frag, del_payload, &frame5, 40, &errors_oom, &errors_transfer_malformed);

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

        rx_slot_update(&slot, 9500, mem_frag, del_payload, &frame6, 50, &errors_oom, &errors_transfer_malformed);

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

// ---------------------------------------------  RX SESSION  ---------------------------------------------

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

typedef struct
{
    udpard_rx_t*      rx;
    udpard_rx_port_t* port;
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

static void on_message(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    printf("on_message: ts=%lld transfer_id=%llu payload_size_stored=%zu\n",
           (long long)transfer.timestamp,
           (unsigned long long)transfer.transfer_id,
           transfer.payload_size_stored);
    callback_result_t* const cb_result = (callback_result_t* const)rx->user;
    cb_result->rx                      = rx;
    cb_result->port                    = port;
    for (size_t i = RX_SLOT_COUNT - 1; i > 0; i--) {
        cb_result->message.history[i] = cb_result->message.history[i - 1];
    }
    cb_result->message.history[0] = transfer;
    cb_result->message.count++;
}

static void on_collision(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_remote_t remote)
{
    callback_result_t* const cb_result = (callback_result_t* const)rx->user;
    cb_result->rx                      = rx;
    cb_result->port                    = port;
    cb_result->collision.remote        = remote;
    cb_result->collision.count++;
}

static void on_ack_mandate(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_ack_mandate_t am)
{
    printf("on_ack_mandate: transfer_id=%llu payload_head_size=%zu\n",
           (unsigned long long)am.transfer_id,
           am.payload_head.size);
    callback_result_t* const cb_result = (callback_result_t* const)rx->user;
    cb_result->rx                      = rx;
    cb_result->port                    = port;
    cb_result->ack_mandate.am          = am;
    cb_result->ack_mandate.count++;
    // Copy the payload head to our storage.
    TEST_PANIC_UNLESS(am.payload_head.size <= sizeof(cb_result->ack_mandate.payload_head_storage));
    memcpy(cb_result->ack_mandate.payload_head_storage, am.payload_head.data, am.payload_head.size);
    cb_result->ack_mandate.am.payload_head.data = cb_result->ack_mandate.payload_head_storage;
}
static const udpard_rx_port_vtable_t callbacks = { &on_message, &on_collision, &on_ack_mandate };

/// Tests the ORDERED reassembly mode (strictly increasing transfer-ID sequence).
static void test_rx_session_ordered(void)
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

    const udpard_rx_mem_resources_t rx_mem = { .fragment = mem_frag, .session = mem_session };

    // Initialize the shared RX instance.
    udpard_rx_t rx;
    udpard_rx_new(&rx);
    callback_result_t cb_result = { 0 };
    rx.user                     = &cb_result;

    // Construct the session instance.
    udpard_us_t      now        = 0;
    const uint64_t   remote_uid = 0xA1B2C3D4E5F60718ULL;
    udpard_rx_port_t port;
    TEST_ASSERT(udpard_rx_port_new(&port, 0x4E81E200CB479D4CULL, 1000, 20 * KILO, rx_mem, &callbacks));
    rx_session_factory_args_t fac_args = {
        .owner                 = &port,
        .sessions_by_animation = &rx.list_session_by_animation,
        .remote_uid            = remote_uid,
        .now                   = now,
    };
    rx_session_t* const ses = (rx_session_t*)cavl2_find_or_insert(&port.index_session_by_remote_uid,
                                                                  &remote_uid,
                                                                  &cavl_compare_rx_session_by_remote_uid,
                                                                  &fac_args,
                                                                  &cavl_factory_rx_session_by_remote_uid);
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
                      make_frame_ptr(meta, mem_payload, "0123456789", 5, 5),
                      del_payload,
                      0);
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000002, .port = 0x4321 }, // different endpoint
                      make_frame_ptr(meta, mem_payload, "0123456789", 0, 5),
                      del_payload,
                      2); // different interface

    // Check the results and free the transfer.
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL_PTR(&rx, cb_result.rx);
    TEST_ASSERT_EQUAL_PTR(&port, cb_result.port);
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
    udpard_fragment_free_all(cb_result.message.history[0].payload, mem_frag);
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
                      make_frame_ptr(meta, mem_payload, "abcdef", 0, 6),
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
                      make_frame_ptr(meta, mem_payload, "123", 0, 3),
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
                      make_frame_ptr(meta, mem_payload, "123456", 3, 3),
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
                      make_frame_ptr(meta, mem_payload, "123", 0, 3),
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
                      make_frame_ptr(meta, mem_payload, "abcdefghij", 0, 10),
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
                      make_frame_ptr(meta, mem_payload, "0123456789", 0, 10),
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
                      make_frame_ptr(meta, mem_payload, "klmnopqrst", 0, 10),
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
                      make_frame_ptr(meta, mem_payload, "9876543210", 0, 10),
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
                      make_frame_ptr(meta, mem_payload, "9876543210", 0, 10),
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
                      make_frame_ptr(meta, mem_payload, "0123443210", 0, 10),
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
        udpard_fragment_free_all(cb_result.message.history[i].payload, mem_frag);
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
                      make_frame_ptr(meta, mem_payload, "abc", 0, 3),
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
    udpard_fragment_free_all(cb_result.message.history[0].payload, mem_frag);
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
        rx_session_update(ses, &rx, now, ep, make_frame_ptr(meta, mem_payload, data, 0, 2), del_payload, 2);
    }
    now = ts_1000 + 1000;
    // 8 transfers are interned.
    TEST_ASSERT_EQUAL(6, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(8, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(8, alloc_payload.allocated_fragments);
    // Pushing a repeat transfer doesn't do anything, it's just dropped.
    // Duplicate, should be dropped.
    rx_session_update(ses, &rx, now, ep, make_frame_ptr(meta, mem_payload, "zz", 0, 2), del_payload, 2);
    // Yeah, it's just dropped.
    TEST_ASSERT_EQUAL(6, cb_result.message.count);
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(8, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(8, alloc_payload.allocated_fragments);
    // Send another transfer. This time we make it multi-frame and incomplete. The entire interned set is released.
    meta.transfer_id = 2000;
    now += 1000;
    // Multi-frame incomplete payload to flush the interned set.
    rx_session_update(ses, &rx, now, ep, make_frame_ptr(meta, mem_payload, "20", 0, 1), del_payload, 2);
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
        udpard_fragment_free_all(tr->payload, mem_frag);
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
        rx_session_update(ses, &rx, now, ep, make_frame_ptr(meta, mem_payload, "30", 0, 1), del_payload, 2);
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
    rx_session_update(ses, &rx, now, ep, make_frame_ptr(meta, mem_payload, "31", 1, 1), del_payload, 2);
    meta.transfer_id = 3000;
    now += 1000;
    rx_session_update(ses, &rx, now, ep, make_frame_ptr(meta, mem_payload, "30", 1, 1), del_payload, 2);
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
    udpard_fragment_free_all(cb_result.message.history[1].payload, mem_frag);
    // Now 3001.
    TEST_ASSERT_EQUAL_INT64(ts_3000 + 1, cb_result.message.history[0].timestamp);
    TEST_ASSERT_EQUAL(3001, cb_result.message.history[0].transfer_id);
    TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[0], 2, "31", 2));
    udpard_fragment_free_all(cb_result.message.history[0].payload, mem_frag);
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

static void test_rx_session_unordered(void)
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

    const udpard_rx_mem_resources_t rx_mem = { .fragment = mem_frag, .session = mem_session };

    // Initialize the shared RX instance.
    udpard_rx_t rx;
    udpard_rx_new(&rx);
    callback_result_t cb_result = { 0 };
    rx.user                     = &cb_result;

    const uint64_t   local_uid = 0xC3C8E4974254E1F5ULL;
    udpard_rx_port_t p2p_port;
    TEST_ASSERT(
      udpard_rx_port_new(&p2p_port, local_uid, SIZE_MAX, UDPARD_RX_REORDERING_WINDOW_UNORDERED, rx_mem, &callbacks));

    // Construct the session instance using the p2p port.
    udpard_us_t               now        = 0;
    const uint64_t            remote_uid = 0xA1B2C3D4E5F60718ULL;
    rx_session_factory_args_t fac_args   = {
          .owner                 = &p2p_port,
          .sessions_by_animation = &rx.list_session_by_animation,
          .remote_uid            = remote_uid,
          .now                   = now,
    };
    rx_session_t* const ses = (rx_session_t*)cavl2_find_or_insert(&p2p_port.index_session_by_remote_uid,
                                                                  &remote_uid,
                                                                  &cavl_compare_rx_session_by_remote_uid,
                                                                  &fac_args,
                                                                  &cavl_factory_rx_session_by_remote_uid);
    // Verify construction outcome.
    TEST_ASSERT_NOT_NULL(ses);
    TEST_ASSERT_EQUAL_PTR(rx.list_session_by_animation.head, &ses->list_by_animation);
    TEST_ASSERT_EQUAL_PTR(p2p_port.index_session_by_remote_uid, &ses->index_remote_uid);
    TEST_ASSERT_EQUAL(1, alloc_session.allocated_fragments);

    // Feed a valid single-frame transfer and ensure immediate ejection (no reordering delay).
    meta_t meta = { .priority              = udpard_prio_high,
                    .flag_ack              = true,
                    .transfer_payload_size = 5,
                    .transfer_id           = 100,
                    .sender_uid            = remote_uid,
                    .topic_hash            = local_uid }; // P2P uses UID as the topic hash
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                      make_frame_ptr(meta, mem_payload, "hello", 0, 5),
                      del_payload,
                      0);

    // Transfer is ejected immediately in UNORDERED mode.
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL_PTR(&rx, cb_result.rx);
    TEST_ASSERT_EQUAL_PTR(&p2p_port, cb_result.port);
    TEST_ASSERT_EQUAL(1000, cb_result.message.history[0].timestamp);
    TEST_ASSERT_EQUAL(udpard_prio_high, cb_result.message.history[0].priority);
    TEST_ASSERT_EQUAL(100, cb_result.message.history[0].transfer_id);
    TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[0], 5, "hello", 5));

    // ACK mandate should be generated.
    TEST_ASSERT_EQUAL(1, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(100, cb_result.ack_mandate.am.transfer_id);
    TEST_ASSERT_EQUAL_size_t(5, cb_result.ack_mandate.am.payload_head.size);
    TEST_ASSERT_EQUAL_MEMORY("hello", cb_result.ack_mandate.am.payload_head.data, 5);

    // Free the transfer payload.
    udpard_fragment_free_all(cb_result.message.history[0].payload, mem_frag);
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);

    // Feed out-of-order transfers: 103, then 102. Both should be ejected immediately in UNORDERED mode.
    meta.transfer_id           = 103;
    meta.transfer_payload_size = 6;
    meta.priority              = udpard_prio_low;
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                      make_frame_ptr(meta, mem_payload, "tid103", 0, 6),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(2, cb_result.message.count);
    TEST_ASSERT_EQUAL(103, cb_result.message.history[0].transfer_id);
    TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[0], 6, "tid103", 6));
    udpard_fragment_free_all(cb_result.message.history[0].payload, mem_frag);

    meta.transfer_id = 102;
    meta.priority    = udpard_prio_nominal;
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                      make_frame_ptr(meta, mem_payload, "tid102", 0, 6),
                      del_payload,
                      0);
    // In UNORDERED mode, 102 is accepted even though it's "late" (arrives after 103).
    TEST_ASSERT_EQUAL(3, cb_result.message.count);
    TEST_ASSERT_EQUAL(102, cb_result.message.history[0].transfer_id);
    TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[0], 6, "tid102", 6));
    udpard_fragment_free_all(cb_result.message.history[0].payload, mem_frag);

    // Verify that duplicates are still rejected.
    meta.transfer_id = 103; // repeat of a received transfer
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                      make_frame_ptr(meta, mem_payload, "dup103", 0, 6),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(3, cb_result.message.count);           // no new message
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments); // payload was freed

    // Repeat duplicate should still trigger ACK if requested on first frame.
    TEST_ASSERT_EQUAL(4, cb_result.ack_mandate.count); // ACK generated for duplicate
    TEST_ASSERT_EQUAL(103, cb_result.ack_mandate.am.transfer_id);

    // Test multi-frame transfer in UNORDERED mode.
    meta.transfer_id           = 200;
    meta.transfer_payload_size = 10;
    meta.priority              = udpard_prio_fast;
    meta.flag_ack              = true;
    now += 1000;
    const udpard_us_t ts_200 = now;
    // Send second frame first.
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000002, .port = 0x5678 },
                      make_frame_ptr(meta, mem_payload, "0123456789", 5, 5),
                      del_payload,
                      1);
    TEST_ASSERT_EQUAL(3, cb_result.message.count); // not complete yet
    TEST_ASSERT_EQUAL(1, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_payload.allocated_fragments);

    // Send first frame to complete the transfer.
    now += 500;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                      make_frame_ptr(meta, mem_payload, "0123456789", 0, 5),
                      del_payload,
                      0);
    // Transfer is completed and ejected immediately.
    TEST_ASSERT_EQUAL(4, cb_result.message.count);
    TEST_ASSERT_EQUAL(ts_200, cb_result.message.history[0].timestamp); // earliest frame timestamp
    TEST_ASSERT_EQUAL(udpard_prio_fast, cb_result.message.history[0].priority);
    TEST_ASSERT_EQUAL(200, cb_result.message.history[0].transfer_id);
    TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[0], 10, "0123456789", 10));
    // Return path discovered from both interfaces.
    TEST_ASSERT_EQUAL(0x0A000001, cb_result.message.history[0].remote.endpoints[0].ip);
    TEST_ASSERT_EQUAL(0x0A000002, cb_result.message.history[0].remote.endpoints[1].ip);
    TEST_ASSERT_EQUAL(0x1234, cb_result.message.history[0].remote.endpoints[0].port);
    TEST_ASSERT_EQUAL(0x5678, cb_result.message.history[0].remote.endpoints[1].port);
    udpard_fragment_free_all(cb_result.message.history[0].payload, mem_frag);

    // ACK mandate generated upon completion.
    TEST_ASSERT_EQUAL(5, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(200, cb_result.ack_mandate.am.transfer_id);

    // Verify that polling doesn't affect UNORDERED mode (no reordering window processing).
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);
    udpard_rx_poll(&rx, now + 1000000);            // advance time significantly
    TEST_ASSERT_EQUAL(4, cb_result.message.count); // no change

    // Test that transfer-ID window works correctly in UNORDERED mode.
    // Transfers far outside the window (very old) should still be rejected as duplicates if within the window,
    // but truly old ones outside the window are treated as new (since they wrapped around).
    // The head is now at 200 (most recently ejected). Sending 200 again should be rejected as duplicate.
    meta.transfer_id           = 200;
    meta.transfer_payload_size = 5;
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                      make_frame_ptr(meta, mem_payload, "dup00", 0, 5),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(4, cb_result.message.count);           // duplicate rejected, count unchanged
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments); // payload was freed

    // Populate all slots with stale in-progress transfers, then verify they are reclaimed on timeout.
    meta.transfer_payload_size = 4;
    meta.priority              = udpard_prio_nominal;
    meta.flag_ack              = false;
    for (size_t i = 0; i < RX_SLOT_COUNT; i++) {
        meta.transfer_id = 300 + i;
        now += 1;
        rx_session_update(ses,
                          &rx,
                          now,
                          (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                          make_frame_ptr(meta, mem_payload, "OLD!", 0, 2),
                          del_payload,
                          0);
    }
    TEST_ASSERT_EQUAL(RX_SLOT_COUNT, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(RX_SLOT_COUNT, alloc_payload.allocated_fragments);
    now += SESSION_LIFETIME + 10;
    meta.transfer_id = 400;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                      make_frame_ptr(meta, mem_payload, "NEW!", 0, 2),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(4, cb_result.message.count);
    TEST_ASSERT_EQUAL(1, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(1, alloc_payload.allocated_fragments);

    // Verify session cleanup on timeout.
    now += SESSION_LIFETIME;
    udpard_rx_poll(&rx, now);
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);
    udpard_rx_port_free(&rx, &p2p_port);
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_session);
    instrumented_allocator_reset(&alloc_payload);
}

/// Ensure the reassembler can detect repeated transfers even after the window has moved past them.
static void test_rx_session_unordered_reject_old(void)
{
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    const udpard_mem_resource_t mem_frag      = instrumented_allocator_make_resource(&alloc_frag);
    instrumented_allocator_t    alloc_session = { 0 };
    instrumented_allocator_new(&alloc_session);
    const udpard_mem_resource_t mem_session   = instrumented_allocator_make_resource(&alloc_session);
    instrumented_allocator_t    alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_resource_t     mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_mem_deleter_t      del_payload = instrumented_allocator_make_deleter(&alloc_payload);
    const udpard_rx_mem_resources_t rx_mem      = { .fragment = mem_frag, .session = mem_session };
    udpard_rx_t                     rx;
    callback_result_t               cb_result = { 0 };
    udpard_rx_new(&rx);
    rx.user                    = &cb_result;
    const uint64_t   local_uid = 0xF00DCAFEF00DCAFEULL;
    udpard_rx_port_t port;
    TEST_ASSERT(
      udpard_rx_port_new(&port, local_uid, SIZE_MAX, UDPARD_RX_REORDERING_WINDOW_UNORDERED, rx_mem, &callbacks));
    udpard_us_t               now        = 0;
    const uint64_t            remote_uid = 0xFACEB00CFACEB00CULL;
    rx_session_factory_args_t fac_args   = {
          .owner                 = &port,
          .sessions_by_animation = &rx.list_session_by_animation,
          .remote_uid            = remote_uid,
          .now                   = now,
    };
    rx_session_t* const ses = (rx_session_t*)cavl2_find_or_insert(&port.index_session_by_remote_uid,
                                                                  &remote_uid,
                                                                  &cavl_compare_rx_session_by_remote_uid,
                                                                  &fac_args,
                                                                  &cavl_factory_rx_session_by_remote_uid);
    TEST_ASSERT_NOT_NULL(ses);

    // Send transfer #10. It should be accepted.
    meta_t meta = { .priority              = udpard_prio_fast,
                    .flag_ack              = false,
                    .transfer_payload_size = 3,
                    .transfer_id           = 10,
                    .sender_uid            = remote_uid,
                    .topic_hash            = local_uid };
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A00000A, .port = 0x0A00 },
                      make_frame_ptr(meta, mem_payload, "old", 0, 3),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(10, cb_result.message.history[0].transfer_id);

    // Send transfer with a very different TID outside the window (a "jump"). It should be accepted also.
    const uint64_t jump_tid    = 10 + 2000 + 5U;
    meta.transfer_id           = jump_tid;
    meta.transfer_payload_size = 4;
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A00000B, .port = 0x0B00 },
                      make_frame_ptr(meta, mem_payload, "jump", 0, 4),
                      del_payload,
                      1);
    TEST_ASSERT_EQUAL(2, cb_result.message.count);
    TEST_ASSERT_EQUAL(jump_tid, cb_result.message.history[0].transfer_id);

    // Send transfer #10 again. It should be rejected as a duplicate.
    meta.transfer_id           = 10;
    meta.transfer_payload_size = 3;
    meta.flag_ack              = true;
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A00000A, .port = 0x0A00 },
                      make_frame_ptr(meta, mem_payload, "dup", 0, 3),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(2, cb_result.message.count); // no new message
    TEST_ASSERT_EQUAL(1, cb_result.ack_mandate.count);
    TEST_ASSERT_EQUAL(10, cb_result.ack_mandate.am.transfer_id);
    TEST_ASSERT_EQUAL_size_t(3, cb_result.ack_mandate.am.payload_head.size);
    TEST_ASSERT_EQUAL_MEMORY("dup", cb_result.ack_mandate.am.payload_head.data, 3);
    udpard_fragment_free_all(cb_result.message.history[0].payload, mem_frag);
    udpard_fragment_free_all(cb_result.message.history[1].payload, mem_frag);
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
    udpard_rx_port_free(&rx, &port);
    TEST_ASSERT_EQUAL_size_t(0, alloc_session.allocated_fragments);
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_session);
    instrumented_allocator_reset(&alloc_payload);
}

/// UNORDERED mode should drop duplicates while accepting earlier arrivals regardless of ordering.
static void test_rx_session_unordered_duplicates(void)
{
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    const udpard_mem_resource_t mem_frag      = instrumented_allocator_make_resource(&alloc_frag);
    instrumented_allocator_t    alloc_session = { 0 };
    instrumented_allocator_new(&alloc_session);
    const udpard_mem_resource_t mem_session   = instrumented_allocator_make_resource(&alloc_session);
    instrumented_allocator_t    alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_resource_t     mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_mem_deleter_t      del_payload = instrumented_allocator_make_deleter(&alloc_payload);
    const udpard_rx_mem_resources_t rx_mem      = { .fragment = mem_frag, .session = mem_session };
    udpard_rx_t                     rx;
    callback_result_t               cb_result = { 0 };
    udpard_rx_new(&rx);
    rx.user = &cb_result;
    udpard_rx_port_t port;
    const uint64_t   topic_hash = 0x1111222233334444ULL;
    TEST_ASSERT(
      udpard_rx_port_new(&port, topic_hash, SIZE_MAX, UDPARD_RX_REORDERING_WINDOW_UNORDERED, rx_mem, &callbacks));
    const uint64_t            remote_uid = 0xAABBCCDDEEFF0011ULL;
    rx_session_factory_args_t fac_args   = {
          .owner                 = &port,
          .sessions_by_animation = &rx.list_session_by_animation,
          .remote_uid            = remote_uid,
          .now                   = 0,
    };
    rx_session_t* const ses = (rx_session_t*)cavl2_find_or_insert(&port.index_session_by_remote_uid,
                                                                  &remote_uid,
                                                                  &cavl_compare_rx_session_by_remote_uid,
                                                                  &fac_args,
                                                                  &cavl_factory_rx_session_by_remote_uid);
    TEST_ASSERT_NOT_NULL(ses);
    // Feed a mix of fresh transfers followed by duplicates; only the first four should be accepted.
    meta_t         meta   = { .priority              = udpard_prio_fast,
                              .flag_ack              = false,
                              .transfer_payload_size = 4,
                              .transfer_id           = 1100,
                              .sender_uid            = remote_uid,
                              .topic_hash            = topic_hash };
    udpard_us_t    now    = 0;
    const uint64_t tids[] = { 1100, 1000, 4000, 4100, 1000, 1100 };
    for (size_t i = 0; i < sizeof(tids) / sizeof(tids[0]); i++) {
        meta.transfer_id = tids[i];
        char payload[4]  = { (char)('A' + (int)(i % 26)), (char)('a' + (int)(i % 26)), 'X', '\0' };
        now += 100;
        rx_session_update(ses,
                          &rx,
                          now,
                          (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                          make_frame_ptr(meta, mem_payload, payload, 0, 4),
                          del_payload,
                          0);
    }
    TEST_ASSERT_EQUAL(4, cb_result.message.count);
    TEST_ASSERT_EQUAL(1100, cb_result.message.history[3].transfer_id);
    TEST_ASSERT_EQUAL(1000, cb_result.message.history[2].transfer_id);
    TEST_ASSERT_EQUAL(4000, cb_result.message.history[1].transfer_id);
    TEST_ASSERT_EQUAL(4100, cb_result.message.history[0].transfer_id);
    for (size_t i = 0; i < cb_result.message.count; i++) {
        udpard_fragment_free_all(cb_result.message.history[i].payload, mem_frag);
    }
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
    udpard_rx_port_free(&rx, &port);
    TEST_ASSERT_EQUAL_size_t(0, alloc_session.allocated_fragments);
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_session);
    instrumented_allocator_reset(&alloc_payload);
}

/// Send transfers 1, 3, 10000, 2 in the ORDERED mode; ensure 2 is rejected because it's late after 3.
static void test_rx_session_ordered_reject_stale_after_jump(void)
{
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    const udpard_mem_resource_t mem_frag      = instrumented_allocator_make_resource(&alloc_frag);
    instrumented_allocator_t    alloc_session = { 0 };
    instrumented_allocator_new(&alloc_session);
    const udpard_mem_resource_t mem_session   = instrumented_allocator_make_resource(&alloc_session);
    instrumented_allocator_t    alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_resource_t     mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_mem_deleter_t      del_payload = instrumented_allocator_make_deleter(&alloc_payload);
    const udpard_rx_mem_resources_t rx_mem      = { .fragment = mem_frag, .session = mem_session };
    udpard_rx_t                     rx;
    udpard_rx_new(&rx);
    callback_result_t cb_result = { 0 };
    rx.user                     = &cb_result;
    udpard_rx_port_t port;
    const uint64_t   topic_hash = 0x123456789ABCDEF0ULL;
    TEST_ASSERT(udpard_rx_port_new(&port, topic_hash, 1000, 1000, rx_mem, &callbacks));
    const uint64_t            remote_uid = 0xDEADBEEFDEADBEEFULL;
    rx_session_factory_args_t fac_args   = {
          .owner                 = &port,
          .sessions_by_animation = &rx.list_session_by_animation,
          .remote_uid            = remote_uid,
          .now                   = 0,
    };
    rx_session_t* const ses = (rx_session_t*)cavl2_find_or_insert(&port.index_session_by_remote_uid,
                                                                  &remote_uid,
                                                                  &cavl_compare_rx_session_by_remote_uid,
                                                                  &fac_args,
                                                                  &cavl_factory_rx_session_by_remote_uid);
    TEST_ASSERT_NOT_NULL(ses);

    // Send transfer #1.
    udpard_us_t now  = 0;
    meta_t      meta = { .priority              = udpard_prio_nominal,
                         .flag_ack              = true,
                         .transfer_payload_size = 1,
                         .transfer_id           = 1,
                         .sender_uid            = remote_uid,
                         .topic_hash            = topic_hash };
    now += 100;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1111 },
                      make_frame_ptr(meta, mem_payload, "a", 0, 1),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(1, cb_result.ack_mandate.count);

    // Send transfer #3. Transfer #2 is missing, so this one is interned.
    meta.transfer_id = 3;
    now += 100;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1111 },
                      make_frame_ptr(meta, mem_payload, "b", 0, 1),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(2, cb_result.ack_mandate.count); // all acked

    // Send transfer #10000. The head is still at #1, so #10000 is interned as well.
    meta.transfer_id           = 10000;
    meta.transfer_payload_size = 1;
    meta.flag_ack              = true;
    now += 10;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1111 },
                      make_frame_ptr(meta, mem_payload, "c", 0, 1),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(1, cb_result.message.count);     // 3 is still interned, 10000 interned too (but acked).
    TEST_ASSERT_EQUAL(3, cb_result.ack_mandate.count); // all acked

    // Some time has passed and the reordering window is now closed. All transfers ejected.
    now += port.reordering_window + 100;
    udpard_rx_poll(&rx, now);
    TEST_ASSERT_EQUAL(3, cb_result.message.count); // 1, 3, 10000 have been ejected.
    TEST_ASSERT_EQUAL(3, cb_result.ack_mandate.count);

    // Send transfer #2. It is stale and must be rejected.
    meta.transfer_id = 2;
    meta.flag_ack    = true;
    now += 10;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1111 },
                      make_frame_ptr(meta, mem_payload, "d", 0, 1),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(3, cb_result.message.count);     // transfer 2 not ejected!
    TEST_ASSERT_EQUAL(3, cb_result.ack_mandate.count); // transfer 2 must have been rejected!

    // Make sure it's not ejected later.
    now += port.reordering_window + 100;
    udpard_rx_poll(&rx, now);
    TEST_ASSERT_EQUAL(3, cb_result.message.count);
    TEST_ASSERT_EQUAL(3, cb_result.ack_mandate.count);

    // Clean up.
    for (size_t i = 0; i < cb_result.message.count; i++) {
        udpard_fragment_free_all(cb_result.message.history[i].payload, mem_frag);
    }
    udpard_rx_port_free(&rx, &port);
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_session.allocated_fragments);
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_session);
    instrumented_allocator_reset(&alloc_payload);
}

/// ORDERED mode with zero reordering delay should accept only strictly increasing IDs.
static void test_rx_session_ordered_zero_reordering_window(void)
{
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    const udpard_mem_resource_t mem_frag      = instrumented_allocator_make_resource(&alloc_frag);
    instrumented_allocator_t    alloc_session = { 0 };
    instrumented_allocator_new(&alloc_session);
    const udpard_mem_resource_t mem_session   = instrumented_allocator_make_resource(&alloc_session);
    instrumented_allocator_t    alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_resource_t     mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_mem_deleter_t      del_payload = instrumented_allocator_make_deleter(&alloc_payload);
    const udpard_rx_mem_resources_t rx_mem      = { .fragment = mem_frag, .session = mem_session };
    udpard_rx_t                     rx;
    callback_result_t               cb_result = { 0 };
    udpard_rx_new(&rx);
    rx.user = &cb_result;
    udpard_rx_port_t port;
    const uint64_t   topic_hash = 0x9999888877776666ULL;
    TEST_ASSERT(udpard_rx_port_new(&port, topic_hash, SIZE_MAX, 0, rx_mem, &callbacks));
    const uint64_t            remote_uid = 0x0A0B0C0D0E0F1011ULL;
    rx_session_factory_args_t fac_args   = {
          .owner                 = &port,
          .sessions_by_animation = &rx.list_session_by_animation,
          .remote_uid            = remote_uid,
          .now                   = 0,
    };
    rx_session_t* const ses = (rx_session_t*)cavl2_find_or_insert(&port.index_session_by_remote_uid,
                                                                  &remote_uid,
                                                                  &cavl_compare_rx_session_by_remote_uid,
                                                                  &fac_args,
                                                                  &cavl_factory_rx_session_by_remote_uid);
    TEST_ASSERT_NOT_NULL(ses);
    // Zero reordering window: out-of-order IDs are rejected, so only 120, 140, 1120 are accepted.
    meta_t         meta   = { .priority              = udpard_prio_nominal,
                              .flag_ack              = false,
                              .transfer_payload_size = 3,
                              .transfer_id           = 120,
                              .sender_uid            = remote_uid,
                              .topic_hash            = topic_hash };
    udpard_us_t    now    = 0;
    const uint64_t tids[] = { 120, 110, 140, 1120, 130 };
    for (size_t i = 0; i < sizeof(tids) / sizeof(tids[0]); i++) {
        meta.transfer_id = tids[i];
        char payload[3]  = { (char)('k' + (int)i), (char)('K' + (int)i), '\0' };
        now += 50;
        rx_session_update(ses,
                          &rx,
                          now,
                          (udpard_udpip_ep_t){ .ip = 0x0A000002, .port = 0x2222 },
                          make_frame_ptr(meta, mem_payload, payload, 0, 3),
                          del_payload,
                          0);
    }
    TEST_ASSERT_EQUAL(3, cb_result.message.count);
    TEST_ASSERT_EQUAL(1120, cb_result.message.history[0].transfer_id);
    TEST_ASSERT_EQUAL(140, cb_result.message.history[1].transfer_id);
    TEST_ASSERT_EQUAL(120, cb_result.message.history[2].transfer_id);
    for (size_t i = 0; i < cb_result.message.count; i++) {
        udpard_fragment_free_all(cb_result.message.history[i].payload, mem_frag);
    }
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
    udpard_rx_port_free(&rx, &port);
    TEST_ASSERT_EQUAL_size_t(0, alloc_session.allocated_fragments);
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_session);
    instrumented_allocator_reset(&alloc_payload);
}

// ---------------------------------------------  RX PORT  ---------------------------------------------

/// Exercises udpard_rx_port_push() across ORDERED and STATELESS ports, covering single- and multi-frame transfers.
static void test_rx_port(void)
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

    const udpard_rx_mem_resources_t rx_mem = { .fragment = mem_frag, .session = mem_session };

    // Initialize the shared RX instance.
    udpard_rx_t rx;
    udpard_rx_new(&rx);
    callback_result_t cb_result = { 0 };
    rx.user                     = &cb_result;

    // Initialize two ports: one ORDERED, one STATELESS.
    udpard_rx_port_t port_ordered;
    const uint64_t   topic_hash_ordered = 0x1234567890ABCDEFULL;
    TEST_ASSERT(udpard_rx_port_new(&port_ordered, topic_hash_ordered, 1000, 10 * KILO, rx_mem, &callbacks));

    udpard_rx_port_t port_stateless;
    const uint64_t   topic_hash_stateless = 0xFEDCBA0987654321ULL;
    TEST_ASSERT(udpard_rx_port_new(
      &port_stateless, topic_hash_stateless, 500, UDPARD_RX_REORDERING_WINDOW_STATELESS, rx_mem, &callbacks));

    udpard_us_t now = 0;

    // Test 1: Send a valid single-frame transfer to the ORDERED port.
    {
        const uint64_t remote_uid  = 0xAABBCCDDEEFF0011ULL;
        const uint64_t transfer_id = 100;
        const char*    payload_str = "Hello World";
        const size_t   payload_len = strlen(payload_str) + 1; // include null terminator
        meta_t         meta        = { .priority              = udpard_prio_nominal,
                                       .flag_ack              = true,
                                       .transfer_payload_size = (uint32_t)payload_len,
                                       .transfer_id           = transfer_id,
                                       .sender_uid            = remote_uid,
                                       .topic_hash            = topic_hash_ordered };
        rx_frame_t*    frame       = make_frame_ptr(meta, mem_payload, payload_str, 0, payload_len);

        // Serialize the frame into a datagram.
        byte_t dgram[HEADER_SIZE_BYTES + payload_len];
        header_serialize(dgram, meta, 0, 0, frame->base.crc);
        memcpy(dgram + HEADER_SIZE_BYTES, payload_str, payload_len);
        mem_free_payload(del_payload, frame->base.origin);

        // Allocate payload for the push.
        void* push_payload = mem_payload.alloc(mem_payload.user, sizeof(dgram));
        memcpy(push_payload, dgram, sizeof(dgram));

        now += 1000;
        TEST_ASSERT(udpard_rx_port_push(&rx,
                                        &port_ordered,
                                        now,
                                        (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                                        (udpard_bytes_mut_t){ .data = push_payload, .size = sizeof(dgram) },
                                        del_payload,
                                        0));

        // Verify the callback was invoked.
        TEST_ASSERT_EQUAL(1, cb_result.message.count);
        TEST_ASSERT_EQUAL(transfer_id, cb_result.message.history[0].transfer_id);
        TEST_ASSERT_EQUAL(remote_uid, cb_result.message.history[0].remote.uid);
        TEST_ASSERT_EQUAL(payload_len, cb_result.message.history[0].payload_size_stored);
        TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[0], payload_len, payload_str, payload_len));

        // Verify ACK was mandated.
        TEST_ASSERT_EQUAL(1, cb_result.ack_mandate.count);
        TEST_ASSERT_EQUAL(transfer_id, cb_result.ack_mandate.am.transfer_id);

        // Clean up.
        udpard_fragment_free_all(cb_result.message.history[0].payload, mem_frag);
        cb_result.message.count     = 0;
        cb_result.ack_mandate.count = 0;
    }

    // Test 2: Send a valid single-frame transfer to the STATELESS port.
    {
        const uint64_t remote_uid  = 0x1122334455667788ULL;
        const uint64_t transfer_id = 200;
        const char*    payload_str = "Stateless";
        const size_t   payload_len = strlen(payload_str) + 1;
        meta_t         meta        = { .priority              = udpard_prio_high,
                                       .flag_ack              = false,
                                       .transfer_payload_size = (uint32_t)payload_len,
                                       .transfer_id           = transfer_id,
                                       .sender_uid            = remote_uid,
                                       .topic_hash            = topic_hash_stateless };
        rx_frame_t*    frame       = make_frame_ptr(meta, mem_payload, payload_str, 0, payload_len);

        byte_t dgram[HEADER_SIZE_BYTES + payload_len];
        header_serialize(dgram, meta, 0, 0, frame->base.crc);
        memcpy(dgram + HEADER_SIZE_BYTES, payload_str, payload_len);
        mem_free_payload(del_payload, frame->base.origin);

        void* push_payload = mem_payload.alloc(mem_payload.user, sizeof(dgram));
        memcpy(push_payload, dgram, sizeof(dgram));

        now += 1000;
        TEST_ASSERT(udpard_rx_port_push(&rx,
                                        &port_stateless,
                                        now,
                                        (udpard_udpip_ep_t){ .ip = 0x0B000001, .port = 0x5678 },
                                        (udpard_bytes_mut_t){ .data = push_payload, .size = sizeof(dgram) },
                                        del_payload,
                                        1));

        TEST_ASSERT_EQUAL(1, cb_result.message.count);
        TEST_ASSERT_EQUAL(transfer_id, cb_result.message.history[0].transfer_id);
        TEST_ASSERT_EQUAL(remote_uid, cb_result.message.history[0].remote.uid);
        TEST_ASSERT_EQUAL(payload_len, cb_result.message.history[0].payload_size_stored);
        TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[0], payload_len, payload_str, payload_len));

        // No ACK for stateless mode without flag_ack.
        TEST_ASSERT_EQUAL(0, cb_result.ack_mandate.count);

        udpard_fragment_free_all(cb_result.message.history[0].payload, mem_frag);
        cb_result.message.count = 0;
    }

    // Test 3: Send a multi-frame transfer to the ORDERED port.
    {
        const uint64_t remote_uid   = 0xAABBCCDDEEFF0011ULL;
        const uint64_t transfer_id  = 101;
        const char*    full_payload = "0123456789ABCDEFGHIJ";
        const size_t   payload_len  = 20;
        meta_t         meta         = { .priority              = udpard_prio_nominal,
                                        .flag_ack              = true,
                                        .transfer_payload_size = (uint32_t)payload_len,
                                        .transfer_id           = transfer_id,
                                        .sender_uid            = remote_uid,
                                        .topic_hash            = topic_hash_ordered };

        // Frame 1: offset 0, 10 bytes.
        {
            rx_frame_t* frame = make_frame_ptr(meta, mem_payload, full_payload, 0, 10);
            byte_t      dgram[HEADER_SIZE_BYTES + 10];
            header_serialize(dgram, meta, 0, 0, frame->base.crc);
            memcpy(dgram + HEADER_SIZE_BYTES, full_payload, 10);
            mem_free_payload(del_payload, frame->base.origin);

            void* push_payload = mem_payload.alloc(mem_payload.user, sizeof(dgram));
            memcpy(push_payload, dgram, sizeof(dgram));

            now += 1000;
            TEST_ASSERT(udpard_rx_port_push(&rx,
                                            &port_ordered,
                                            now,
                                            (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                                            (udpard_bytes_mut_t){ .data = push_payload, .size = sizeof(dgram) },
                                            del_payload,
                                            0));
        }

        // Frame 2: offset 10, 10 bytes.
        {
            rx_frame_t* frame = make_frame_ptr(meta, mem_payload, full_payload, 10, 10);
            byte_t      dgram[HEADER_SIZE_BYTES + 10];
            header_serialize(dgram, meta, 1, 10, frame->base.crc);
            memcpy(dgram + HEADER_SIZE_BYTES, full_payload + 10, 10);
            mem_free_payload(del_payload, frame->base.origin);

            void* push_payload = mem_payload.alloc(mem_payload.user, sizeof(dgram));
            memcpy(push_payload, dgram, sizeof(dgram));

            now += 1000;
            TEST_ASSERT(udpard_rx_port_push(&rx,
                                            &port_ordered,
                                            now,
                                            (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                                            (udpard_bytes_mut_t){ .data = push_payload, .size = sizeof(dgram) },
                                            del_payload,
                                            0));
        }

        // Verify the transfer was received.
        TEST_ASSERT_EQUAL(1, cb_result.message.count);
        TEST_ASSERT_EQUAL(transfer_id, cb_result.message.history[0].transfer_id);
        TEST_ASSERT_EQUAL(payload_len, cb_result.message.history[0].payload_size_stored);
        TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[0], payload_len, full_payload, payload_len));

        TEST_ASSERT_EQUAL(1, cb_result.ack_mandate.count);

        udpard_fragment_free_all(cb_result.message.history[0].payload, mem_frag);
        cb_result.message.count     = 0;
        cb_result.ack_mandate.count = 0;
    }

    // Test 4: Send a frame with wrong topic hash (collision).
    {
        const uint64_t remote_uid  = 0x9988776655443322ULL;
        const uint64_t transfer_id = 300;
        const char*    payload_str = "Collision";
        const size_t   payload_len = strlen(payload_str) + 1;
        const uint64_t wrong_hash  = topic_hash_ordered + 1; // Different hash
        meta_t         meta        = { .priority              = udpard_prio_nominal,
                                       .flag_ack              = false,
                                       .transfer_payload_size = (uint32_t)payload_len,
                                       .transfer_id           = transfer_id,
                                       .sender_uid            = remote_uid,
                                       .topic_hash            = wrong_hash };
        rx_frame_t*    frame       = make_frame_ptr(meta, mem_payload, payload_str, 0, payload_len);

        byte_t dgram[HEADER_SIZE_BYTES + payload_len];
        header_serialize(dgram, meta, 0, 0, frame->base.crc);
        memcpy(dgram + HEADER_SIZE_BYTES, payload_str, payload_len);
        mem_free_payload(del_payload, frame->base.origin);

        void* push_payload = mem_payload.alloc(mem_payload.user, sizeof(dgram));
        memcpy(push_payload, dgram, sizeof(dgram));

        now += 1000;
        TEST_ASSERT(udpard_rx_port_push(&rx,
                                        &port_ordered,
                                        now,
                                        (udpard_udpip_ep_t){ .ip = 0x0C000001, .port = 0x9999 },
                                        (udpard_bytes_mut_t){ .data = push_payload, .size = sizeof(dgram) },
                                        del_payload,
                                        2));

        // Verify collision callback was invoked.
        TEST_ASSERT_EQUAL(1, cb_result.collision.count);
        TEST_ASSERT_EQUAL(remote_uid, cb_result.collision.remote.uid);

        // No message should have been received.
        TEST_ASSERT_EQUAL(0, cb_result.message.count);

        cb_result.collision.count = 0;
    }

    // Test 5: Send a malformed frame (bad CRC in header).
    {
        const uint64_t errors_before = rx.errors_frame_malformed;
        byte_t         bad_dgram[HEADER_SIZE_BYTES + 10];
        memset(bad_dgram, 0xAA, sizeof(bad_dgram)); // Garbage data

        void* push_payload = mem_payload.alloc(mem_payload.user, sizeof(bad_dgram));
        memcpy(push_payload, bad_dgram, sizeof(bad_dgram));

        now += 1000;
        TEST_ASSERT(udpard_rx_port_push(&rx,
                                        &port_ordered,
                                        now,
                                        (udpard_udpip_ep_t){ .ip = 0x0D000001, .port = 0xAAAA },
                                        (udpard_bytes_mut_t){ .data = push_payload, .size = sizeof(bad_dgram) },
                                        del_payload,
                                        0));

        // Verify error counter was incremented.
        TEST_ASSERT_EQUAL(errors_before + 1, rx.errors_frame_malformed);

        // No callbacks should have been invoked.
        TEST_ASSERT_EQUAL(0, cb_result.message.count);
        TEST_ASSERT_EQUAL(0, cb_result.collision.count);
        TEST_ASSERT_EQUAL(0, cb_result.ack_mandate.count);
    }

    // Test 6: Send a multi-frame transfer to STATELESS port (should be rejected).
    {
        const uint64_t errors_before = rx.errors_transfer_malformed;
        const uint64_t remote_uid    = 0x1122334455667788ULL;
        const uint64_t transfer_id   = 201;
        const char*    payload_str   = "MultiFrameStateless";
        const size_t   payload_len   = strlen(payload_str) + 1;
        meta_t         meta          = { .priority              = udpard_prio_high,
                                         .flag_ack              = false,
                                         .transfer_payload_size = (uint32_t)payload_len,
                                         .transfer_id           = transfer_id,
                                         .sender_uid            = remote_uid,
                                         .topic_hash            = topic_hash_stateless };

        // Send only the first frame (offset 0, partial payload).
        rx_frame_t* frame = make_frame_ptr(meta, mem_payload, payload_str, 0, 10);
        byte_t      dgram[HEADER_SIZE_BYTES + 10];
        header_serialize(dgram, meta, 0, 0, frame->base.crc);
        memcpy(dgram + HEADER_SIZE_BYTES, payload_str, 10);
        mem_free_payload(del_payload, frame->base.origin);

        void* push_payload = mem_payload.alloc(mem_payload.user, sizeof(dgram));
        memcpy(push_payload, dgram, sizeof(dgram));

        now += 1000;
        TEST_ASSERT(udpard_rx_port_push(&rx,
                                        &port_stateless,
                                        now,
                                        (udpard_udpip_ep_t){ .ip = 0x0B000001, .port = 0x5678 },
                                        (udpard_bytes_mut_t){ .data = push_payload, .size = sizeof(dgram) },
                                        del_payload,
                                        1));

        // STATELESS mode rejects multi-frame transfers.
        TEST_ASSERT_EQUAL(errors_before + 1, rx.errors_transfer_malformed);
        TEST_ASSERT_EQUAL(0, cb_result.message.count);
    }

    // Test 7: Verify invalid API calls return false.
    {
        void* dummy_payload = mem_payload.alloc(mem_payload.user, 100);
        memset(dummy_payload, 0, 100);
        // Null rx pointer.
        TEST_ASSERT_FALSE(udpard_rx_port_push(NULL,
                                              &port_ordered,
                                              now,
                                              (udpard_udpip_ep_t){ .ip = 0x01020304, .port = 1234 },
                                              (udpard_bytes_mut_t){ .data = dummy_payload, .size = 100 },
                                              del_payload,
                                              0));
        // Null port pointer.
        TEST_ASSERT_FALSE(udpard_rx_port_push(&rx,
                                              NULL,
                                              now,
                                              (udpard_udpip_ep_t){ .ip = 0x01020304, .port = 1234 },
                                              (udpard_bytes_mut_t){ .data = dummy_payload, .size = 100 },
                                              del_payload,
                                              0));
        // Invalid endpoint (ip = 0).
        TEST_ASSERT_FALSE(udpard_rx_port_push(&rx,
                                              &port_ordered,
                                              now,
                                              (udpard_udpip_ep_t){ .ip = 0, .port = 1234 },
                                              (udpard_bytes_mut_t){ .data = dummy_payload, .size = 100 },
                                              del_payload,
                                              0));
        // Invalid endpoint (port = 0).
        TEST_ASSERT_FALSE(udpard_rx_port_push(&rx,
                                              &port_ordered,
                                              now,
                                              (udpard_udpip_ep_t){ .ip = 0x01020304, .port = 0 },
                                              (udpard_bytes_mut_t){ .data = dummy_payload, .size = 100 },
                                              del_payload,
                                              0));
        // Null datagram payload.
        TEST_ASSERT_FALSE(udpard_rx_port_push(&rx,
                                              &port_ordered,
                                              now,
                                              (udpard_udpip_ep_t){ .ip = 0x01020304, .port = 1234 },
                                              (udpard_bytes_mut_t){ .data = NULL, .size = 100 },
                                              del_payload,
                                              0));
        // Invalid interface index.
        TEST_ASSERT_FALSE(udpard_rx_port_push(&rx,
                                              &port_ordered,
                                              now,
                                              (udpard_udpip_ep_t){ .ip = 0x01020304, .port = 1234 },
                                              (udpard_bytes_mut_t){ .data = dummy_payload, .size = 100 },
                                              del_payload,
                                              UDPARD_NETWORK_INTERFACE_COUNT_MAX));
        // Free the dummy payload since all calls failed.
        mem_free(mem_payload, 100, dummy_payload);
    }

    // Cleanup.
    udpard_rx_port_free(&rx, &port_ordered);
    udpard_rx_port_free(&rx, &port_stateless);

    // Verify no memory leaks.
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
}

/// Starts a few transfers on multiple ports, lets them expire, and ensures cleanup in udpard_rx_poll().
static void test_rx_port_timeouts(void)
{
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    const udpard_mem_resource_t mem_frag = instrumented_allocator_make_resource(&alloc_frag);

    instrumented_allocator_t alloc_session = { 0 };
    instrumented_allocator_new(&alloc_session);
    const udpard_mem_resource_t mem_session = instrumented_allocator_make_resource(&alloc_session);

    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_resource_t     mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_mem_deleter_t      del_payload = instrumented_allocator_make_deleter(&alloc_payload);
    const udpard_rx_mem_resources_t rx_mem      = { .fragment = mem_frag, .session = mem_session };

    udpard_rx_t       rx;
    callback_result_t cb_result = { 0 };
    udpard_rx_new(&rx);
    rx.user = &cb_result;

    udpard_rx_port_t port_a;
    udpard_rx_port_t port_b;
    const uint64_t   topic_hash_a = 0x1111111111111111ULL;
    const uint64_t   topic_hash_b = 0x2222222222222222ULL;
    TEST_ASSERT(udpard_rx_port_new(&port_a, topic_hash_a, 1000, 20000, rx_mem, &callbacks));
    TEST_ASSERT(udpard_rx_port_new(&port_b, topic_hash_b, 1000, 20000, rx_mem, &callbacks));

    udpard_us_t now = 1000;

    // Remote A: start transfer 10 (incomplete) and 11 (complete) so 11 arms the reordering timer.
    {
        meta_t      meta  = { .priority              = udpard_prio_nominal,
                              .flag_ack              = false,
                              .transfer_payload_size = 10,
                              .transfer_id           = 10,
                              .sender_uid            = 0xAAAAULL,
                              .topic_hash            = topic_hash_a };
        rx_frame_t* frame = make_frame_ptr(meta, mem_payload, "ABCDEFGHIJ", 0, 5);
        byte_t      dgram[HEADER_SIZE_BYTES + 5];
        header_serialize(dgram, meta, 0, 0, frame->base.crc);
        const byte_t payload_head[5] = { 'A', 'B', 'C', 'D', 'E' };
        memcpy(dgram + HEADER_SIZE_BYTES, payload_head, sizeof(payload_head));
        mem_free(mem_payload, frame->base.origin.size, frame->base.origin.data);
        void* push_payload = mem_payload.alloc(mem_payload.user, sizeof(dgram));
        memcpy(push_payload, dgram, sizeof(dgram));
        TEST_ASSERT(udpard_rx_port_push(&rx,
                                        &port_a,
                                        now,
                                        (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                                        (udpard_bytes_mut_t){ .data = push_payload, .size = sizeof(dgram) },
                                        del_payload,
                                        0));
        meta.transfer_payload_size = 4;
        meta.transfer_id           = 11;
        rx_frame_t* done_frame     = make_frame_ptr(meta, mem_payload, "DONE", 0, 4);
        byte_t      done_dgram[HEADER_SIZE_BYTES + 4];
        header_serialize(done_dgram, meta, 0, 0, done_frame->base.crc);
        const byte_t done_payload[4] = { 'D', 'O', 'N', 'E' };
        memcpy(done_dgram + HEADER_SIZE_BYTES, done_payload, sizeof(done_payload));
        mem_free(mem_payload, done_frame->base.origin.size, done_frame->base.origin.data);
        void* push_done = mem_payload.alloc(mem_payload.user, sizeof(done_dgram));
        memcpy(push_done, done_dgram, sizeof(done_dgram));
        now += 1000;
        TEST_ASSERT(udpard_rx_port_push(&rx,
                                        &port_a,
                                        now,
                                        (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                                        (udpard_bytes_mut_t){ .data = push_done, .size = sizeof(done_dgram) },
                                        del_payload,
                                        0));
    }

    // Remote B mirrors the same pattern to populate the reordering deadline tree with another entry.
    {
        meta_t      meta  = { .priority              = udpard_prio_nominal,
                              .flag_ack              = false,
                              .transfer_payload_size = 6,
                              .transfer_id           = 20,
                              .sender_uid            = 0xBBBBULL,
                              .topic_hash            = topic_hash_b };
        rx_frame_t* frame = make_frame_ptr(meta, mem_payload, "QRSTUV", 0, 3);
        byte_t      dgram[HEADER_SIZE_BYTES + 3];
        header_serialize(dgram, meta, 0, 0, frame->base.crc);
        const byte_t payload_head[3] = { 'Q', 'R', 'S' };
        memcpy(dgram + HEADER_SIZE_BYTES, payload_head, sizeof(payload_head));
        mem_free(mem_payload, frame->base.origin.size, frame->base.origin.data);
        void* push_payload = mem_payload.alloc(mem_payload.user, sizeof(dgram));
        memcpy(push_payload, dgram, sizeof(dgram));
        now += 1000;
        TEST_ASSERT(udpard_rx_port_push(&rx,
                                        &port_b,
                                        now,
                                        (udpard_udpip_ep_t){ .ip = 0x0B000001, .port = 0x5678 },
                                        (udpard_bytes_mut_t){ .data = push_payload, .size = sizeof(dgram) },
                                        del_payload,
                                        0));
        meta.transfer_payload_size = 5;
        meta.transfer_id           = 21;
        rx_frame_t* done_frame     = make_frame_ptr(meta, mem_payload, "READY", 0, 5);
        byte_t      done_dgram[HEADER_SIZE_BYTES + 5];
        header_serialize(done_dgram, meta, 0, 0, done_frame->base.crc);
        const byte_t done_payload[5] = { 'R', 'E', 'A', 'D', 'Y' };
        memcpy(done_dgram + HEADER_SIZE_BYTES, done_payload, sizeof(done_payload));
        mem_free(mem_payload, done_frame->base.origin.size, done_frame->base.origin.data);
        void* push_done = mem_payload.alloc(mem_payload.user, sizeof(done_dgram));
        memcpy(push_done, done_dgram, sizeof(done_dgram));
        now += 1000;
        TEST_ASSERT(udpard_rx_port_push(&rx,
                                        &port_b,
                                        now,
                                        (udpard_udpip_ep_t){ .ip = 0x0B000001, .port = 0x5678 },
                                        (udpard_bytes_mut_t){ .data = push_done, .size = sizeof(done_dgram) },
                                        del_payload,
                                        0));
    }

    TEST_ASSERT_EQUAL(0, cb_result.message.count);

    // Advance past the session lifetime so the busy slots will be reset on the next arrival.
    now += SESSION_LIFETIME + 5000;
    {
        meta_t      meta  = { .priority              = udpard_prio_nominal,
                              .flag_ack              = false,
                              .transfer_payload_size = 3,
                              .transfer_id           = 30,
                              .sender_uid            = 0xAAAAULL,
                              .topic_hash            = topic_hash_a };
        rx_frame_t* frame = make_frame_ptr(meta, mem_payload, "NEW", 0, 3);
        byte_t      dgram[HEADER_SIZE_BYTES + 3];
        header_serialize(dgram, meta, 0, 0, frame->base.crc);
        const byte_t payload_head[3] = { 'N', 'E', 'W' };
        memcpy(dgram + HEADER_SIZE_BYTES, payload_head, sizeof(payload_head));
        mem_free(mem_payload, frame->base.origin.size, frame->base.origin.data);
        void* push_payload = mem_payload.alloc(mem_payload.user, sizeof(dgram));
        memcpy(push_payload, dgram, sizeof(dgram));
        TEST_ASSERT(udpard_rx_port_push(&rx,
                                        &port_a,
                                        now,
                                        (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                                        (udpard_bytes_mut_t){ .data = push_payload, .size = sizeof(dgram) },
                                        del_payload,
                                        0));
    }

    // The late arrival should have ejected the earlier completed transfers.
    TEST_ASSERT(cb_result.message.count >= 1);
    for (size_t i = 0; i < cb_result.message.count; i++) {
        udpard_fragment_free_all(cb_result.message.history[i].payload, mem_frag);
    }
    cb_result.message.count = 0;

    // Let both sessions expire and be retired from poll.
    udpard_rx_poll(&rx, now);
    now += SESSION_LIFETIME + 1000;
    udpard_rx_poll(&rx, now);

    udpard_rx_port_free(&rx, &port_a);
    udpard_rx_port_free(&rx, &port_b);

    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
}

static void test_rx_port_oom(void)
{
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    instrumented_allocator_t alloc_session = { 0 };
    instrumented_allocator_new(&alloc_session);
    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    alloc_session.limit_fragments               = 0;
    alloc_frag.limit_fragments                  = 0;
    const udpard_mem_resource_t     mem_frag    = instrumented_allocator_make_resource(&alloc_frag);
    const udpard_mem_resource_t     mem_session = instrumented_allocator_make_resource(&alloc_session);
    const udpard_mem_resource_t     mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_mem_deleter_t      del_payload = instrumented_allocator_make_deleter(&alloc_payload);
    const udpard_rx_mem_resources_t rx_mem      = { .fragment = mem_frag, .session = mem_session };
    udpard_rx_t                     rx;
    callback_result_t               cb_result = { 0 };
    udpard_rx_new(&rx);
    rx.user = &cb_result;
    udpard_rx_port_t port_ordered;
    udpard_rx_port_t port_stateless;
    TEST_ASSERT(udpard_rx_port_new(&port_ordered, 0xAAAALL, 100, 20000, rx_mem, &callbacks));
    TEST_ASSERT(
      udpard_rx_port_new(&port_stateless, 0xBBBBLL, 100, UDPARD_RX_REORDERING_WINDOW_STATELESS, rx_mem, &callbacks));
    udpard_us_t  now             = 0;
    const byte_t payload_state[] = { 's', 't', 'a', 't', 'e', 'f', 'u', 'l' };
    const size_t payload_len     = sizeof(payload_state);
    meta_t       meta_state      = { .priority              = udpard_prio_nominal,
                                     .flag_ack              = false,
                                     .transfer_payload_size = (uint32_t)payload_len,
                                     .transfer_id           = 1,
                                     .sender_uid            = 0x1111ULL,
                                     .topic_hash            = 0xAAAALL };
    rx_frame_t*  frame_state     = make_frame_ptr(meta_state, mem_payload, payload_state, 0, payload_len);
    byte_t       dgram_state[HEADER_SIZE_BYTES + payload_len];
    header_serialize(dgram_state, meta_state, 0, 0, frame_state->base.crc);
    memcpy(dgram_state + HEADER_SIZE_BYTES, payload_state, payload_len);
    mem_free(mem_payload, frame_state->base.origin.size, frame_state->base.origin.data);
    void* push_state = mem_payload.alloc(mem_payload.user, sizeof(dgram_state));
    memcpy(push_state, dgram_state, sizeof(dgram_state));
    const uint64_t errors_before = rx.errors_oom;
    TEST_ASSERT(udpard_rx_port_push(&rx,
                                    &port_ordered,
                                    now,
                                    (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                                    (udpard_bytes_mut_t){ .data = push_state, .size = sizeof(dgram_state) },
                                    del_payload,
                                    0));
    TEST_ASSERT_EQUAL(errors_before + 1, rx.errors_oom);
    TEST_ASSERT_EQUAL(0, cb_result.message.count);
    const byte_t payload_stateless[] = { 's', 't', 'a', 't', 'e', 'l', 'e', 's', 's' };
    const size_t payload_stat_len    = sizeof(payload_stateless);
    meta_t       meta_stateless      = { .priority              = udpard_prio_slow,
                                         .flag_ack              = false,
                                         .transfer_payload_size = (uint32_t)payload_stat_len,
                                         .transfer_id           = 2,
                                         .sender_uid            = 0x2222ULL,
                                         .topic_hash            = 0xBBBBLL };
    rx_frame_t*  frame_stateless = make_frame_ptr(meta_stateless, mem_payload, payload_stateless, 0, payload_stat_len);
    byte_t       dgram_stateless[HEADER_SIZE_BYTES + payload_stat_len];
    header_serialize(dgram_stateless, meta_stateless, 0, 0, frame_stateless->base.crc);
    memcpy(dgram_stateless + HEADER_SIZE_BYTES, payload_stateless, payload_stat_len);
    mem_free(mem_payload, frame_stateless->base.origin.size, frame_stateless->base.origin.data);
    void* push_stateless = mem_payload.alloc(mem_payload.user, sizeof(dgram_stateless));
    memcpy(push_stateless, dgram_stateless, sizeof(dgram_stateless));
    now += 1000;
    TEST_ASSERT(udpard_rx_port_push(&rx,
                                    &port_stateless,
                                    now,
                                    (udpard_udpip_ep_t){ .ip = 0x0A000002, .port = 0x5678 },
                                    (udpard_bytes_mut_t){ .data = push_stateless, .size = sizeof(dgram_stateless) },
                                    del_payload,
                                    1));
    TEST_ASSERT_EQUAL(errors_before + 2, rx.errors_oom);
    TEST_ASSERT_EQUAL(0, cb_result.message.count);
    udpard_rx_port_free(&rx, &port_ordered);
    udpard_rx_port_free(&rx, &port_stateless);
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_session);
    instrumented_allocator_reset(&alloc_payload);
}

/// Ensures udpard_rx_port_free walks and clears all sessions across ports.
static void test_rx_port_free_loop(void)
{
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

    const udpard_rx_mem_resources_t rx_mem = { .fragment = mem_frag, .session = mem_session };

    const uint64_t    local_uid = 0xCAFED00DCAFED00DULL;
    udpard_rx_t       rx;
    callback_result_t cb_result = { 0 };
    udpard_rx_new(&rx);
    rx.user = &cb_result;

    udpard_rx_port_t port_p2p;
    TEST_ASSERT(
      udpard_rx_port_new(&port_p2p, local_uid, SIZE_MAX, UDPARD_RX_REORDERING_WINDOW_UNORDERED, rx_mem, &callbacks));

    udpard_rx_port_t port_extra;
    const uint64_t   topic_hash_extra = 0xDEADBEEFF00D1234ULL;
    TEST_ASSERT(udpard_rx_port_new(&port_extra, topic_hash_extra, 1000, 5000, rx_mem, &callbacks));

    udpard_us_t now = 0;

    // Incomplete transfer on the p2p port.
    {
        const char* payload = "INCOMPLETE";
        meta_t      meta    = { .priority              = udpard_prio_slow,
                                .flag_ack              = false,
                                .transfer_payload_size = (uint32_t)strlen(payload),
                                .transfer_id           = 10,
                                .sender_uid            = 0xAAAAULL,
                                .topic_hash            = port_p2p.topic_hash };
        rx_frame_t* frame   = make_frame_ptr(meta, mem_payload, payload, 0, 4);
        byte_t      dgram[HEADER_SIZE_BYTES + 4];
        header_serialize(dgram, meta, 0, 0, frame->base.crc);
        memcpy(dgram + HEADER_SIZE_BYTES, payload, 4);
        mem_free(mem_payload, frame->base.origin.size, frame->base.origin.data);
        void* push_payload = mem_payload.alloc(mem_payload.user, sizeof(dgram));
        memcpy(push_payload, dgram, sizeof(dgram));
        now += 1000;
        TEST_ASSERT(udpard_rx_port_push(&rx,
                                        &port_p2p,
                                        now,
                                        (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                                        (udpard_bytes_mut_t){ .data = push_payload, .size = sizeof(dgram) },
                                        del_payload,
                                        0));
    }

    // Incomplete transfer on the extra port.
    {
        const char* payload = "FRAGMENTS";
        meta_t      meta    = { .priority              = udpard_prio_fast,
                                .flag_ack              = false,
                                .transfer_payload_size = (uint32_t)strlen(payload),
                                .transfer_id           = 20,
                                .sender_uid            = 0xBBBBULL,
                                .topic_hash            = topic_hash_extra };
        rx_frame_t* frame   = make_frame_ptr(meta, mem_payload, payload, 0, 3);
        byte_t      dgram[HEADER_SIZE_BYTES + 3];
        header_serialize(dgram, meta, 0, 0, frame->base.crc);
        memcpy(dgram + HEADER_SIZE_BYTES, payload, 3);
        mem_free(mem_payload, frame->base.origin.size, frame->base.origin.data);
        void* push_payload = mem_payload.alloc(mem_payload.user, sizeof(dgram));
        memcpy(push_payload, dgram, sizeof(dgram));
        now += 1000;
        TEST_ASSERT(udpard_rx_port_push(&rx,
                                        &port_extra,
                                        now,
                                        (udpard_udpip_ep_t){ .ip = 0x0A000002, .port = 0x5678 },
                                        (udpard_bytes_mut_t){ .data = push_payload, .size = sizeof(dgram) },
                                        del_payload,
                                        1));
    }

    TEST_ASSERT(alloc_session.allocated_fragments >= 2);
    TEST_ASSERT(alloc_frag.allocated_fragments >= 2);
    udpard_rx_port_free(&rx, &port_p2p);
    udpard_rx_port_free(&rx, &port_extra);
    TEST_ASSERT_EQUAL_size_t(0, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);

    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_session);
    instrumented_allocator_reset(&alloc_payload);
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_rx_fragment_tree_update_a);
    RUN_TEST(test_rx_fragment_tree_update_exhaustive);
    RUN_TEST(test_rx_fragment_tree_oom);

    RUN_TEST(test_rx_slot_update);

    RUN_TEST(test_rx_transfer_id_forward_distance);

    RUN_TEST(test_rx_session_ordered);
    RUN_TEST(test_rx_session_unordered);
    RUN_TEST(test_rx_session_unordered_reject_old);
    RUN_TEST(test_rx_session_ordered_reject_stale_after_jump);
    RUN_TEST(test_rx_session_unordered_duplicates);
    RUN_TEST(test_rx_session_ordered_zero_reordering_window);

    RUN_TEST(test_rx_port);
    RUN_TEST(test_rx_port_timeouts);
    RUN_TEST(test_rx_port_oom);
    RUN_TEST(test_rx_port_free_loop);

    return UNITY_END();
}
