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
static rx_frame_base_t make_frame_base(const udpard_mem_t mem_payload,
                                       const size_t       offset,
                                       const size_t       size,
                                       const void* const  payload)
{
    void* data = mem_res_alloc(mem_payload, size);
    if (size > 0) {
        memcpy(data, payload, size);
    }
    return (rx_frame_base_t){ .offset  = offset,
                              .payload = { .data = data, .size = size },
                              .origin  = { .data = data, .size = size } };
}
/// The payload string cannot contain NUL characters.
static rx_frame_base_t make_frame_base_str(const udpard_mem_t mem_payload,
                                           const size_t       offset,
                                           const char* const  payload)
{
    return make_frame_base(mem_payload, offset, (payload != NULL) ? (strlen(payload) + 1) : 0U, payload);
}

/// The created frame will copy the given full transfer payload at the specified offset, of the specified size.
/// The full transfer payload can be invalidated after this call. It is needed here so that we could compute the
/// CRC prefix correctly, which covers the transfer payload bytes in [0,(offset+size)].
static rx_frame_t make_frame(const meta_t       meta,
                             const udpard_mem_t mem_payload,
                             const void* const  full_transfer_payload,
                             const size_t       frame_payload_offset,
                             const size_t       frame_payload_size)
{
    rx_frame_base_t base = make_frame_base(mem_payload,
                                           frame_payload_offset,
                                           frame_payload_size,
                                           (const uint8_t*)full_transfer_payload + frame_payload_offset);
    base.crc             = crc_full(frame_payload_offset + frame_payload_size, (const uint8_t*)full_transfer_payload);
    return (rx_frame_t){ .base = base, .meta = meta };
}
/// A helper that creates a frame in static storage and returns a reference to it. This is a testing aid.
static rx_frame_t* make_frame_ptr(const meta_t       meta,
                                  const udpard_mem_t mem_payload,
                                  const void* const  full_transfer_payload,
                                  const size_t       frame_payload_offset,
                                  const size_t       frame_payload_size)
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
    const udpard_mem_t mem_frag = instrumented_allocator_make_resource(&alloc_frag);

    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_t     mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_deleter_t del_payload = instrumented_allocator_make_deleter(&alloc_payload);

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
        udpard_fragment_free_all((udpard_fragment_t*)root, udpard_make_deleter(mem_frag));
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

    // Redundant fragment removal when a larger fragment bridges neighbors.
    {
        udpard_tree_t*                   root      = NULL;
        size_t                           cov       = 0;
        rx_fragment_tree_update_result_t res       = rx_fragment_tree_rejected;
        const char                       payload[] = "abcdefghij";

        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 0, 2, payload),
                                      10,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 2, 2, payload + 2),
                                      10,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 6, 2, payload + 6),
                                      10,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
        TEST_ASSERT_EQUAL_size_t(3, tree_count(root));

        res = rx_fragment_tree_update(&root, //
                                      mem_frag,
                                      del_payload,
                                      make_frame_base(mem_payload, 1, 6, payload + 1),
                                      10,
                                      10,
                                      &cov);
        TEST_ASSERT_EQUAL(rx_fragment_tree_accepted, res);
        TEST_ASSERT_EQUAL_size_t(3, tree_count(root));
        TEST_ASSERT_EQUAL_size_t(0, fragment_at(root, 0)->offset);
        TEST_ASSERT_EQUAL_size_t(1, fragment_at(root, 1)->offset);
        TEST_ASSERT_EQUAL_size_t(6, fragment_at(root, 2)->offset);

        // Cleanup.
        udpard_fragment_free_all((udpard_fragment_t*)root, udpard_make_deleter(mem_frag));
        TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
        TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
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
        udpard_fragment_free_all((udpard_fragment_t*)root, udpard_make_deleter(mem_frag));
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
        udpard_fragment_free_all((udpard_fragment_t*)root, udpard_make_deleter(mem_frag));
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
        udpard_fragment_free_all(udpard_fragment_seek((udpard_fragment_t*)root, 0), udpard_make_deleter(mem_frag));
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
        udpard_fragment_free_all((udpard_fragment_t*)root, udpard_make_deleter(mem_frag));
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
        udpard_fragment_free_all((udpard_fragment_t*)root, udpard_make_deleter(mem_frag));
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
    const udpard_mem_t mem_frag = instrumented_allocator_make_resource(&alloc_frag);

    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_t     mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_deleter_t del_payload = instrumented_allocator_make_deleter(&alloc_payload);

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
            char* const frag_data = mem_res_alloc(mem_payload, sub.length);
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
        udpard_fragment_free_all((udpard_fragment_t*)root, udpard_make_deleter(mem_frag));
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

            char* const frag_data = mem_res_alloc(mem_payload, sub.length);
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
        udpard_fragment_free_all((udpard_fragment_t*)root, udpard_make_deleter(mem_frag));
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
    const udpard_mem_t mem_frag = instrumented_allocator_make_resource(&alloc_frag);

    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_t     mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_deleter_t del_payload = instrumented_allocator_make_deleter(&alloc_payload);

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
        udpard_fragment_free_all((udpard_fragment_t*)root, udpard_make_deleter(mem_frag));
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
        udpard_fragment_free_all((udpard_fragment_t*)root, udpard_make_deleter(mem_frag));
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
    const udpard_mem_t mem_frag = instrumented_allocator_make_resource(&alloc_frag);

    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_t     mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_deleter_t del_payload = instrumented_allocator_make_deleter(&alloc_payload);

    uint64_t errors_oom                = 0;
    uint64_t errors_transfer_malformed = 0;

    // Test 1: Initialize slot from idle state (slot->busy == false branch)
    {
        rx_slot_t slot = { 0 };

        rx_frame_t frame                 = { 0 };
        frame.base                       = make_frame_base(mem_payload, 0, 5, "hello");
        frame.base.crc                   = 0x9a71bb4cUL; // CRC32C for "hello"
        frame.meta.transfer_id           = 123;
        frame.meta.transfer_payload_size = 5;

        const udpard_us_t ts = 1000;

        // Single-frame transfer should complete immediately.
        const bool done =
          rx_slot_update(&slot, ts, mem_frag, del_payload, &frame, 5, &errors_oom, &errors_transfer_malformed);

        // Verify slot was initialized
        TEST_ASSERT_TRUE(done);
        TEST_ASSERT_FALSE(slot.busy);
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

        // First frame at offset 0
        rx_frame_t frame1                 = { 0 };
        frame1.base                       = make_frame_base(mem_payload, 0, 3, "abc");
        frame1.base.crc                   = 0x12345678;
        frame1.meta.transfer_id           = 456;
        frame1.meta.transfer_payload_size = 10;

        const udpard_us_t ts1 = 2000;
        // First frame initializes slot but does not complete transfer.
        const bool done1 =
          rx_slot_update(&slot, ts1, mem_frag, del_payload, &frame1, 10, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_FALSE(done1);
        TEST_ASSERT_TRUE(slot.busy);
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
        // Later frame updates timestamps and CRC tracking.
        const bool done2 =
          rx_slot_update(&slot, ts2, mem_frag, del_payload, &frame2, 10, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_FALSE(done2);
        TEST_ASSERT_TRUE(slot.busy);
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
        // Earlier frame updates ts_min and extends covered prefix.
        const bool done3 =
          rx_slot_update(&slot, ts3, mem_frag, del_payload, &frame3, 10, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_FALSE(done3);
        TEST_ASSERT_TRUE(slot.busy);
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
        errors_oom     = 0;

        // Limit allocations to trigger OOM
        alloc_frag.limit_fragments = 0;

        rx_frame_t frame                 = { 0 };
        frame.base                       = make_frame_base(mem_payload, 0, 5, "hello");
        frame.base.crc                   = 0x9a71bb4cUL; // CRC32C for "hello"
        frame.meta.transfer_id           = 789;
        frame.meta.transfer_payload_size = 5;

        // OOM should not complete the transfer.
        const bool done =
          rx_slot_update(&slot, 5000, mem_frag, del_payload, &frame, 5, &errors_oom, &errors_transfer_malformed);

        // Verify OOM error was counted
        TEST_ASSERT_FALSE(done);
        TEST_ASSERT_EQUAL(1, errors_oom);
        TEST_ASSERT_TRUE(slot.busy);                      // Slot initialized but fragment not added
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
        errors_transfer_malformed = 0;

        // Single-frame transfer with incorrect CRC
        rx_frame_t frame                 = { 0 };
        frame.base                       = make_frame_base(mem_payload, 0, 4, "test");
        frame.base.crc                   = 0xDEADBEEF; // Incorrect CRC
        frame.meta.transfer_id           = 999;
        frame.meta.transfer_payload_size = 4;

        // CRC failure should reset the slot and report malformed.
        const bool done =
          rx_slot_update(&slot, 6000, mem_frag, del_payload, &frame, 4, &errors_oom, &errors_transfer_malformed);

        // Verify malformed error was counted and slot was reset
        TEST_ASSERT_FALSE(done);
        TEST_ASSERT_EQUAL(1, errors_transfer_malformed);
        TEST_ASSERT_FALSE(slot.busy); // Slot reset after CRC failure
        TEST_ASSERT_EQUAL_size_t(0, slot.covered_prefix);
        TEST_ASSERT_NULL(slot.fragments);

        rx_slot_reset(&slot, mem_frag);
    }
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Test 5: Successful completion with correct CRC (tree_res == rx_fragment_tree_done, CRC pass)
    {
        rx_slot_t slot            = { 0 };
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

        // Correct CRC should complete the transfer.
        const bool done =
          rx_slot_update(&slot, 7000, mem_frag, del_payload, &frame, 4, &errors_oom, &errors_transfer_malformed);

        // Verify successful completion
        TEST_ASSERT_TRUE(done);
        TEST_ASSERT_EQUAL(0, errors_transfer_malformed);
        TEST_ASSERT_FALSE(slot.busy); // Successfully completed
        TEST_ASSERT_EQUAL_size_t(4, slot.covered_prefix);
        TEST_ASSERT_NOT_NULL(slot.fragments);

        rx_slot_reset(&slot, mem_frag);
    }
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Test 6: CRC end update only when crc_end >= slot->crc_end
    {
        rx_slot_t slot            = { 0 };
        errors_transfer_malformed = 0;
        errors_oom                = 0;

        // Frame 1 at offset 5 (will set crc_end to 10)
        rx_frame_t frame1                 = { 0 };
        frame1.base                       = make_frame_base(mem_payload, 5, 5, "world");
        frame1.base.crc                   = 0xAAAAAAAA;
        frame1.meta.transfer_id           = 2222;
        frame1.meta.transfer_payload_size = 20;

        // First frame initializes CRC tracking.
        const bool done1 =
          rx_slot_update(&slot, 8000, mem_frag, del_payload, &frame1, 20, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_FALSE(done1);
        TEST_ASSERT_TRUE(slot.busy);
        TEST_ASSERT_EQUAL(10, slot.crc_end);
        TEST_ASSERT_EQUAL(0xAAAAAAAA, slot.crc);

        // Frame 2 at offset 0 (crc_end would be 3, less than current 10, so CRC shouldn't update)
        rx_frame_t frame2                 = { 0 };
        frame2.base                       = make_frame_base(mem_payload, 0, 3, "abc");
        frame2.base.crc                   = 0xBBBBBBBB;
        frame2.meta.transfer_id           = 2222;
        frame2.meta.transfer_payload_size = 20;

        // Earlier CRC end should not update tracking.
        const bool done2 =
          rx_slot_update(&slot, 8100, mem_frag, del_payload, &frame2, 20, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_FALSE(done2);
        TEST_ASSERT_TRUE(slot.busy);
        TEST_ASSERT_EQUAL(10, slot.crc_end);     // Unchanged
        TEST_ASSERT_EQUAL(0xAAAAAAAA, slot.crc); // Unchanged (frame2 didn't update it)

        // Frame 3 at offset 10 (crc_end would be 15, greater than current 10, so CRC should update)
        rx_frame_t frame3                 = { 0 };
        frame3.base                       = make_frame_base(mem_payload, 10, 5, "hello");
        frame3.base.crc                   = 0xCCCCCCCC;
        frame3.meta.transfer_id           = 2222;
        frame3.meta.transfer_payload_size = 20;

        // Later CRC end should update tracking.
        const bool done3 =
          rx_slot_update(&slot, 8200, mem_frag, del_payload, &frame3, 20, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_FALSE(done3);
        TEST_ASSERT_TRUE(slot.busy);
        TEST_ASSERT_EQUAL(15, slot.crc_end);     // Updated
        TEST_ASSERT_EQUAL(0xCCCCCCCC, slot.crc); // Updated

        rx_slot_reset(&slot, mem_frag);
    }
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Test 7: Inconsistent frame fields; suspicious transfer rejected.
    {
        rx_slot_t slot            = { 0 };
        errors_transfer_malformed = 0;
        errors_oom                = 0;

        // First frame initializes the slot with transfer_payload_size=20 and priority=udpard_prio_high
        rx_frame_t frame1                 = { 0 };
        frame1.base                       = make_frame_base(mem_payload, 0, 5, "hello");
        frame1.base.crc                   = 0x12345678;
        frame1.meta.transfer_id           = 3333;
        frame1.meta.transfer_payload_size = 20;
        frame1.meta.priority              = udpard_prio_high;

        // First frame initializes the slot.
        const bool done1 =
          rx_slot_update(&slot, 9000, mem_frag, del_payload, &frame1, 20, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_FALSE(done1);
        TEST_ASSERT_TRUE(slot.busy);
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

        // Inconsistent total_size should reset the slot.
        const bool done2 =
          rx_slot_update(&slot, 9100, mem_frag, del_payload, &frame2, 25, &errors_oom, &errors_transfer_malformed);

        // Verify that the malformed error was counted and slot was reset
        TEST_ASSERT_FALSE(done2);
        TEST_ASSERT_EQUAL(1, errors_transfer_malformed);
        TEST_ASSERT_FALSE(slot.busy); // Slot reset due to inconsistent total_size
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

        // Reinitialize after reset.
        const bool done3 =
          rx_slot_update(&slot, 9200, mem_frag, del_payload, &frame3, 30, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_FALSE(done3);
        TEST_ASSERT_TRUE(slot.busy);
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

        // Inconsistent priority should reset the slot.
        const bool done4 =
          rx_slot_update(&slot, 9300, mem_frag, del_payload, &frame4, 30, &errors_oom, &errors_transfer_malformed);

        // Verify that the malformed error was counted and slot was reset
        TEST_ASSERT_FALSE(done4);
        TEST_ASSERT_EQUAL(1, errors_transfer_malformed);
        TEST_ASSERT_FALSE(slot.busy); // Slot reset due to inconsistent priority
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

        // Reinitialize after reset.
        const bool done5 =
          rx_slot_update(&slot, 9400, mem_frag, del_payload, &frame5, 40, &errors_oom, &errors_transfer_malformed);

        TEST_ASSERT_FALSE(done5);
        TEST_ASSERT_TRUE(slot.busy);
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

        // Inconsistent priority and total_size should reset the slot.
        const bool done6 =
          rx_slot_update(&slot, 9500, mem_frag, del_payload, &frame6, 50, &errors_oom, &errors_transfer_malformed);

        // Verify that the malformed error was counted and slot was reset
        TEST_ASSERT_FALSE(done6);
        TEST_ASSERT_EQUAL(1, errors_transfer_malformed);
        TEST_ASSERT_FALSE(slot.busy); // Slot reset due to both inconsistencies
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

// Captures ack transfers emitted into the TX pipelines.
typedef struct
{
    udpard_prio_t     priority;
    uint64_t          transfer_id;
    udpard_udpip_ep_t destination;
} ack_tx_info_t;

typedef struct
{
    instrumented_allocator_t alloc_transfer;
    instrumented_allocator_t alloc_payload;
    udpard_tx_t              tx;
    ack_tx_info_t            captured[16];
    size_t                   captured_count;
} tx_fixture_t;

static bool tx_capture_ack_subject(udpard_tx_t* const tx, udpard_tx_ejection_t* const ejection)
{
    (void)tx;
    (void)ejection;
    return true; // ACKs are P2P, subject eject should not be called for them
}

static bool tx_capture_ack_p2p(udpard_tx_t* const          tx,
                               udpard_tx_ejection_t* const ejection,
                               const udpard_udpip_ep_t     destination)
{
    tx_fixture_t* const self = (tx_fixture_t*)tx->user;
    if ((self == NULL) || (self->captured_count >= (sizeof(self->captured) / sizeof(self->captured[0])))) {
        return false;
    }
    udpard_tx_refcount_inc(ejection->datagram);
    meta_t         meta         = { 0 };
    uint32_t       frame_index  = 0;
    uint32_t       frame_offset = 0;
    uint32_t       prefix_crc   = 0;
    udpard_bytes_t payload      = { 0 };
    const bool     ok           = header_deserialize(
      (udpard_bytes_mut_t){ .size = ejection->datagram.size, .data = (void*)ejection->datagram.data },
      &meta,
      &frame_index,
      &frame_offset,
      &prefix_crc,
      &payload);
    if (ok && (frame_index == 0U) && (frame_offset == 0U) && (meta.kind == frame_ack) && (payload.size == 0U)) {
        ack_tx_info_t* const info = &self->captured[self->captured_count++];
        info->priority            = meta.priority;
        info->transfer_id         = meta.transfer_id;
        info->destination         = destination;
    }
    udpard_tx_refcount_dec(ejection->datagram);
    return true;
}

static void tx_fixture_init(tx_fixture_t* const self, const uint64_t uid, const size_t capacity)
{
    instrumented_allocator_new(&self->alloc_transfer);
    instrumented_allocator_new(&self->alloc_payload);
    self->captured_count          = 0;
    udpard_tx_mem_resources_t mem = { 0 };
    mem.transfer                  = instrumented_allocator_make_resource(&self->alloc_transfer);
    for (size_t i = 0; i < UDPARD_IFACE_COUNT_MAX; i++) {
        mem.payload[i] = instrumented_allocator_make_resource(&self->alloc_payload);
    }
    static const udpard_tx_vtable_t vtb = { .eject_subject = &tx_capture_ack_subject,
                                            .eject_p2p     = &tx_capture_ack_p2p };
    TEST_ASSERT(udpard_tx_new(&self->tx, uid, 1U, capacity, mem, &vtb));
    self->tx.user = self;
}

static void tx_fixture_free(tx_fixture_t* const self)
{
    udpard_tx_free(&self->tx);
    TEST_ASSERT_EQUAL(0, self->alloc_transfer.allocated_fragments);
    TEST_ASSERT_EQUAL(0, self->alloc_payload.allocated_fragments);
    instrumented_allocator_reset(&self->alloc_transfer);
    instrumented_allocator_reset(&self->alloc_payload);
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
        ack_tx_info_t last;
        uint64_t      count;
    } ack;
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

static const udpard_rx_port_vtable_t callbacks = { .on_message = &on_message };

/// Checks that ack transfers are emitted into the TX queues.
static void test_rx_ack_enqueued(void)
{
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    const udpard_mem_t mem_frag = instrumented_allocator_make_resource(&alloc_frag);

    instrumented_allocator_t alloc_session = { 0 };
    instrumented_allocator_new(&alloc_session);
    const udpard_mem_t mem_session = instrumented_allocator_make_resource(&alloc_session);

    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_t     mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_deleter_t del_payload = instrumented_allocator_make_deleter(&alloc_payload);

    const udpard_rx_mem_resources_t rx_mem = { .fragment = mem_frag, .session = mem_session };

    tx_fixture_t tx_fix = { 0 };
    tx_fixture_init(&tx_fix, 0xBADC0FFEE0DDF00DULL, 8);

    udpard_rx_t rx;
    udpard_rx_new(&rx, &tx_fix.tx);
    callback_result_t cb_result = { 0 };
    rx.user                     = &cb_result;

    udpard_rx_port_t port;
    const uint64_t   remote_uid = 0xA1B2C3D4E5F60718ULL;
    const size_t     extent     = 1000;
    TEST_ASSERT(udpard_rx_port_new(&port, extent, rx_mem, &callbacks));
    rx_session_factory_args_t fac_args = {
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

    meta_t                  meta = { .priority              = udpard_prio_high,
                                     .kind                  = frame_msg_reliable,
                                     .transfer_payload_size = 5,
                                     .transfer_id           = 77,
                                     .sender_uid            = remote_uid };
    udpard_us_t             now  = 0;
    const udpard_udpip_ep_t ep0  = { .ip = 0x0A000001, .port = 0x1234 };
    now += 100;
    rx_session_update(ses, &rx, now, ep0, make_frame_ptr(meta, mem_payload, "hello", 0, 5), del_payload, 0);
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    udpard_tx_poll(&tx_fix.tx, now, (uint_fast8_t)(1U << 0U));
    cb_result.ack.count = tx_fix.captured_count;
    if (tx_fix.captured_count > 0) {
        cb_result.ack.last = tx_fix.captured[tx_fix.captured_count - 1U];
    }
    TEST_ASSERT(cb_result.ack.count >= 1);
    TEST_ASSERT_EQUAL_UINT64(meta.transfer_id, cb_result.ack.last.transfer_id);
    TEST_ASSERT_EQUAL_UINT32(ep0.ip, cb_result.ack.last.destination.ip);
    TEST_ASSERT_EQUAL_UINT16(ep0.port, cb_result.ack.last.destination.port);

    udpard_fragment_free_all(cb_result.message.history[0].payload, udpard_make_deleter(mem_frag));
    cb_result.message.history[0].payload = NULL;
    cb_result.message.history[0].payload = NULL;
    cb_result.message.history[0].payload = NULL;

    const udpard_udpip_ep_t ep1 = { .ip = 0x0A000002, .port = 0x5678 };
    now += 100;
    rx_session_update(ses, &rx, now, ep1, make_frame_ptr(meta, mem_payload, "hello", 0, 5), del_payload, 1);
    udpard_tx_poll(&tx_fix.tx, now, (uint_fast8_t)(1U << 1U));
    cb_result.ack.count = tx_fix.captured_count;
    if (tx_fix.captured_count > 0) {
        cb_result.ack.last = tx_fix.captured[tx_fix.captured_count - 1U];
    }
    TEST_ASSERT(cb_result.ack.count >= 2); // acks on interfaces 0 and 1
    TEST_ASSERT_EQUAL_UINT64(meta.transfer_id, cb_result.ack.last.transfer_id);

    udpard_rx_port_free(&rx, &port);
    tx_fixture_free(&tx_fix);
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_session);
    instrumented_allocator_reset(&alloc_payload);
}

static void test_rx_session_unordered(void)
{
    // Memory and rx for P2P unordered session.
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    instrumented_allocator_t alloc_session = { 0 };
    instrumented_allocator_new(&alloc_session);
    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_t              mem_frag    = instrumented_allocator_make_resource(&alloc_frag);
    const udpard_mem_t              mem_session = instrumented_allocator_make_resource(&alloc_session);
    const udpard_mem_t              mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_deleter_t          del_payload = instrumented_allocator_make_deleter(&alloc_payload);
    const udpard_rx_mem_resources_t rx_mem      = { .fragment = mem_frag, .session = mem_session };

    udpard_rx_t rx;
    udpard_rx_new(&rx, NULL);
    callback_result_t cb_result = { 0 };
    rx.user                     = &cb_result;

    udpard_rx_port_t port = { 0 };
    TEST_ASSERT(udpard_rx_port_new(&port, SIZE_MAX, rx_mem, &callbacks));

    udpard_us_t               now        = 0;
    const uint64_t            remote_uid = 0xA1B2C3D4E5F60718ULL;
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

    // Single-frame transfer is ejected immediately.
    meta_t meta = { .priority              = udpard_prio_high,
                    .kind                  = frame_msg_best,
                    .transfer_payload_size = 5,
                    .transfer_id           = 100,
                    .sender_uid            = remote_uid };
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                      make_frame_ptr(meta, mem_payload, "hello", 0, 5),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(100, cb_result.message.history[0].transfer_id);
    TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[0], 5, "hello", 5));
    udpard_fragment_free_all(cb_result.message.history[0].payload, udpard_make_deleter(mem_frag));
    cb_result.message.history[0].payload = NULL;

    // Out-of-order arrivals are accepted.
    meta.transfer_id = 103;
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000002, .port = 0x5678 },
                      make_frame_ptr(meta, mem_payload, "tid103", 0, 6),
                      del_payload,
                      1);
    TEST_ASSERT_EQUAL(2, cb_result.message.count);
    TEST_ASSERT_EQUAL(103, cb_result.message.history[0].transfer_id);
    udpard_fragment_free_all(cb_result.message.history[0].payload, udpard_make_deleter(mem_frag));
    cb_result.message.history[0].payload = NULL;

    meta.transfer_id = 102;
    now += 500;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x9999 },
                      make_frame_ptr(meta, mem_payload, "tid102", 0, 6),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(3, cb_result.message.count);
    TEST_ASSERT_EQUAL(102, cb_result.message.history[0].transfer_id);
    udpard_fragment_free_all(cb_result.message.history[0].payload, udpard_make_deleter(mem_frag));
    cb_result.message.history[0].payload = NULL;

    // Duplicate is ignored.
    meta.transfer_id = 103;
    now += 100;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000002, .port = 0x5678 },
                      make_frame_ptr(meta, mem_payload, "dup103", 0, 6),
                      del_payload,
                      1);
    TEST_ASSERT_EQUAL(3, cb_result.message.count);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);

    // Multi-frame transfer completes once all pieces arrive.
    meta.transfer_id           = 200;
    meta.transfer_payload_size = 10;
    meta.priority              = udpard_prio_fast;
    meta.kind                  = frame_msg_reliable;
    now += 500;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000002, .port = 0x5678 },
                      make_frame_ptr(meta, mem_payload, "0123456789", 5, 5),
                      del_payload,
                      1);
    TEST_ASSERT_EQUAL(3, cb_result.message.count);
    TEST_ASSERT_EQUAL(1, alloc_frag.allocated_fragments);
    now += 200;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                      make_frame_ptr(meta, mem_payload, "0123456789", 0, 5),
                      del_payload,
                      0);
    TEST_ASSERT(cb_result.message.count >= 1);
    TEST_ASSERT_EQUAL(200, cb_result.message.history[0].transfer_id);
    TEST_ASSERT(transfer_payload_verify(&cb_result.message.history[0], 10, "0123456789", 10));
    TEST_ASSERT_EQUAL(0x0A000001, cb_result.message.history[0].remote.endpoints[0].ip);
    TEST_ASSERT_EQUAL(0x0A000002, cb_result.message.history[0].remote.endpoints[1].ip);
    udpard_fragment_free_all(cb_result.message.history[0].payload, udpard_make_deleter(mem_frag));
    cb_result.message.history[0].payload = NULL;
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);

    udpard_rx_port_free(&rx, &port);
    TEST_ASSERT_EQUAL(0, alloc_session.allocated_fragments);
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_session);
    instrumented_allocator_reset(&alloc_payload);
}

static void test_rx_session_unordered_reject_old(void)
{
    // Memory and rx with TX for ack replay.
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    const udpard_mem_t       mem_frag      = instrumented_allocator_make_resource(&alloc_frag);
    instrumented_allocator_t alloc_session = { 0 };
    instrumented_allocator_new(&alloc_session);
    const udpard_mem_t       mem_session   = instrumented_allocator_make_resource(&alloc_session);
    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_t              mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_deleter_t          del_payload = instrumented_allocator_make_deleter(&alloc_payload);
    const udpard_rx_mem_resources_t rx_mem      = { .fragment = mem_frag, .session = mem_session };

    tx_fixture_t tx_fix = { 0 };
    tx_fixture_init(&tx_fix, 0xF00DCAFEF00DCAFEULL, 4);
    udpard_rx_t rx;
    udpard_rx_new(&rx, &tx_fix.tx);
    callback_result_t cb_result = { 0 };
    rx.user                     = &cb_result;

    udpard_rx_port_t port = { 0 };
    TEST_ASSERT(udpard_rx_port_new(&port, SIZE_MAX, rx_mem, &callbacks));

    udpard_us_t               now        = 0;
    const uint64_t            remote_uid = 0x0123456789ABCDEFULL;
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

    meta_t meta = { .priority              = udpard_prio_fast,
                    .kind                  = frame_msg_best,
                    .transfer_payload_size = 3,
                    .transfer_id           = 10,
                    .sender_uid            = remote_uid };
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
    udpard_fragment_free_all(cb_result.message.history[0].payload, udpard_make_deleter(mem_frag));

    // Jump far ahead then report the old transfer again.
    meta.transfer_id           = 2050;
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
    TEST_ASSERT_EQUAL(2050, cb_result.message.history[0].transfer_id);
    udpard_fragment_free_all(cb_result.message.history[0].payload, udpard_make_deleter(mem_frag));

    meta.transfer_id           = 10;
    meta.transfer_payload_size = 3;
    meta.kind                  = frame_msg_reliable;
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x0A00000A, .port = 0x0A00 },
                      make_frame_ptr(meta, mem_payload, "dup", 0, 3),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(2, cb_result.message.count);
    udpard_tx_poll(&tx_fix.tx, now, UDPARD_IFACE_BITMAP_ALL);
    cb_result.ack.count = tx_fix.captured_count;
    if (tx_fix.captured_count > 0) {
        cb_result.ack.last = tx_fix.captured[tx_fix.captured_count - 1U];
    }
    TEST_ASSERT_GREATER_OR_EQUAL_UINT64(1, cb_result.ack.count);
    TEST_ASSERT_EQUAL_UINT64(10, cb_result.ack.last.transfer_id);
    TEST_ASSERT_EQUAL_UINT64(meta.transfer_id, cb_result.ack.last.transfer_id);

    udpard_rx_port_free(&rx, &port);
    tx_fixture_free(&tx_fix);
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_session);
    instrumented_allocator_reset(&alloc_payload);
}

static void test_rx_session_unordered_duplicates(void)
{
    // Unordered session accepts earlier arrivals but rejects duplicates.
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    instrumented_allocator_t alloc_session = { 0 };
    instrumented_allocator_new(&alloc_session);
    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_t              mem_frag    = instrumented_allocator_make_resource(&alloc_frag);
    const udpard_mem_t              mem_session = instrumented_allocator_make_resource(&alloc_session);
    const udpard_mem_t              mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_deleter_t          del_payload = instrumented_allocator_make_deleter(&alloc_payload);
    const udpard_rx_mem_resources_t rx_mem      = { .fragment = mem_frag, .session = mem_session };

    udpard_rx_t rx;
    udpard_rx_new(&rx, NULL);
    callback_result_t cb_result = { 0 };
    rx.user                     = &cb_result;

    udpard_rx_port_t port = { 0 };
    TEST_ASSERT(udpard_rx_port_new(&port, SIZE_MAX, rx_mem, &callbacks));

    udpard_us_t               now        = 0;
    const uint64_t            remote_uid = 0xAABBCCDDEEFF0011ULL;
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

    meta_t meta = { .priority              = udpard_prio_nominal,
                    .kind                  = frame_msg_best,
                    .transfer_payload_size = 2,
                    .transfer_id           = 5,
                    .sender_uid            = remote_uid };
    now += 1000;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x11223344, .port = 0x1111 },
                      make_frame_ptr(meta, mem_payload, "aa", 0, 2),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(5, cb_result.message.history[0].transfer_id);
    udpard_fragment_free_all(cb_result.message.history[0].payload, udpard_make_deleter(mem_frag));
    cb_result.message.history[0].payload = NULL;

    // Duplicate dropped.
    now += 10;
    rx_session_update(ses,
                      &rx,
                      now,
                      (udpard_udpip_ep_t){ .ip = 0x11223344, .port = 0x1111 },
                      make_frame_ptr(meta, mem_payload, "bb", 0, 2),
                      del_payload,
                      0);
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);

    udpard_rx_port_free(&rx, &port);
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_session);
    instrumented_allocator_reset(&alloc_payload);
}

static void test_rx_port(void)
{
    // P2P ports behave like ordinary ports for payload delivery.
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    instrumented_allocator_t alloc_session = { 0 };
    instrumented_allocator_new(&alloc_session);
    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_t              mem_frag    = instrumented_allocator_make_resource(&alloc_frag);
    const udpard_mem_t              mem_session = instrumented_allocator_make_resource(&alloc_session);
    const udpard_mem_t              mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_deleter_t          del_payload = instrumented_allocator_make_deleter(&alloc_payload);
    const udpard_rx_mem_resources_t rx_mem      = { .fragment = mem_frag, .session = mem_session };

    udpard_rx_t rx;
    udpard_rx_new(&rx, NULL);
    callback_result_t cb_result = { 0 };
    rx.user                     = &cb_result;

    udpard_rx_port_t port = { 0 };
    TEST_ASSERT(udpard_rx_port_new_p2p(&port, 64, rx_mem, &callbacks));

    // Compose a P2P response datagram without a P2P header.
    const uint64_t resp_tid   = 55;
    const uint8_t  payload[3] = { 'a', 'b', 'c' };

    meta_t      meta  = { .priority              = udpard_prio_fast,
                          .kind                  = frame_msg_best,
                          .transfer_payload_size = sizeof(payload),
                          .transfer_id           = resp_tid,
                          .sender_uid            = 0x0BADF00D0BADF00DULL };
    rx_frame_t* frame = make_frame_ptr(meta, mem_payload, payload, 0, sizeof(payload));
    byte_t      dgram[HEADER_SIZE_BYTES + sizeof(payload)];
    header_serialize(dgram, meta, 0, 0, frame->base.crc);
    memcpy(dgram + HEADER_SIZE_BYTES, payload, sizeof(payload));
    mem_free(mem_payload, frame->base.origin.size, frame->base.origin.data);
    void* push_payload = mem_res_alloc(mem_payload, sizeof(dgram));
    memcpy(push_payload, dgram, sizeof(dgram));

    udpard_us_t now = 0;
    TEST_ASSERT(udpard_rx_port_push(&rx,
                                    &port,
                                    now,
                                    (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                                    (udpard_bytes_mut_t){ .data = push_payload, .size = sizeof(dgram) },
                                    del_payload,
                                    0));
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    TEST_ASSERT_EQUAL(resp_tid, cb_result.message.history[0].transfer_id);
    udpard_fragment_t* const frag = udpard_fragment_seek(cb_result.message.history[0].payload, 0);
    TEST_ASSERT_NOT_NULL(frag);
    TEST_ASSERT_EQUAL_size_t(3, frag->view.size);
    TEST_ASSERT_EQUAL_MEMORY("abc", frag->view.data, 3);
    udpard_fragment_free_all(cb_result.message.history[0].payload, udpard_make_deleter(mem_frag));
    cb_result.message.history[0].payload = NULL;

    udpard_rx_port_free(&rx, &port);
    TEST_ASSERT_EQUAL(0, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_session);
    instrumented_allocator_reset(&alloc_payload);
}

static void test_rx_port_timeouts(void)
{
    // Sessions are retired after SESSION_LIFETIME.
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    instrumented_allocator_t alloc_session = { 0 };
    instrumented_allocator_new(&alloc_session);
    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_t              mem_frag    = instrumented_allocator_make_resource(&alloc_frag);
    const udpard_mem_t              mem_session = instrumented_allocator_make_resource(&alloc_session);
    const udpard_mem_t              mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_deleter_t          del_payload = instrumented_allocator_make_deleter(&alloc_payload);
    const udpard_rx_mem_resources_t rx_mem      = { .fragment = mem_frag, .session = mem_session };

    udpard_rx_t rx;
    udpard_rx_new(&rx, NULL);
    callback_result_t cb_result = { 0 };
    rx.user                     = &cb_result;

    udpard_rx_port_t port = { 0 };
    TEST_ASSERT(udpard_rx_port_new(&port, 128, rx_mem, &callbacks));

    meta_t       meta            = { .priority              = udpard_prio_nominal,
                                     .kind                  = frame_msg_best,
                                     .transfer_payload_size = 4,
                                     .transfer_id           = 1,
                                     .sender_uid            = 0x1111222233334444ULL };
    rx_frame_t*  frame           = make_frame_ptr(meta, mem_payload, "ping", 0, 4);
    const byte_t payload_bytes[] = { 'p', 'i', 'n', 'g' };
    byte_t       dgram[HEADER_SIZE_BYTES + sizeof(payload_bytes)];
    header_serialize(dgram, meta, 0, 0, frame->base.crc);
    memcpy(dgram + HEADER_SIZE_BYTES, payload_bytes, sizeof(payload_bytes));
    mem_free(mem_payload, frame->base.origin.size, frame->base.origin.data);
    void* payload_buf = mem_res_alloc(mem_payload, sizeof(dgram));
    memcpy(payload_buf, dgram, sizeof(dgram));

    udpard_us_t now = 0;
    TEST_ASSERT(udpard_rx_port_push(&rx,
                                    &port,
                                    now,
                                    (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                                    (udpard_bytes_mut_t){ .data = payload_buf, .size = sizeof(dgram) },
                                    del_payload,
                                    0));
    TEST_ASSERT_GREATER_THAN_UINT32(0, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(1, cb_result.message.count);
    udpard_fragment_free_all(cb_result.message.history[0].payload, udpard_make_deleter(mem_frag));
    cb_result.message.history[0].payload = NULL;

    now += SESSION_LIFETIME + 1;
    udpard_rx_poll(&rx, now);
    TEST_ASSERT_EQUAL(0, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);
    udpard_rx_port_free(&rx, &port);
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_session);
    instrumented_allocator_reset(&alloc_payload);
}

static void test_rx_port_oom(void)
{
    // Session allocation failure should be reported gracefully.
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    instrumented_allocator_t alloc_session = { 0 };
    instrumented_allocator_new(&alloc_session);
    alloc_session.limit_fragments          = 0; // force allocation failure
    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_t              mem_frag    = instrumented_allocator_make_resource(&alloc_frag);
    const udpard_mem_t              mem_session = instrumented_allocator_make_resource(&alloc_session);
    const udpard_mem_t              mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_deleter_t          del_payload = instrumented_allocator_make_deleter(&alloc_payload);
    const udpard_rx_mem_resources_t rx_mem      = { .fragment = mem_frag, .session = mem_session };

    udpard_rx_t rx;
    udpard_rx_new(&rx, NULL);
    callback_result_t cb_result = { 0 };
    rx.user                     = &cb_result;

    udpard_rx_port_t port = { 0 };
    TEST_ASSERT(udpard_rx_port_new(&port, 64, rx_mem, &callbacks));

    meta_t       meta            = { .priority              = udpard_prio_nominal,
                                     .kind                  = frame_msg_best,
                                     .transfer_payload_size = 4,
                                     .transfer_id           = 1,
                                     .sender_uid            = 0x0101010101010101ULL };
    rx_frame_t*  frame           = make_frame_ptr(meta, mem_payload, "oom!", 0, 4);
    const byte_t payload_bytes[] = { 'o', 'o', 'm', '!' };
    byte_t       dgram[HEADER_SIZE_BYTES + sizeof(payload_bytes)];
    header_serialize(dgram, meta, 0, 0, frame->base.crc);
    memcpy(dgram + HEADER_SIZE_BYTES, payload_bytes, sizeof(payload_bytes));
    mem_free(mem_payload, frame->base.origin.size, frame->base.origin.data);
    void* payload_buf = mem_res_alloc(mem_payload, sizeof(dgram));
    memcpy(payload_buf, dgram, sizeof(dgram));

    udpard_us_t now = 0;
    TEST_ASSERT(udpard_rx_port_push(&rx,
                                    &port,
                                    now,
                                    (udpard_udpip_ep_t){ .ip = 0x0A000001, .port = 0x1234 },
                                    (udpard_bytes_mut_t){ .data = payload_buf, .size = sizeof(dgram) },
                                    del_payload,
                                    0));
    TEST_ASSERT_GREATER_THAN_UINT64(0, rx.errors_oom);
    TEST_ASSERT_EQUAL(0, alloc_session.allocated_fragments);
    TEST_ASSERT_EQUAL(0, cb_result.message.count);
    TEST_ASSERT_EQUAL(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL(0, alloc_payload.allocated_fragments);
    udpard_rx_port_free(&rx, &port);
    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_session);
    instrumented_allocator_reset(&alloc_payload);
}

static void test_rx_port_free_loop(void)
{
    // Freeing ports with in-flight transfers releases all allocations.
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_new(&alloc_frag);
    instrumented_allocator_t alloc_session = { 0 };
    instrumented_allocator_new(&alloc_session);
    instrumented_allocator_t alloc_payload = { 0 };
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_t              mem_frag    = instrumented_allocator_make_resource(&alloc_frag);
    const udpard_mem_t              mem_session = instrumented_allocator_make_resource(&alloc_session);
    const udpard_mem_t              mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_deleter_t          del_payload = instrumented_allocator_make_deleter(&alloc_payload);
    const udpard_rx_mem_resources_t rx_mem      = { .fragment = mem_frag, .session = mem_session };

    udpard_rx_t rx;
    udpard_rx_new(&rx, NULL);
    callback_result_t cb_result = { 0 };
    rx.user                     = &cb_result;

    udpard_rx_port_t port_p2p = { 0 };
    TEST_ASSERT(udpard_rx_port_new_p2p(&port_p2p, SIZE_MAX, rx_mem, &callbacks));
    udpard_rx_port_t port_extra = { 0 };
    TEST_ASSERT(udpard_rx_port_new(&port_extra, 1000, rx_mem, &callbacks));

    udpard_us_t now = 0;

    // Incomplete transfer on the p2p port.
    {
        const char* payload = "INCOMPLETE";
        meta_t      meta    = { .priority              = udpard_prio_slow,
                                .kind                  = frame_msg_best,
                                .transfer_payload_size = (uint32_t)strlen(payload),
                                .transfer_id           = 10,
                                .sender_uid            = 0xAAAAULL };
        rx_frame_t* frame   = make_frame_ptr(meta, mem_payload, payload, 0, 4);
        byte_t      dgram[HEADER_SIZE_BYTES + 4];
        header_serialize(dgram, meta, 0, 0, frame->base.crc);
        memcpy(dgram + HEADER_SIZE_BYTES, payload, 4);
        mem_free(mem_payload, frame->base.origin.size, frame->base.origin.data);
        void* push_payload = mem_res_alloc(mem_payload, sizeof(dgram));
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
                                .kind                  = frame_msg_best,
                                .transfer_payload_size = (uint32_t)strlen(payload),
                                .transfer_id           = 20,
                                .sender_uid            = 0xBBBBULL };
        rx_frame_t* frame   = make_frame_ptr(meta, mem_payload, payload, 0, 3);
        byte_t      dgram[HEADER_SIZE_BYTES + 3];
        header_serialize(dgram, meta, 0, 0, frame->base.crc);
        memcpy(dgram + HEADER_SIZE_BYTES, payload, 3);
        mem_free(mem_payload, frame->base.origin.size, frame->base.origin.data);
        void* push_payload = mem_res_alloc(mem_payload, sizeof(dgram));
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

static void stub_on_message(udpard_rx_t* const rx, udpard_rx_port_t* const port, const udpard_rx_transfer_t transfer)
{
    (void)rx;
    udpard_fragment_free_all(transfer.payload, udpard_make_deleter(port->memory.fragment));
}

static udpard_udpip_ep_t make_ep(const uint32_t ip) { return (udpard_udpip_ep_t){ .ip = ip, .port = 1U }; }

static void test_rx_additional_coverage(void)
{
    instrumented_allocator_t alloc_frag = { 0 };
    instrumented_allocator_t alloc_ses  = { 0 };
    instrumented_allocator_new(&alloc_frag);
    instrumented_allocator_new(&alloc_ses);
    const udpard_rx_mem_resources_t mem = { .session  = instrumented_allocator_make_resource(&alloc_ses),
                                            .fragment = instrumented_allocator_make_resource(&alloc_frag) };
    // Memory validation rejects missing hooks.
    const udpard_mem_vtable_t vtable_no_free  = { .base = { .free = NULL }, .alloc = dummy_alloc };
    const udpard_mem_vtable_t vtable_no_alloc = { .base = { .free = dummy_free }, .alloc = NULL };
    udpard_rx_mem_resources_t bad_mem         = mem;
    bad_mem.session.vtable                    = &vtable_no_free;
    TEST_ASSERT_FALSE(rx_validate_mem_resources(bad_mem));
    bad_mem.session.vtable = &vtable_no_alloc;
    TEST_ASSERT_FALSE(rx_validate_mem_resources(bad_mem));
    bad_mem                 = mem;
    bad_mem.fragment.vtable = &vtable_no_free;
    TEST_ASSERT_FALSE(rx_validate_mem_resources(bad_mem));
    bad_mem.fragment.vtable = &vtable_no_alloc;
    TEST_ASSERT_FALSE(rx_validate_mem_resources(bad_mem));

    // Session helpers and free paths.
    const udpard_rx_port_vtable_t vtb  = { .on_message = stub_on_message };
    udpard_rx_port_t              port = { 0 };
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port, 8, mem, &vtb));
    udpard_list_t             anim_list = { 0 };
    rx_session_factory_args_t fac_args  = {
         .owner = &port, .sessions_by_animation = &anim_list, .remote_uid = 77, .now = 0
    };
    rx_session_t* const ses = (rx_session_t*)cavl2_find_or_insert(&port.index_session_by_remote_uid,
                                                                  &fac_args.remote_uid,
                                                                  &cavl_compare_rx_session_by_remote_uid,
                                                                  &fac_args,
                                                                  &cavl_factory_rx_session_by_remote_uid);
    TEST_ASSERT_NOT_NULL(ses);
    for (size_t i = 0; i < RX_TRANSFER_HISTORY_COUNT; i++) {
        ses->history[i] = 1;
    }
    ses->history[0] = 5;
    TEST_ASSERT_TRUE(rx_session_is_transfer_ejected(ses, 5));
    TEST_ASSERT_FALSE(rx_session_is_transfer_ejected(ses, 6));
    TEST_ASSERT_EQUAL(-1, cavl_compare_rx_session_by_remote_uid(&(uint64_t){ 10 }, &ses->index_remote_uid));
    TEST_ASSERT_EQUAL(1, cavl_compare_rx_session_by_remote_uid(&(uint64_t){ 100 }, &ses->index_remote_uid));
    rx_session_free(ses, &anim_list);

    // Slot acquisition covers stale busy and eviction.
    udpard_rx_t  rx = { 0 };
    rx_session_t ses_slots;
    mem_zero(sizeof(ses_slots), &ses_slots);
    ses_slots.port            = &port;
    ses_slots.history_current = 0;
    for (size_t i = 0; i < RX_TRANSFER_HISTORY_COUNT; i++) {
        ses_slots.history[i] = 1;
    }
    ses_slots.slots[0].busy        = true;
    ses_slots.slots[0].ts_max      = 0;
    ses_slots.slots[0].transfer_id = 1;
    rx_slot_t* slot                = rx_session_get_slot(&ses_slots, SESSION_LIFETIME + 1, 99);
    TEST_ASSERT_NOT_NULL(slot);
    for (size_t i = 0; i < RX_SLOT_COUNT; i++) {
        ses_slots.slots[i].busy   = true;
        ses_slots.slots[i].ts_max = 10 + (udpard_us_t)i;
    }
    slot = rx_session_get_slot(&ses_slots, 50, 2);
    TEST_ASSERT_NOT_NULL(slot);

    // Stateless accept success, OOM, malformed.
    udpard_rx_port_t port_stateless = { 0 };
    TEST_ASSERT_TRUE(udpard_rx_port_new_stateless(&port_stateless, 8, mem, &vtb));
    rx_frame_t frame;
    byte_t     payload[4] = { 1, 2, 3, 4 };
    mem_zero(sizeof(frame), &frame);
    void* payload_buf = mem_res_alloc(mem.fragment, sizeof(payload));
    memcpy(payload_buf, payload, sizeof(payload));
    frame.base.payload               = (udpard_bytes_t){ .data = payload_buf, .size = sizeof(payload) };
    frame.base.origin                = (udpard_bytes_mut_t){ .data = payload_buf, .size = sizeof(payload) };
    frame.base.crc                   = crc_full(frame.base.payload.size, frame.base.payload.data);
    frame.meta.priority              = udpard_prio_nominal;
    frame.meta.transfer_payload_size = (uint32_t)frame.base.payload.size;
    frame.meta.sender_uid            = 9;
    frame.meta.transfer_id           = 11;
    rx_port_accept_stateless(
      &rx, &port_stateless, 0, make_ep(1), &frame, instrumented_allocator_make_deleter(&alloc_frag), 0);
    alloc_frag.limit_fragments = 0;
    frame.base.payload.data    = payload;
    frame.base.payload.size    = sizeof(payload);
    frame.base.origin          = (udpard_bytes_mut_t){ 0 };
    frame.base.crc             = crc_full(frame.base.payload.size, frame.base.payload.data);
    rx_port_accept_stateless(
      &rx, &port_stateless, 0, make_ep(1), &frame, instrumented_allocator_make_deleter(&alloc_frag), 0);
    frame.base.payload.size          = 0;
    frame.meta.transfer_payload_size = 8;
    rx_port_accept_stateless(
      &rx, &port_stateless, 0, make_ep(1), &frame, instrumented_allocator_make_deleter(&alloc_frag), 0);
    // Stateless accept rejects nonzero offsets.
    alloc_frag.limit_fragments = SIZE_MAX;
    void* payload_buf2         = mem_res_alloc(mem.fragment, sizeof(payload));
    TEST_ASSERT_NOT_NULL(payload_buf2);
    memcpy(payload_buf2, payload, sizeof(payload));
    frame.base.payload               = (udpard_bytes_t){ .data = payload_buf2, .size = sizeof(payload) };
    frame.base.origin                = (udpard_bytes_mut_t){ .data = payload_buf2, .size = sizeof(payload) };
    frame.base.offset                = 1U;
    frame.meta.transfer_payload_size = (uint32_t)sizeof(payload);
    rx_port_accept_stateless(
      &rx, &port_stateless, 0, make_ep(1), &frame, instrumented_allocator_make_deleter(&alloc_frag), 0);
    frame.base.offset = 0;
    udpard_rx_port_free(&rx, &port_stateless);

    // ACK frames are rejected on non-P2P ports.
    udpard_rx_port_t port_normal = { 0 };
    TEST_ASSERT_TRUE(udpard_rx_port_new(&port_normal, 8, mem, &vtb));
    byte_t ack_dgram[HEADER_SIZE_BYTES] = { 0 };
    meta_t ack_meta                     = { .priority              = udpard_prio_nominal,
                                            .kind                  = frame_ack,
                                            .transfer_payload_size = 0,
                                            .transfer_id           = 1,
                                            .sender_uid            = 2 };
    header_serialize(ack_dgram, ack_meta, 0, 0, crc_full(0, NULL));
    udpard_bytes_mut_t ack_payload = { .data = mem_res_alloc(mem.fragment, sizeof(ack_dgram)),
                                       .size = sizeof(ack_dgram) };
    memcpy(ack_payload.data, ack_dgram, sizeof(ack_dgram));
    const uint64_t malformed_before = rx.errors_frame_malformed;
    TEST_ASSERT(udpard_rx_port_push(
      &rx, &port_normal, 0, make_ep(3), ack_payload, instrumented_allocator_make_deleter(&alloc_frag), 0));
    TEST_ASSERT_EQUAL_UINT64(malformed_before + 1U, rx.errors_frame_malformed);
    udpard_rx_port_free(&rx, &port_normal);

    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_ses);
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

    RUN_TEST(test_rx_ack_enqueued);

    RUN_TEST(test_rx_session_unordered);
    RUN_TEST(test_rx_session_unordered_reject_old);
    RUN_TEST(test_rx_session_unordered_duplicates);

    RUN_TEST(test_rx_port);
    RUN_TEST(test_rx_port_timeouts);
    RUN_TEST(test_rx_port_oom);
    RUN_TEST(test_rx_port_free_loop);
    RUN_TEST(test_rx_additional_coverage);

    return UNITY_END();
}
