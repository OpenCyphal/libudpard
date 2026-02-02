/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.h>
#include "helpers.h"
#include <unity.h>
#include <cstring>
#include <algorithm>

namespace {

/// The data is copied.
udpard_fragment_t* make_test_fragment(const udpard_mem_t&    fragment_memory,
                                      const udpard_mem_t&    payload_memory,
                                      const udpard_deleter_t payload_deleter,
                                      const size_t           offset,
                                      const size_t           size,
                                      const void*            data)
{
    auto* frag = static_cast<udpard_fragment_t*>(mem_res_alloc(fragment_memory, sizeof(udpard_fragment_t)));
    if (frag == nullptr) {
        return nullptr;
    }
    void* payload_data = mem_res_alloc(payload_memory, size);
    if (payload_data == nullptr) {
        mem_res_free(fragment_memory, sizeof(udpard_fragment_t), frag);
        return nullptr;
    }
    if (size > 0 && data != nullptr) {
        std::memcpy(payload_data, data, size);
    }
    std::memset(frag, 0, sizeof(*frag));
    frag->view.data       = payload_data;
    frag->view.size       = size;
    frag->origin.data     = payload_data;
    frag->origin.size     = size;
    frag->offset          = offset;
    frag->payload_deleter = payload_deleter;
    return frag;
}

void test_udpard_fragment_seek()
{
    instrumented_allocator_t alloc_frag{};
    instrumented_allocator_new(&alloc_frag);
    const udpard_mem_t mem_frag = instrumented_allocator_make_resource(&alloc_frag);

    instrumented_allocator_t alloc_payload{};
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_t     mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_deleter_t del_payload = instrumented_allocator_make_deleter(&alloc_payload);

    // Test 1: Single fragment at offset 0 (root node).
    // Note: udpard_fragment_seek() uses the index_offset tree structure internally,
    // which can only be properly built by the RX pipeline. For public API testing,
    // we can only test simple cases with manually constructed tree structures.
    udpard_fragment_t* single = make_test_fragment(mem_frag, mem_payload, del_payload, 0, 5, "hello");
    TEST_ASSERT_NOT_NULL(single);
    // Initialize the tree node to null (no parent, no children) - this makes it a standalone root
    single->index_offset.up    = nullptr;
    single->index_offset.lr[0] = nullptr;
    single->index_offset.lr[1] = nullptr;
    single->index_offset.bf    = 0;

    // Seek to offset 0 should return the fragment itself.
    TEST_ASSERT_EQUAL_PTR(single, udpard_fragment_seek(single, 0));

    // Seek within single fragment range [0-5).
    TEST_ASSERT_EQUAL_PTR(single, udpard_fragment_seek(single, 0));
    TEST_ASSERT_EQUAL_PTR(single, udpard_fragment_seek(single, 1));
    TEST_ASSERT_EQUAL_PTR(single, udpard_fragment_seek(single, 2));
    TEST_ASSERT_EQUAL_PTR(single, udpard_fragment_seek(single, 4));

    // Seek beyond single fragment should return NULL.
    TEST_ASSERT_NULL(udpard_fragment_seek(single, 5));
    TEST_ASSERT_NULL(udpard_fragment_seek(single, 100));

    // Cleanup.
    mem_res_free(mem_payload, single->origin.size, single->origin.data);
    mem_res_free(mem_frag, sizeof(udpard_fragment_t), single);
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);

    instrumented_allocator_reset(&alloc_frag);
    instrumented_allocator_reset(&alloc_payload);

    // Test 2: Tree with root and child - to test the root-finding loop.
    // Create a simple tree: root at offset 5, left child at offset 0, right child at offset 10
    udpard_fragment_t* root  = make_test_fragment(mem_frag, mem_payload, del_payload, 5, 3, "mid");
    udpard_fragment_t* left  = make_test_fragment(mem_frag, mem_payload, del_payload, 0, 3, "abc");
    udpard_fragment_t* right = make_test_fragment(mem_frag, mem_payload, del_payload, 10, 4, "wxyz");
    TEST_ASSERT_NOT_NULL(root);
    TEST_ASSERT_NOT_NULL(left);
    TEST_ASSERT_NOT_NULL(right);

    // Build tree structure: root has left and right children
    root->index_offset.up    = nullptr;              // root has no parent
    root->index_offset.lr[0] = &left->index_offset;  // left child
    root->index_offset.lr[1] = &right->index_offset; // right child
    root->index_offset.bf    = 0;

    left->index_offset.up    = &root->index_offset; // parent is root
    left->index_offset.lr[0] = nullptr;
    left->index_offset.lr[1] = nullptr;
    left->index_offset.bf    = 0;

    right->index_offset.up    = &root->index_offset; // parent is root
    right->index_offset.lr[0] = nullptr;
    right->index_offset.lr[1] = nullptr;
    right->index_offset.bf    = 0;

    // Test seeking from the left child (non-root) - should traverse up to root first.
    // Seeking to offset 0 should find the left fragment.
    TEST_ASSERT_EQUAL_PTR(left, udpard_fragment_seek(left, 0));
    TEST_ASSERT_EQUAL_PTR(left, udpard_fragment_seek(left, 1));
    TEST_ASSERT_EQUAL_PTR(left, udpard_fragment_seek(left, 2));

    // Seeking from left child to middle fragment's range [5-8).
    TEST_ASSERT_EQUAL_PTR(root, udpard_fragment_seek(left, 5));
    TEST_ASSERT_EQUAL_PTR(root, udpard_fragment_seek(left, 6));
    TEST_ASSERT_EQUAL_PTR(root, udpard_fragment_seek(left, 7));

    // Seeking from right child (non-root) to its own range [10-14).
    TEST_ASSERT_EQUAL_PTR(right, udpard_fragment_seek(right, 10));
    TEST_ASSERT_EQUAL_PTR(right, udpard_fragment_seek(right, 11));
    TEST_ASSERT_EQUAL_PTR(right, udpard_fragment_seek(right, 13));

    // Seeking from right child back to left child - should traverse up to root first.
    TEST_ASSERT_EQUAL_PTR(left, udpard_fragment_seek(right, 0));
    TEST_ASSERT_EQUAL_PTR(left, udpard_fragment_seek(right, 2));

    // Seeking from any node to gaps should return NULL.
    TEST_ASSERT_NULL(udpard_fragment_seek(left, 3));   // gap [3-5)
    TEST_ASSERT_NULL(udpard_fragment_seek(root, 8));   // gap [8-10)
    TEST_ASSERT_NULL(udpard_fragment_seek(right, 14)); // beyond all fragments

    // Cleanup.
    mem_res_free(mem_payload, left->origin.size, left->origin.data);
    mem_res_free(mem_frag, sizeof(udpard_fragment_t), left);
    mem_res_free(mem_payload, root->origin.size, root->origin.data);
    mem_res_free(mem_frag, sizeof(udpard_fragment_t), root);
    mem_res_free(mem_payload, right->origin.size, right->origin.data);
    mem_res_free(mem_frag, sizeof(udpard_fragment_t), right);
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
}

void test_udpard_fragment_gather()
{
    instrumented_allocator_t alloc_frag{};
    instrumented_allocator_new(&alloc_frag);
    const udpard_mem_t mem_frag = instrumented_allocator_make_resource(&alloc_frag);

    instrumented_allocator_t alloc_payload{};
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_t     mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_deleter_t del_payload = instrumented_allocator_make_deleter(&alloc_payload);

    // Test 1: NULL fragment returns 0.
    char                     buf[100]; // NOLINT(*-avoid-c-arrays)
    const udpard_fragment_t* null_frag = nullptr;
    TEST_ASSERT_EQUAL_size_t(0, udpard_fragment_gather(&null_frag, 0, sizeof(buf), static_cast<void*>(buf)));

    // Test 2: NULL destination returns 0.
    udpard_fragment_t* const single = make_test_fragment(mem_frag, mem_payload, del_payload, 0, 5, "hello");
    TEST_ASSERT_NOT_NULL(single);
    single->index_offset.up         = nullptr;
    single->index_offset.lr[0]      = nullptr;
    single->index_offset.lr[1]      = nullptr;
    single->index_offset.bf         = 0;
    const udpard_fragment_t* cursor = single;
    TEST_ASSERT_EQUAL_size_t(0, udpard_fragment_gather(&cursor, 0, sizeof(buf), nullptr));
    TEST_ASSERT_EQUAL_PTR(single, cursor);

    // Test 3: Single fragment - gather all.
    (void)std::memset(static_cast<void*>(buf), 0, sizeof(buf));
    cursor = single;
    TEST_ASSERT_EQUAL_size_t(5, udpard_fragment_gather(&cursor, 0, sizeof(buf), static_cast<void*>(buf)));
    TEST_ASSERT_EQUAL_MEMORY("hello", buf, 5);
    TEST_ASSERT_EQUAL_PTR(single, cursor);

    // Test 4: Single fragment - truncation (destination smaller than fragment).
    (void)std::memset(static_cast<void*>(buf), 0, sizeof(buf));
    cursor = single;
    TEST_ASSERT_EQUAL_size_t(3, udpard_fragment_gather(&cursor, 0, 3, static_cast<void*>(buf)));
    TEST_ASSERT_EQUAL_MEMORY("hel", buf, 3);
    TEST_ASSERT_EQUAL_PTR(single, cursor);

    // Test 5: Single fragment - offset into the payload.
    (void)std::memset(static_cast<void*>(buf), 0, sizeof(buf));
    cursor = single;
    TEST_ASSERT_EQUAL_size_t(2, udpard_fragment_gather(&cursor, 2, 2, static_cast<void*>(buf)));
    TEST_ASSERT_EQUAL_MEMORY("ll", buf, 2);
    TEST_ASSERT_EQUAL_PTR(single, cursor);

    // Cleanup single fragment.
    mem_res_free(mem_payload, single->origin.size, single->origin.data);
    mem_res_free(mem_frag, sizeof(udpard_fragment_t), single);

    // Test 6: Multiple fragments forming a tree.
    // Create tree: root at offset 5 ("MID"), left at offset 0 ("ABCDE"), right at offset 8 ("WXYZ")
    // Total payload when gathered: "ABCDE" + "MID" + "WXYZ" = "ABCDEMIDWXYZ" (12 bytes)
    udpard_fragment_t* const root  = make_test_fragment(mem_frag, mem_payload, del_payload, 5, 3, "MID");
    udpard_fragment_t* const left  = make_test_fragment(mem_frag, mem_payload, del_payload, 0, 5, "ABCDE");
    udpard_fragment_t* const right = make_test_fragment(mem_frag, mem_payload, del_payload, 8, 4, "WXYZ");
    TEST_ASSERT_NOT_NULL(root);
    TEST_ASSERT_NOT_NULL(left);
    TEST_ASSERT_NOT_NULL(right);

    // Build tree structure.
    root->index_offset.up    = nullptr;
    root->index_offset.lr[0] = &left->index_offset;
    root->index_offset.lr[1] = &right->index_offset;
    root->index_offset.bf    = 0;

    left->index_offset.up    = &root->index_offset;
    left->index_offset.lr[0] = nullptr;
    left->index_offset.lr[1] = nullptr;
    left->index_offset.bf    = 0;

    right->index_offset.up    = &root->index_offset;
    right->index_offset.lr[0] = nullptr;
    right->index_offset.lr[1] = nullptr;
    right->index_offset.bf    = 0;

    // Gather from root - should collect all fragments in order.
    (void)std::memset(static_cast<void*>(buf), 0, sizeof(buf));
    cursor = root;
    TEST_ASSERT_EQUAL_size_t(12, udpard_fragment_gather(&cursor, 0, sizeof(buf), static_cast<void*>(buf)));
    TEST_ASSERT_EQUAL_MEMORY("ABCDEMIDWXYZ", buf, 12);
    TEST_ASSERT_EQUAL_PTR(right, cursor);

    // Gather from left child - should still collect all fragments (traverses to root first).
    (void)std::memset(static_cast<void*>(buf), 0, sizeof(buf));
    cursor = left;
    TEST_ASSERT_EQUAL_size_t(12, udpard_fragment_gather(&cursor, 0, sizeof(buf), static_cast<void*>(buf)));
    TEST_ASSERT_EQUAL_MEMORY("ABCDEMIDWXYZ", buf, 12);
    TEST_ASSERT_EQUAL_PTR(right, cursor);

    // Gather from right child - should still collect all fragments.
    (void)std::memset(static_cast<void*>(buf), 0, sizeof(buf));
    cursor = right;
    TEST_ASSERT_EQUAL_size_t(12, udpard_fragment_gather(&cursor, 0, sizeof(buf), static_cast<void*>(buf)));
    TEST_ASSERT_EQUAL_MEMORY("ABCDEMIDWXYZ", buf, 12);
    TEST_ASSERT_EQUAL_PTR(right, cursor);

    // Gather starting exactly at the end of the current cursor fragment.
    (void)std::memset(static_cast<void*>(buf), 0, sizeof(buf));
    cursor = left;
    TEST_ASSERT_EQUAL_size_t(7, udpard_fragment_gather(&cursor, 5, 7, static_cast<void*>(buf)));
    TEST_ASSERT_EQUAL_MEMORY("MIDWXYZ", buf, 7);
    TEST_ASSERT_EQUAL_PTR(right, cursor);

    // Test 7: Truncation with multiple fragments - buffer smaller than total.
    (void)std::memset(static_cast<void*>(buf), 0, sizeof(buf));
    cursor = root;
    TEST_ASSERT_EQUAL_size_t(7, udpard_fragment_gather(&cursor, 0, 7, static_cast<void*>(buf)));
    TEST_ASSERT_EQUAL_MEMORY("ABCDEMI", buf, 7);
    TEST_ASSERT_EQUAL_PTR(root, cursor);

    // Test 8: Truncation mid-fragment.
    (void)std::memset(static_cast<void*>(buf), 0, sizeof(buf));
    cursor = root;
    TEST_ASSERT_EQUAL_size_t(3, udpard_fragment_gather(&cursor, 0, 3, static_cast<void*>(buf)));
    TEST_ASSERT_EQUAL_MEMORY("ABC", buf, 3);
    TEST_ASSERT_EQUAL_PTR(left, cursor);

    // Test 9: Offset across fragments.
    (void)std::memset(static_cast<void*>(buf), 0, sizeof(buf));
    cursor = root;
    TEST_ASSERT_EQUAL_size_t(6, udpard_fragment_gather(&cursor, 2, 6, static_cast<void*>(buf)));
    TEST_ASSERT_EQUAL_MEMORY("CDEMID", buf, 6);
    TEST_ASSERT_EQUAL_PTR(root, cursor);

    // Test 10: Start on fragment boundary, span into next.
    (void)std::memset(static_cast<void*>(buf), 0, sizeof(buf));
    cursor = root;
    TEST_ASSERT_EQUAL_size_t(5, udpard_fragment_gather(&cursor, 5, 5, static_cast<void*>(buf)));
    TEST_ASSERT_EQUAL_MEMORY("MIDWX", buf, 5);
    TEST_ASSERT_EQUAL_PTR(right, cursor);

    // Test 11: Start inside last fragment with request beyond stored data.
    (void)std::memset(static_cast<void*>(buf), 0, sizeof(buf));
    cursor = root;
    TEST_ASSERT_EQUAL_size_t(3, udpard_fragment_gather(&cursor, 9, 10, static_cast<void*>(buf)));
    TEST_ASSERT_EQUAL_MEMORY("XYZ", buf, 3);
    TEST_ASSERT_EQUAL_PTR(right, cursor);

    // Test 12: Offset beyond available payload.
    (void)std::memset(static_cast<void*>(buf), 0, sizeof(buf));
    cursor = root;
    TEST_ASSERT_EQUAL_size_t(0, udpard_fragment_gather(&cursor, 100, sizeof(buf), static_cast<void*>(buf)));
    TEST_ASSERT_EQUAL_PTR(root, cursor);

    // Test 13: Zero-size destination.
    cursor = root;
    TEST_ASSERT_EQUAL_size_t(0, udpard_fragment_gather(&cursor, 0, 0, static_cast<void*>(buf)));
    TEST_ASSERT_EQUAL_PTR(root, cursor);

    // Cleanup.
    mem_res_free(mem_payload, left->origin.size, left->origin.data);
    mem_res_free(mem_frag, sizeof(udpard_fragment_t), left);
    mem_res_free(mem_payload, root->origin.size, root->origin.data);
    mem_res_free(mem_frag, sizeof(udpard_fragment_t), root);
    mem_res_free(mem_payload, right->origin.size, right->origin.data);
    mem_res_free(mem_frag, sizeof(udpard_fragment_t), right);
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
}

} // namespace

extern "C" void setUp() {}

extern "C" void tearDown() {}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_udpard_fragment_seek);
    RUN_TEST(test_udpard_fragment_gather);
    return UNITY_END();
}
