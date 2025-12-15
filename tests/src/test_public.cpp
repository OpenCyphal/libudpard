/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT

#include <udpard.h>
#include "helpers.h"
#include <unity.h>
#include <cstring>

namespace {

/// The data is copied.
udpard_fragment_t* make_test_fragment(const udpard_mem_resource_t& fragment_memory,
                                      const udpard_mem_resource_t& payload_memory,
                                      const udpard_mem_deleter_t   payload_deleter,
                                      const size_t                 offset,
                                      const size_t                 size,
                                      const void*                  data)
{
    auto* const frag =
      static_cast<udpard_fragment_t*>(fragment_memory.alloc(fragment_memory.user, sizeof(udpard_fragment_t)));
    if (frag == nullptr) {
        return nullptr;
    }
    void* payload_data = payload_memory.alloc(payload_memory.user, size);
    if (payload_data == nullptr) {
        fragment_memory.free(fragment_memory.user, sizeof(udpard_fragment_t), frag);
        return nullptr;
    }
    if (size > 0 && data != nullptr) {
        std::memcpy(payload_data, data, size);
    }
    std::memset(frag, 0, sizeof(*frag));
    frag->next            = nullptr;
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
    const udpard_mem_resource_t mem_frag = instrumented_allocator_make_resource(&alloc_frag);

    instrumented_allocator_t alloc_payload{};
    instrumented_allocator_new(&alloc_payload);
    const udpard_mem_resource_t mem_payload = instrumented_allocator_make_resource(&alloc_payload);
    const udpard_mem_deleter_t  del_payload = instrumented_allocator_make_deleter(&alloc_payload);

    // Test with single fragment at offset 0.
    // Note: udpard_fragment_seek() uses the index_offset tree structure internally,
    // which can only be properly built by the RX pipeline. For public API testing,
    // we can only test simple cases with standalone fragments.
    udpard_fragment_t* single = make_test_fragment(mem_frag, mem_payload, del_payload, 0, 5, "hello");
    TEST_ASSERT_NOT_NULL(single);
    single->next = nullptr;
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
    mem_payload.free(mem_payload.user, single->origin.size, single->origin.data);
    mem_frag.free(mem_frag.user, sizeof(udpard_fragment_t), single);
    TEST_ASSERT_EQUAL_size_t(0, alloc_frag.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, alloc_payload.allocated_fragments);
}

} // namespace

extern "C"
{
void setUp() {}
void tearDown() {}
}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_udpard_fragment_seek);
    return UNITY_END();
}
