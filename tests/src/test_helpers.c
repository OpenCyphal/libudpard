// This software is distributed under the terms of the MIT License.
// Copyright (c) 2016-2020 OpenCyphal Development Team.

#include "helpers.h"
#include <unity.h>

static void test_instrumented_allocator(void)
{
    instrumented_allocator_t al;
    instrumented_allocator_new(&al);
    TEST_ASSERT_EQUAL_size_t(0, al.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(SIZE_MAX, al.limit_bytes);
    TEST_ASSERT_EQUAL_UINT64(0, al.count_alloc);
    TEST_ASSERT_EQUAL_UINT64(0, al.count_free);

    const udpard_mem_t resource = instrumented_allocator_make_resource(&al);

    void* a = mem_res_alloc(resource, 123);
    TEST_ASSERT_EQUAL_size_t(1, al.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(123, al.allocated_bytes);
    TEST_ASSERT_EQUAL_UINT64(1, al.count_alloc);
    TEST_ASSERT_EQUAL_UINT64(0, al.count_free);

    void* b = mem_res_alloc(resource, 456);
    TEST_ASSERT_EQUAL_size_t(2, al.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(579, al.allocated_bytes);
    TEST_ASSERT_EQUAL_UINT64(2, al.count_alloc);
    TEST_ASSERT_EQUAL_UINT64(0, al.count_free);

    al.limit_bytes     = 600;
    al.limit_fragments = 2;

    TEST_ASSERT_EQUAL_PTR(NULL, mem_res_alloc(resource, 100));
    TEST_ASSERT_EQUAL_size_t(2, al.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(579, al.allocated_bytes);
    TEST_ASSERT_EQUAL_UINT64(3, al.count_alloc);
    TEST_ASSERT_EQUAL_UINT64(0, al.count_free);

    TEST_ASSERT_EQUAL_PTR(NULL, mem_res_alloc(resource, 21));
    TEST_ASSERT_EQUAL_size_t(2, al.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(579, al.allocated_bytes);
    TEST_ASSERT_EQUAL_UINT64(4, al.count_alloc);
    TEST_ASSERT_EQUAL_UINT64(0, al.count_free);
    al.limit_fragments = 4;

    void* c = mem_res_alloc(resource, 21);
    TEST_ASSERT_EQUAL_size_t(3, al.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(600, al.allocated_bytes);
    TEST_ASSERT_EQUAL_UINT64(5, al.count_alloc);
    TEST_ASSERT_EQUAL_UINT64(0, al.count_free);

    mem_res_free(resource, 123, a);
    TEST_ASSERT_EQUAL_size_t(2, al.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(477, al.allocated_bytes);
    TEST_ASSERT_EQUAL_UINT64(5, al.count_alloc);
    TEST_ASSERT_EQUAL_UINT64(1, al.count_free);

    void* d = mem_res_alloc(resource, 100);
    TEST_ASSERT_EQUAL_size_t(3, al.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(577, al.allocated_bytes);
    TEST_ASSERT_EQUAL_UINT64(6, al.count_alloc);
    TEST_ASSERT_EQUAL_UINT64(1, al.count_free);

    mem_res_free(resource, 21, c);
    TEST_ASSERT_EQUAL_size_t(2, al.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(556, al.allocated_bytes);
    TEST_ASSERT_EQUAL_UINT64(6, al.count_alloc);
    TEST_ASSERT_EQUAL_UINT64(2, al.count_free);

    mem_res_free(resource, 100, d);
    TEST_ASSERT_EQUAL_size_t(1, al.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(456, al.allocated_bytes);
    TEST_ASSERT_EQUAL_UINT64(6, al.count_alloc);
    TEST_ASSERT_EQUAL_UINT64(3, al.count_free);

    mem_res_free(resource, 456, b);
    TEST_ASSERT_EQUAL_size_t(0, al.allocated_fragments);
    TEST_ASSERT_EQUAL_size_t(0, al.allocated_bytes);
    TEST_ASSERT_EQUAL_UINT64(6, al.count_alloc);
    TEST_ASSERT_EQUAL_UINT64(4, al.count_free);
}

void setUp(void) {}

void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_instrumented_allocator);
    return UNITY_END();
}
