// This software is distributed under the terms of the MIT License.
// Copyright (c) 2016 Cyphal Development Team.
/// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

#pragma once

#include <udpard.h>  // Shall always be included first.
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#if !(defined(UDPARD_VERSION_MAJOR) && defined(UDPARD_VERSION_MINOR))
#    error "Library version not defined"
#endif

#if !(defined(UDPARD_CYPHAL_SPECIFICATION_VERSION_MAJOR) && defined(UDPARD_CYPHAL_SPECIFICATION_VERSION_MINOR))
#    error "Cyphal specification version not defined"
#endif

// This is only needed to tell static analyzers that the code that follows is not C++.
#ifdef __cplusplus
extern "C" {
#endif

#define TEST_PANIC(message)                                                            \
    do                                                                                 \
    {                                                                                  \
        fprintf(stderr, "%s:%u: PANIC: %s\n", __FILE__, (unsigned) __LINE__, message); \
        fflush(stderr);                                                                \
        abort();                                                                       \
    } while (0)
#define TEST_PANIC_UNLESS(condition) \
    do                               \
    {                                \
        if (!(condition))            \
        {                            \
            TEST_PANIC(#condition);  \
        }                            \
    } while (0)

static inline void* dummyAllocatorAllocate(UdpardMemoryResource* const self, const size_t size)
{
    (void) self;
    (void) size;
    return NULL;
}

static inline void dummyAllocatorFree(UdpardMemoryResource* const self, const size_t size, void* const pointer)
{
    (void) size;
    TEST_PANIC_UNLESS(self != NULL);
    TEST_PANIC_UNLESS(pointer == NULL);
}

/// The instrumented allocator tracks memory consumption, checks for heap corruption, and can be configured to fail
/// allocations above a certain threshold.
#define INSTRUMENTED_ALLOCATOR_CANARY_SIZE 1024U
typedef struct
{
    UdpardMemoryResource base;
    uint_least8_t        canary[INSTRUMENTED_ALLOCATOR_CANARY_SIZE];
    /// The limit can be changed at any moment to control the maximum amount of memory that can be allocated.
    /// It may be set to a value less than the currently allocated amount.
    size_t limit_bytes;
    /// The current state of the allocator.
    size_t allocated_fragments;
    size_t allocated_bytes;
} InstrumentedAllocator;

static inline void* instrumentedAllocatorAllocate(UdpardMemoryResource* const base, const size_t size)
{
    InstrumentedAllocator* const self = (InstrumentedAllocator*) base;
    TEST_PANIC_UNLESS(self->base.allocate == &instrumentedAllocatorAllocate);
    void* result = NULL;
    if ((size > 0U) && ((self->allocated_bytes + size) <= self->limit_bytes))
    {
        const size_t size_with_canaries = size + ((size_t) INSTRUMENTED_ALLOCATOR_CANARY_SIZE * 2U);
        void*        origin             = malloc(size_with_canaries);
        TEST_PANIC_UNLESS(origin != NULL);
        *((size_t*) origin) = size;
        uint_least8_t* p    = ((uint_least8_t*) origin) + sizeof(size_t);
        result              = ((uint_least8_t*) origin) + INSTRUMENTED_ALLOCATOR_CANARY_SIZE;
        for (size_t i = sizeof(size_t); i < INSTRUMENTED_ALLOCATOR_CANARY_SIZE; i++)  // Fill the front canary.
        {
            *p++ = self->canary[i];
        }
        for (size_t i = 0; i < size; i++)  // Randomize the allocated fragment.
        {
            *p++ = (uint_least8_t) (rand() % (UINT_LEAST8_MAX + 1));
        }
        for (size_t i = 0; i < INSTRUMENTED_ALLOCATOR_CANARY_SIZE; i++)  // Fill the back canary.
        {
            *p++ = self->canary[i];
        }
        self->allocated_fragments++;
        self->allocated_bytes += size;
    }
    return result;
}

static inline void instrumentedAllocatorFree(UdpardMemoryResource* const base, const size_t size, void* const pointer)
{
    InstrumentedAllocator* const self = (InstrumentedAllocator*) base;
    TEST_PANIC_UNLESS(self->base.allocate == &instrumentedAllocatorAllocate);
    TEST_PANIC_UNLESS(self->base.free == &instrumentedAllocatorFree);
    if (pointer != NULL)
    {
        uint_least8_t* p         = ((uint_least8_t*) pointer) - INSTRUMENTED_ALLOCATOR_CANARY_SIZE;
        void* const    origin    = p;
        const size_t   true_size = *((const size_t*) origin);
        TEST_PANIC_UNLESS(size == true_size);
        p += sizeof(size_t);
        for (size_t i = sizeof(size_t); i < INSTRUMENTED_ALLOCATOR_CANARY_SIZE; i++)  // Check the front canary.
        {
            TEST_PANIC_UNLESS(*p++ == self->canary[i]);
        }
        for (size_t i = 0; i < size; i++)  // Destroy the returned memory to prevent use-after-free.
        {
            *p++ = (uint_least8_t) (rand() % (UINT_LEAST8_MAX + 1));
        }
        for (size_t i = 0; i < INSTRUMENTED_ALLOCATOR_CANARY_SIZE; i++)  // Check the back canary.
        {
            TEST_PANIC_UNLESS(*p++ == self->canary[i]);
        }
        free(origin);
        TEST_PANIC_UNLESS(self->allocated_fragments > 0U);
        self->allocated_fragments--;
        TEST_PANIC_UNLESS(self->allocated_bytes >= size);
        self->allocated_bytes -= size;
    }
}

/// By default, the limit is unrestricted (set to the maximum possible value).
static inline void instrumentedAllocatorNew(InstrumentedAllocator* const self)
{
    self->base.allocate       = &instrumentedAllocatorAllocate;
    self->base.free           = &instrumentedAllocatorFree;
    self->base.user_reference = NULL;
    for (size_t i = 0; i < INSTRUMENTED_ALLOCATOR_CANARY_SIZE; i++)
    {
        self->canary[i] = (uint_least8_t) (rand() % (UINT_LEAST8_MAX + 1));
    }
    self->limit_bytes         = SIZE_MAX;
    self->allocated_fragments = 0U;
    self->allocated_bytes     = 0U;
}

#ifdef __cplusplus
}
#endif
