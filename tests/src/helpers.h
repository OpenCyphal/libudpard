// This software is distributed under the terms of the MIT License.
// Copyright (c) 2016 Cyphal Development Team.
/// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

// ReSharper disable CppRedundantInlineSpecifier
// NOLINTBEGIN(*-unchecked-string-to-number-conversion,*-deprecated-headers,*-designated-initializers,*-loop-convert)
// NOLINTBEGIN(*DeprecatedOrUnsafeBufferHandling,*err34-c,*-vararg,*-use-auto,*-use-nullptr,*-redundant-void-arg)
// NOLINTBEGIN(*-cstyle-cast)
#pragma once

#include <udpard.h> // Shall always be included first.
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#if !(defined(UDPARD_VERSION_MAJOR) && defined(UDPARD_VERSION_MINOR))
#error "Library version not defined"
#endif

#if !(defined(UDPARD_CYPHAL_VERSION_MAJOR) && defined(UDPARD_CYPHAL_VERSION_MINOR))
#error "Cyphal specification version not defined"
#endif

// This is only needed to tell static analyzers that the code that follows is not C++.
#ifdef __cplusplus
extern "C"
{
#endif

#define TEST_PANIC(message)                                                                 \
    do {                                                                                    \
        (void)fprintf(stderr, "%s:%u: PANIC: %s\n", __FILE__, (unsigned)__LINE__, message); \
        (void)fflush(stderr);                                                               \
        abort();                                                                            \
    } while (0)
#define TEST_PANIC_UNLESS(condition) \
    do {                             \
        if (!(condition)) {          \
            TEST_PANIC(#condition);  \
        }                            \
    } while (0)

static inline void* dummy_alloc(void* const user, const size_t size)
{
    (void)user;
    (void)size;
    return NULL;
}

static inline void dummy_free(void* const user, const size_t size, void* const pointer)
{
    (void)user;
    (void)size;
    TEST_PANIC_UNLESS(pointer == NULL);
}

// Single-fragment scatter helper.
static inline udpard_bytes_scattered_t make_scattered(const void* const data, const size_t size)
{
    udpard_bytes_scattered_t out;
    out.bytes.size = size;
    out.bytes.data = data;
    out.next       = NULL;
    return out;
}

// Legacy compatibility user context (removed from public API).
typedef union
{
    void*         ptr[2];
    unsigned char bytes[sizeof(void*) * 2];
} udpard_user_context_t;
#ifdef __cplusplus
#define UDPARD_USER_CONTEXT_NULL \
    udpard_user_context_t {}
#else
#define UDPARD_USER_CONTEXT_NULL ((udpard_user_context_t){ .ptr = { NULL } })
#endif

// Legacy compatibility feedback payload (reliable TX removed from public API).
typedef struct
{
    udpard_user_context_t user;
    uint16_t              acknowledgements;
} udpard_tx_feedback_t;

// Wraps an application pointer for legacy user context plumbing.
static inline udpard_user_context_t make_user_context(void* const obj)
{
    udpard_user_context_t out = UDPARD_USER_CONTEXT_NULL;
    out.ptr[0]                = obj;
    return out;
}

// Calls the current public TX push API directly.
static inline bool udpard_tx_push_native(udpard_tx_t* const             self,
                                         const udpard_us_t              now,
                                         const udpard_us_t              deadline,
                                         const uint16_t                 iface_bitmap,
                                         const udpard_prio_t            priority,
                                         const uint64_t                 transfer_id,
                                         const udpard_udpip_ep_t        endpoint,
                                         const udpard_bytes_scattered_t payload,
                                         void* const                    user)
{
    return udpard_tx_push(self, now, deadline, iface_bitmap, priority, transfer_id, endpoint, payload, user);
}

// Calls the current public TX P2P push API directly.
static inline bool udpard_tx_push_p2p_native(udpard_tx_t* const             self,
                                             const udpard_us_t              now,
                                             const udpard_us_t              deadline,
                                             const udpard_prio_t            priority,
                                             const udpard_udpip_ep_t        endpoints[UDPARD_IFACE_COUNT_MAX],
                                             const udpard_bytes_scattered_t payload,
                                             void* const                    user)
{
    return udpard_tx_push_p2p(self, now, deadline, priority, endpoints, payload, user);
}

// Calls the current public RX constructor directly.
static inline void udpard_rx_new_native(udpard_rx_t* const self) { udpard_rx_new(self); }

// Maps legacy subject push API to the new endpoint-based API.
static inline bool udpard_tx_push_compat(udpard_tx_t* const             self,
                                         const udpard_us_t              now,
                                         const udpard_us_t              deadline,
                                         const uint16_t                 iface_bitmap,
                                         const udpard_prio_t            priority,
                                         const uint64_t                 transfer_id,
                                         const udpard_bytes_scattered_t payload,
                                         void (*const feedback)(udpard_tx_t*, udpard_tx_feedback_t),
                                         const udpard_user_context_t user)
{
    (void)feedback;
    return udpard_tx_push_native(
      self, now, deadline, iface_bitmap, priority, transfer_id, udpard_make_subject_endpoint(0U), payload, user.ptr[0]);
}

// Maps legacy P2P push API to the new endpoint-array API.
static inline bool udpard_tx_push_p2p_compat(udpard_tx_t* const             self,
                                             const udpard_us_t              now,
                                             const udpard_us_t              deadline,
                                             const udpard_prio_t            priority,
                                             const udpard_remote_t          remote,
                                             const udpard_bytes_scattered_t payload,
                                             void (*const feedback)(udpard_tx_t*, udpard_tx_feedback_t),
                                             const udpard_user_context_t user,
                                             uint64_t* const             out_transfer_id)
{
    (void)feedback;
    const uint64_t tid = (self != NULL) ? self->p2p_transfer_id : 0U;
    const bool ok = udpard_tx_push_p2p_native(self, now, deadline, priority, remote.endpoints, payload, user.ptr[0]);
    if (ok && (out_transfer_id != NULL)) {
        *out_transfer_id = tid;
    }
    return ok;
}

// Maps legacy RX constructor API to the new standalone constructor.
static inline void udpard_rx_new_compat(udpard_rx_t* const self, udpard_tx_t* const tx)
{
    (void)tx;
    udpard_rx_new_native(self);
}

// Remap legacy symbol names used by old tests.
#define udpard_tx_push     udpard_tx_push_compat
#define udpard_tx_push_p2p udpard_tx_push_p2p_compat
#define udpard_rx_new      udpard_rx_new_compat

/// The instrumented allocator tracks memory consumption, checks for heap corruption, and can be configured to fail
/// allocations above a certain threshold.
#define INSTRUMENTED_ALLOCATOR_CANARY_SIZE 1024U
typedef struct
{
    /// Each allocator has its own canary, to catch an attempt to free memory allocated by a different allocator.
    uint_least8_t canary[INSTRUMENTED_ALLOCATOR_CANARY_SIZE];
    /// The limit can be changed at any moment to control the maximum amount of memory that can be allocated.
    /// It may be set to a value less than the currently allocated amount.
    size_t limit_fragments;
    size_t limit_bytes;
    /// The current state of the allocator.
    size_t allocated_fragments;
    size_t allocated_bytes;
    /// Event counters.
    uint64_t count_alloc;
    uint64_t count_free;
} instrumented_allocator_t;

static inline void* instrumented_allocator_alloc(void* const user_reference, const size_t size)
{
    instrumented_allocator_t* const self   = (instrumented_allocator_t*)user_reference;
    void*                           result = NULL; // NOLINT(*-const-correctness)
    self->count_alloc++;
    if ((size > 0U) &&                                           //
        ((self->allocated_bytes + size) <= self->limit_bytes) && //
        ((self->allocated_fragments + 1U) <= self->limit_fragments)) {
        const size_t size_with_canaries = size + ((size_t)INSTRUMENTED_ALLOCATOR_CANARY_SIZE * 2U);
        void*        origin             = malloc(size_with_canaries);
        TEST_PANIC_UNLESS(origin != NULL);
        *((size_t*)origin) = size;
        uint_least8_t* p   = ((uint_least8_t*)origin) + sizeof(size_t); // NOLINT(*-const-correctness)
        result             = ((uint_least8_t*)origin) + INSTRUMENTED_ALLOCATOR_CANARY_SIZE;
        for (size_t i = sizeof(size_t); i < INSTRUMENTED_ALLOCATOR_CANARY_SIZE; i++) // Fill the front canary.
        {
            *p++ = self->canary[i];
        }
        for (size_t i = 0; i < size; i++) // Randomize the allocated fragment.
        {
            *p++ = (uint_least8_t)(rand() % (UINT_LEAST8_MAX + 1));
        }
        for (size_t i = 0; i < INSTRUMENTED_ALLOCATOR_CANARY_SIZE; i++) // Fill the back canary.
        {
            *p++ = self->canary[i];
        }
        self->allocated_fragments++;
        self->allocated_bytes += size;
    }
    return result;
}

static inline void instrumented_allocator_free(void* const user_reference, const size_t size, void* const pointer)
{
    instrumented_allocator_t* const self = (instrumented_allocator_t*)user_reference;
    self->count_free++;
    if (pointer != NULL) { // NOLINTNEXTLINE(*-const-correctness)
        uint_least8_t* p         = ((uint_least8_t*)pointer) - INSTRUMENTED_ALLOCATOR_CANARY_SIZE;
        void* const    origin    = p;
        const size_t   true_size = *((const size_t*)origin);
        TEST_PANIC_UNLESS(size == true_size);
        p += sizeof(size_t);
        for (size_t i = sizeof(size_t); i < INSTRUMENTED_ALLOCATOR_CANARY_SIZE; i++) // Check the front canary.
        {
            TEST_PANIC_UNLESS(*p++ == self->canary[i]);
        }
        for (size_t i = 0; i < size; i++) // Destroy the returned memory to prevent use-after-free.
        {
            *p++ = (uint_least8_t)(rand() % (UINT_LEAST8_MAX + 1));
        }
        for (size_t i = 0; i < INSTRUMENTED_ALLOCATOR_CANARY_SIZE; i++) // Check the back canary.
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
static inline void instrumented_allocator_new(instrumented_allocator_t* const self)
{
    for (size_t i = 0; i < INSTRUMENTED_ALLOCATOR_CANARY_SIZE; i++) {
        self->canary[i] = (uint_least8_t)(rand() % (UINT_LEAST8_MAX + 1));
    }
    self->limit_fragments     = SIZE_MAX;
    self->limit_bytes         = SIZE_MAX;
    self->allocated_fragments = 0U;
    self->allocated_bytes     = 0U;
    self->count_alloc         = 0U;
    self->count_free          = 0U;
}

/// Resets the counters and generates a new canary.
/// Will crash if there are outstanding allocations.
static inline void instrumented_allocator_reset(instrumented_allocator_t* const self)
{
    TEST_PANIC_UNLESS(self->allocated_fragments == 0U);
    TEST_PANIC_UNLESS(self->allocated_bytes == 0U);
    instrumented_allocator_new(self);
}

// Shared vtable for instrumented allocators.
static const udpard_mem_vtable_t instrumented_allocator_vtable = {
    .base  = { .free = instrumented_allocator_free },
    .alloc = instrumented_allocator_alloc,
};

static inline udpard_mem_t instrumented_allocator_make_resource(const instrumented_allocator_t* const self)
{
    const udpard_mem_t result = { .vtable = &instrumented_allocator_vtable, .context = (void*)self };
    return result;
}

static inline udpard_deleter_t instrumented_allocator_make_deleter(const instrumented_allocator_t* const self)
{
    const udpard_deleter_t result = { .vtable = &instrumented_allocator_vtable.base, .context = (void*)self };
    return result;
}

// Shortcuts for vtable-based memory access.
static inline void* mem_res_alloc(const udpard_mem_t mem, const size_t size)
{
    return mem.vtable->alloc(mem.context, size);
}

static inline void mem_res_free(const udpard_mem_t mem, const size_t size, void* const ptr)
{
    mem.vtable->base.free(mem.context, size, ptr);
}

static inline void mem_del_free(const udpard_deleter_t del, const size_t size, void* const ptr)
{
    del.vtable->free(del.context, size, ptr);
}

static inline void seed_prng(void)
{
    unsigned          seed    = (unsigned)time(NULL);
    const char* const env_var = getenv("RANDOM_SEED");
    if (env_var != NULL) {
        seed = (unsigned)atoll(env_var); // Conversion errors are possible but ignored.
    }
    srand(seed);
    (void)fprintf(stderr, "export RANDOM_SEED=%u\n", seed);
}

#ifdef __cplusplus
}
#endif

// NOLINTEND(*-cstyle-cast)
// NOLINTEND(*DeprecatedOrUnsafeBufferHandling,*err34-c,*-vararg,*-use-auto,*-use-nullptr,*-redundant-void-arg)
// NOLINTEND(*-unchecked-string-to-number-conversion,*-deprecated-headers,*-designated-initializers,*-loop-convert)
