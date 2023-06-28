// This software is distributed under the terms of the MIT License.
// Copyright (c) 2016 Cyphal Development Team.
/// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

#pragma once

#include <udpard.h>  // Shall always be included first.
#include <algorithm>
#include <atomic>
#include <array>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <numeric>
#include <unordered_map>
#include <vector>
#include <stdexcept>

#if !(defined(UDPARD_VERSION_MAJOR) && defined(UDPARD_VERSION_MINOR))
#    error "Library version not defined"
#endif

#if !(defined(UDPARD_CYPHAL_SPECIFICATION_VERSION_MAJOR) && defined(UDPARD_CYPHAL_SPECIFICATION_VERSION_MINOR))
#    error "Cyphal specification version not defined"
#endif

namespace helpers
{
namespace dummy_allocator
{
inline auto allocate(UdpardMemoryResource* const ins, const std::size_t amount) -> void*
{
    (void) ins;
    (void) amount;
    return nullptr;
}

inline void free(UdpardMemoryResource* const ins, const size_t size, void* const pointer)
{
    (void) ins;
    (void) size;
    (void) pointer;
}
}  // namespace dummy_allocator

/// We can't use the recommended true random std::random because it cannot be seeded by Catch2 (the testing framework).
template <typename T>
inline auto getRandomNatural(const T upper_open) -> T
{
    return static_cast<T>(static_cast<std::size_t>(std::rand()) % upper_open);
}

template <typename F>
inline void traverse(const UdpardTreeNode* const root, const F& fun)
{
    if (root != nullptr)
    {
        traverse<F>(root->lr[0], fun);
        fun(root);
        traverse<F>(root->lr[1], fun);
    }
}

/// An allocator that sits on top of the standard malloc() providing additional testing capabilities.
/// It allows the user to specify the maximum amount of memory that can be allocated; further requests will emulate OOM.
/// It also performs correctness checks on the memory use.
class TestAllocator
{
public:
    TestAllocator()                                         = default;
    TestAllocator(const TestAllocator&)                     = delete;
    TestAllocator(const TestAllocator&&)                    = delete;
    auto operator=(const TestAllocator&) -> TestAllocator&  = delete;
    auto operator=(const TestAllocator&&) -> TestAllocator& = delete;

    virtual ~TestAllocator()
    {
        const std::unique_lock locker(lock_);
        for (const auto& pair : allocated_)
        {
            // Clang-tidy complains about manual memory management. Suppressed because we need it for testing purposes.
            std::free(pair.first - canary_.size());  // NOLINT
        }
    }

    [[nodiscard]] auto allocate(const std::size_t amount) -> void*
    {
        const std::unique_lock locker(lock_);
        std::uint8_t*          p = nullptr;
        if ((amount > 0U) && ((getTotalAllocatedAmount() + amount) <= ceiling_))
        {
            const auto amount_with_canaries = amount + canary_.size() * 2U;
            // Clang-tidy complains about manual memory management. Suppressed because we need it for testing purposes.
            p = static_cast<std::uint8_t*>(std::malloc(amount_with_canaries));  // NOLINT
            if (p == nullptr)
            {
                throw std::bad_alloc();  // This is a test suite failure, not a failed test. Mind the difference.
            }
            p += canary_.size();
            std::generate_n(p, amount, []() { return static_cast<std::uint8_t>(getRandomNatural(256U)); });
            std::memcpy(p - canary_.size(), canary_.begin(), canary_.size());
            std::memcpy(p + amount, canary_.begin(), canary_.size());
            allocated_.emplace(p, amount);
        }
        return p;
    }

    void free(const std::size_t size, void* const pointer)
    {
        (void) size;  // TODO FIXME ensure the size passed to this function is correct.
        if (pointer != nullptr)
        {
            const std::unique_lock locker(lock_);
            const auto             it = allocated_.find(static_cast<std::uint8_t*>(pointer));
            if (it == std::end(allocated_))  // Catch an attempt to deallocate memory that is not allocated.
            {
                throw std::logic_error("Attempted to deallocate memory that was never allocated; ptr=" +
                                       std::to_string(reinterpret_cast<std::uint64_t>(pointer)));
            }
            const auto [p, amount] = *it;
            if ((0 != std::memcmp(p - canary_.size(), canary_.begin(), canary_.size())) ||
                (0 != std::memcmp(p + amount, canary_.begin(), canary_.size())))
            {
                throw std::logic_error("Dead canary detected at ptr=" +
                                       std::to_string(reinterpret_cast<std::uint64_t>(pointer)));
            }
            std::generate_n(p - canary_.size(),  // Damage the memory to make sure it's not used after deallocation.
                            amount + canary_.size() * 2U,
                            []() { return static_cast<std::uint8_t>(getRandomNatural(256U)); });
            std::free(p - canary_.size());
            allocated_.erase(it);
        }
    }

    [[nodiscard]] auto getNumAllocatedFragments() const
    {
        const std::unique_lock locker(lock_);
        return std::size(allocated_);
    }

    [[nodiscard]] auto getTotalAllocatedAmount() const -> std::size_t
    {
        const std::unique_lock locker(lock_);
        std::size_t            out = 0U;
        for (const auto& pair : allocated_)
        {
            out += pair.second;
        }
        return out;
    }

    [[nodiscard]] auto getAllocationCeiling() const { return static_cast<std::size_t>(ceiling_); }
    void               setAllocationCeiling(const std::size_t amount) { ceiling_ = amount; }

private:
    static auto makeCanary() -> std::array<std::uint8_t, 256>
    {
        std::array<std::uint8_t, 256> out{};
        std::generate_n(out.begin(), out.size(), []() { return static_cast<std::uint8_t>(getRandomNatural(256U)); });
        return out;
    }

    const std::array<std::uint8_t, 256> canary_ = makeCanary();

    mutable std::recursive_mutex                   lock_;
    std::unordered_map<std::uint8_t*, std::size_t> allocated_;
    std::atomic<std::size_t>                       ceiling_ = std::numeric_limits<std::size_t>::max();
};

}  // namespace helpers
