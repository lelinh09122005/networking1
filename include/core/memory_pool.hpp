#pragma once

/**
 * @file memory_pool.hpp
 * @brief High-Speed Lock-Free Pre-allocated Slab Memory Pool for PacketBuffers.
 *
 * Telecom Fast-Path Invariant:
 *   Zero dynamic heap allocations (`malloc`/`new`) on the fast path.
 *
 * Architecture:
 *   - Pre-allocates a contiguous slab of N `PacketBuffer`s in RAM.
 *   - Guaranteed 64-byte Cache Line alignment for every `PacketBuffer` in the slab.
 *   - Lock-Free LIFO Free-List using 64-bit Tagged-Index Compare-And-Swap (CAS):
 *     - Immune to the ABA problem via 32-bit monotonically incrementing tag counter.
 *     - Maximum CPU Cache Warmth: LIFO order reuses recently freed buffers while still in L1/L2 cache.
 *     - Handles arbitrary out-of-order allocations and frees across multiple worker threads.
 *   - Direct integration with `PacketBuffer::release()`:
 *     - Calling `pkt->release()` automatically recycles the buffer back to this pool.
 *   - Vector / Batch API (`allocate_batch`, `free_batch`) for DPDK-like vector processing.
 */

#include "packet_buffer.hpp"
#include <cstddef>
#include <cstdint>
#include <atomic>
#include <cassert>
#include <new>

namespace telecom::core {

template <size_t PoolCapacity = 16384>
class alignas(64) MemoryPool {
    static_assert(PoolCapacity >= 2, "MemoryPool PoolCapacity must be >= 2!");
    static_assert(PoolCapacity <= 0xFFFFFFFEU, "PoolCapacity must fit in 32-bit index!");
    static constexpr uint32_t EMPTY_INDEX = 0xFFFFFFFFU;

private:
    // ------------------------------------------------------------------------
    // Pre-allocated Contiguous Storage (Slab)
    // ------------------------------------------------------------------------
    PacketBuffer* slab_{nullptr};
    std::atomic<uint32_t>* next_free_{nullptr};

    // ------------------------------------------------------------------------
    // Lock-Free Tagged Stack Head (High 32 bits = Tag, Low 32 bits = Index)
    // ------------------------------------------------------------------------
    alignas(64) std::atomic<uint64_t> head_{0};
    uint8_t _pad_head_[64 - sizeof(std::atomic<uint64_t>)]{};

    // ------------------------------------------------------------------------
    // Performance and Health Monitoring Counters
    // ------------------------------------------------------------------------
    alignas(64) std::atomic<uint64_t> alloc_count_{0};
    std::atomic<uint64_t> free_count_{0};
    std::atomic<uint64_t> fail_count_{0};
    std::atomic<int64_t>  in_use_count_{0};

public:
    MemoryPool() {
        // Allocate contiguous slab aligned to 64 bytes
        slab_ = new (std::align_val_t{64}) PacketBuffer[PoolCapacity];
        assert(reinterpret_cast<uintptr_t>(slab_) % 64 == 0 && "Slab must be 64-byte aligned!");

        next_free_ = new std::atomic<uint32_t>[PoolCapacity];

        // Initialize each PacketBuffer and chain them in the free-list
        for (size_t i = 0; i < PoolCapacity; ++i) {
            PacketBuffer* pkt = &slab_[i];
            pkt->reset();
            pkt->pool_index = static_cast<uint16_t>(i);
            pkt->user_data  = this;
            pkt->release_cb = &MemoryPool::pool_release_cb;

            const uint32_t next_idx = (i + 1 < PoolCapacity) ? static_cast<uint32_t>(i + 1) : EMPTY_INDEX;
            next_free_[i].store(next_idx, std::memory_order_relaxed);
        }

        // Initialize head: Tag = 0, Top index = 0
        head_.store(0ULL, std::memory_order_relaxed);
        in_use_count_.store(0, std::memory_order_relaxed);
    }

    ~MemoryPool() {
        delete[] slab_;
        delete[] next_free_;
    }

    // Non-copyable, non-movable to maintain pointer stability
    MemoryPool(const MemoryPool&) = delete;
    MemoryPool& operator=(const MemoryPool&) = delete;
    MemoryPool(MemoryPool&&) = delete;
    MemoryPool& operator=(MemoryPool&&) = delete;

    /**
     * @brief Allocate a single PacketBuffer from the pool (Lock-free O(1)).
     * @return Pointer to freshly reset PacketBuffer, or nullptr if pool is exhausted.
     */
    [[nodiscard]] PacketBuffer* allocate() noexcept {
        uint64_t old_head = head_.load(std::memory_order_acquire);

        for (;;) {
            const uint32_t index = static_cast<uint32_t>(old_head & 0xFFFFFFFFULL);
            if (index == EMPTY_INDEX) {
                fail_count_.fetch_add(1, std::memory_order_relaxed);
                return nullptr; // Pool is empty
            }

            const uint32_t next_idx = next_free_[index].load(std::memory_order_relaxed);
            const uint32_t tag = static_cast<uint32_t>(old_head >> 32) + 1;
            const uint64_t new_head = (static_cast<uint64_t>(tag) << 32) | next_idx;

            if (head_.compare_exchange_weak(old_head, new_head,
                                            std::memory_order_acquire,
                                            std::memory_order_relaxed)) {
                PacketBuffer* pkt = &slab_[index];
                pkt->reset();
                alloc_count_.fetch_add(1, std::memory_order_relaxed);
                in_use_count_.fetch_add(1, std::memory_order_relaxed);
                return pkt;
            }
            // If CAS failed, old_head is updated automatically with the current value
        }
    }

    /**
     * @brief Return a PacketBuffer to the pool (Lock-free O(1)).
     * @param pkt PacketBuffer to return.
     */
    void free(PacketBuffer* pkt) noexcept {
        if (!pkt) return;
        assert(is_from_this_pool(pkt) && "MemoryPool::free: PacketBuffer does not belong to this pool!");

        const uint32_t index = pkt->pool_index;
        uint64_t old_head = head_.load(std::memory_order_relaxed);

        for (;;) {
            const uint32_t cur_top = static_cast<uint32_t>(old_head & 0xFFFFFFFFULL);
            next_free_[index].store(cur_top, std::memory_order_relaxed);

            const uint32_t tag = static_cast<uint32_t>(old_head >> 32) + 1;
            const uint64_t new_head = (static_cast<uint64_t>(tag) << 32) | index;

            if (head_.compare_exchange_weak(old_head, new_head,
                                            std::memory_order_release,
                                            std::memory_order_relaxed)) {
                free_count_.fetch_add(1, std::memory_order_relaxed);
                in_use_count_.fetch_sub(1, std::memory_order_relaxed);
                return;
            }
        }
    }

    /**
     * @brief Allocate a batch of PacketBuffers (Vector processing).
     * @param out_pkts Array to store pointers of allocated buffers.
     * @param count Number of buffers requested.
     * @return Number of buffers successfully allocated (0 <= allocated <= count).
     */
    size_t allocate_batch(PacketBuffer** out_pkts, size_t count) noexcept {
        if (!out_pkts || count == 0) return 0;
        size_t allocated = 0;
        for (size_t i = 0; i < count; ++i) {
            PacketBuffer* pkt = allocate();
            if (!pkt) break;
            out_pkts[i] = pkt;
            ++allocated;
        }
        return allocated;
    }

    /**
     * @brief Free a batch of PacketBuffers.
     * @param pkts Array of packet pointers to free.
     * @param count Number of packets in the array.
     */
    void free_batch(PacketBuffer** pkts, size_t count) noexcept {
        if (!pkts || count == 0) return;
        for (size_t i = 0; i < count; ++i) {
            if (pkts[i]) {
                free(pkts[i]);
            }
        }
    }

    /**
     * @brief Check whether a PacketBuffer belongs to this pool's slab memory.
     */
    [[nodiscard]] bool is_from_this_pool(const PacketBuffer* pkt) const noexcept {
        return (pkt >= &slab_[0]) && (pkt < &slab_[PoolCapacity]);
    }

    // ------------------------------------------------------------------------
    // Capacity & Status Queries
    // ------------------------------------------------------------------------
    [[nodiscard]] static constexpr size_t capacity() noexcept {
        return PoolCapacity;
    }

    [[nodiscard]] size_t in_use() const noexcept {
        const int64_t used = in_use_count_.load(std::memory_order_relaxed);
        return (used > 0) ? static_cast<size_t>(used) : 0;
    }

    [[nodiscard]] size_t available() const noexcept {
        const size_t used = in_use();
        return (used <= PoolCapacity) ? (PoolCapacity - used) : 0;
    }

    [[nodiscard]] uint64_t total_allocations() const noexcept {
        return alloc_count_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t total_frees() const noexcept {
        return free_count_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t alloc_failures() const noexcept {
        return fail_count_.load(std::memory_order_relaxed);
    }

private:
    /**
     * @brief Static callback wired to `PacketBuffer::release_cb`.
     */
    static void pool_release_cb(PacketBuffer* pkt) noexcept {
        assert(pkt != nullptr && "Cannot release null PacketBuffer!");
        assert(pkt->user_data != nullptr && "PacketBuffer::user_data must point to MemoryPool!");
        auto* pool = static_cast<MemoryPool<PoolCapacity>*>(pkt->user_data);
        pool->free(pkt);
    }
};

using DefaultMemoryPool = MemoryPool<16384>;

} // namespace telecom::core
