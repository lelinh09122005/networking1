#pragma once

/**
 * @file spsc_ring_queue.hpp
 * @brief Lock-Free Single-Producer Single-Consumer (SPSC) Ring Buffer.
 *
 * Designed for ultra-high-speed inter-thread packet transfer in telecom pipelines
 * (e.g. Traffic Generator -> Protocol Engine -> Channel Simulator).
 *
 * Key Architecture:
 *   - Lock-free, wait-free O(1) Push and Pop operations.
 *   - Independent 64-byte Cache Line alignment for Producer and Consumer indices:
 *     Prevents CPU cache bouncing / False Sharing across cores.
 *   - Power-of-2 capacity: modulo replaced by single-cycle bitwise AND (idx & MASK).
 *   - Local index caching (cached_read_idx_ / cached_write_idx_):
 *     Avoids inter-core atomic cache invalidation on 99% of fast-path operations.
 *   - Vector / Batch packet transfer API (push_batch / pop_batch) for DPDK-like throughput.
 */

#include <cstddef>
#include <cstdint>
#include <atomic>
#include <cassert>
#include <utility>
#include <type_traits>

namespace telecom::core {

template <typename T, size_t Capacity = 4096>
class alignas(64) SpscRingQueue {
    static_assert((Capacity >= 2) && ((Capacity & (Capacity - 1)) == 0),
                  "SpscRingQueue Capacity must be a power of 2 and >= 2!");
    static constexpr size_t MASK = Capacity - 1;

private:
    // ------------------------------------------------------------------------
    // Producer Cache Line (Modified only by the Producer thread)
    // ------------------------------------------------------------------------
    alignas(64) std::atomic<size_t> write_idx_{0};
    size_t cached_read_idx_{0}; // Producer's shadow copy of Consumer's read_idx_
    uint8_t _pad_producer_[64 - sizeof(std::atomic<size_t>) - sizeof(size_t)]{};

    // ------------------------------------------------------------------------
    // Consumer Cache Line (Modified only by the Consumer thread)
    // ------------------------------------------------------------------------
    alignas(64) std::atomic<size_t> read_idx_{0};
    size_t cached_write_idx_{0}; // Consumer's shadow copy of Producer's write_idx_
    uint8_t _pad_consumer_[64 - sizeof(std::atomic<size_t>) - sizeof(size_t)]{};

    // ------------------------------------------------------------------------
    // Ring Storage (Aligned to 64 bytes)
    // ------------------------------------------------------------------------
    alignas(64) T storage_[Capacity];

public:
    SpscRingQueue() noexcept {
        write_idx_.store(0, std::memory_order_relaxed);
        read_idx_.store(0, std::memory_order_relaxed);
    }

    ~SpscRingQueue() = default;

    // Non-copyable, non-movable to guarantee address stability for lock-free access
    SpscRingQueue(const SpscRingQueue&) = delete;
    SpscRingQueue& operator=(const SpscRingQueue&) = delete;
    SpscRingQueue(SpscRingQueue&&) = delete;
    SpscRingQueue& operator=(SpscRingQueue&&) = delete;

    /**
     * @brief Push a single element into the queue (Producer only).
     * @param item Element to push.
     * @return true if pushed successfully, false if queue is full.
     */
    bool push(const T& item) noexcept {
        const size_t w = write_idx_.load(std::memory_order_relaxed);
        // Fast-path: Check against local cached read index first
        if (w - cached_read_idx_ >= Capacity) {
            // Shadow copy says queue is full; reload from consumer's atomic read_idx_
            cached_read_idx_ = read_idx_.load(std::memory_order_acquire);
            if (w - cached_read_idx_ >= Capacity) {
                return false; // Queue is genuinely full
            }
        }

        storage_[w & MASK] = item;
        write_idx_.store(w + 1, std::memory_order_release);
        return true;
    }

    bool push(T&& item) noexcept {
        const size_t w = write_idx_.load(std::memory_order_relaxed);
        if (w - cached_read_idx_ >= Capacity) {
            cached_read_idx_ = read_idx_.load(std::memory_order_acquire);
            if (w - cached_read_idx_ >= Capacity) {
                return false;
            }
        }

        storage_[w & MASK] = std::move(item);
        write_idx_.store(w + 1, std::memory_order_release);
        return true;
    }

    /**
     * @brief Pop a single element from the queue (Consumer only).
     * @param item Out reference to store popped element.
     * @return true if popped successfully, false if queue is empty.
     */
    bool pop(T& item) noexcept {
        const size_t r = read_idx_.load(std::memory_order_relaxed);
        // Fast-path: Check against local cached write index first
        if (r == cached_write_idx_) {
            // Shadow copy says queue is empty; reload from producer's atomic write_idx_
            cached_write_idx_ = write_idx_.load(std::memory_order_acquire);
            if (r == cached_write_idx_) {
                return false; // Queue is genuinely empty
            }
        }

        item = std::move(storage_[r & MASK]);
        read_idx_.store(r + 1, std::memory_order_release);
        return true;
    }

    /**
     * @brief Push a batch of elements (Vector Packet Processing, Producer only).
     * @param items Pointer to array of items.
     * @param count Number of items to push.
     * @return Actual number of items successfully pushed (0 <= pushed <= count).
     */
    size_t push_batch(const T* items, size_t count) noexcept {
        if (!items || count == 0) return 0;

        const size_t w = write_idx_.load(std::memory_order_relaxed);
        size_t available = Capacity - (w - cached_read_idx_);

        if (available < count) {
            cached_read_idx_ = read_idx_.load(std::memory_order_acquire);
            available = Capacity - (w - cached_read_idx_);
        }

        const size_t to_push = (count < available) ? count : available;
        if (to_push == 0) return 0;

        for (size_t i = 0; i < to_push; ++i) {
            storage_[(w + i) & MASK] = items[i];
        }

        // Single atomic store with release order for the entire batch
        write_idx_.store(w + to_push, std::memory_order_release);
        return to_push;
    }

    /**
     * @brief Pop a batch of elements (Vector Packet Processing, Consumer only).
     * @param items Destination array.
     * @param count Maximum number of items to pop.
     * @return Actual number of items popped (0 <= popped <= count).
     */
    size_t pop_batch(T* items, size_t count) noexcept {
        if (!items || count == 0) return 0;

        const size_t r = read_idx_.load(std::memory_order_relaxed);
        size_t available = cached_write_idx_ - r;

        if (available < count) {
            cached_write_idx_ = write_idx_.load(std::memory_order_acquire);
            available = cached_write_idx_ - r;
        }

        const size_t to_pop = (count < available) ? count : available;
        if (to_pop == 0) return 0;

        for (size_t i = 0; i < to_pop; ++i) {
            items[i] = std::move(storage_[(r + i) & MASK]);
        }

        // Single atomic store with release order for the entire batch
        read_idx_.store(r + to_pop, std::memory_order_release);
        return to_pop;
    }

    /**
     * @brief Current number of elements in the queue (approximate when called across threads).
     */
    [[nodiscard]] size_t size() const noexcept {
        const size_t w = write_idx_.load(std::memory_order_relaxed);
        const size_t r = read_idx_.load(std::memory_order_relaxed);
        return (w >= r) ? (w - r) : 0;
    }

    /**
     * @brief Check if queue is empty (approximate if Producer is running).
     */
    [[nodiscard]] bool empty() const noexcept {
        return read_idx_.load(std::memory_order_relaxed) == write_idx_.load(std::memory_order_relaxed);
    }

    /**
     * @brief Check if queue is full (approximate if Consumer is running).
     */
    [[nodiscard]] bool full() const noexcept {
        return size() >= Capacity;
    }

    /**
     * @brief Maximum capacity of this ring queue.
     */
    [[nodiscard]] static constexpr size_t capacity() noexcept {
        return Capacity;
    }

    /**
     * @brief Clear queue (Call ONLY when no concurrent push/pop is active).
     */
    void clear() noexcept {
        write_idx_.store(0, std::memory_order_relaxed);
        read_idx_.store(0, std::memory_order_relaxed);
        cached_read_idx_ = 0;
        cached_write_idx_ = 0;
    }
};

} // namespace telecom::core
