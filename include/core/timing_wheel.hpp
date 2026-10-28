#pragma once

/**
 * @file timing_wheel.hpp
 * @brief High-Speed Hierarchical Timing Wheel for 5G NR / LTE Layer-2 (RLC AM/UM).
 *
 * Telecom Fast-Path Requirement:
 *   RLC entities run thousands of concurrent timers (t-PollRetransmit, t-Reassembly,
 *   t-StatusProhibit). Operating system threads or std::priority_queue (O(log N))
 *   cause unacceptable latency and CPU cache thrashing.
 *
 * Architecture:
 *   - 4-Level Hierarchical Timing Wheel (HTW) based on Varghese & Lauck algorithm:
 *       Level 0: 256 slots (covers 0..255 ticks, e.g. 0..255 ms) -> 99% of RLC timers fall here!
 *       Level 1:  64 slots (covers up to 16,384 ticks ~ 16.38 seconds)
 *       Level 2:  64 slots (covers up to 1,048,576 ticks ~ 17.47 minutes)
 *       Level 3:  64 slots (covers up to 67,108,864 ticks ~ 18.64 hours)
 *   - O(1) Insertion: Direct bit-shift and mask hashing.
 *   - O(1) Cancellation: Intrusive doubly-linked list with generational TimerId.
 *   - O(1) Expiration: Amortized per tick. Cascading only on slot boundary rollover.
 *   - Pre-allocated Timer Pool: Zero dynamic allocations (`new`/`malloc`) on fast path.
 */

#include <cstddef>
#include <cstdint>
#include <cassert>
#include <vector>
#include <chrono>

namespace telecom::core {

using TimerId = uint64_t;
using TimerCallback = void(*)(void* arg);

static constexpr TimerId INVALID_TIMER_ID = 0;

template <size_t MaxTimers = 16384>
class alignas(64) TimingWheel {
    static_assert(MaxTimers >= 4, "MaxTimers must be at least 4");

    // ------------------------------------------------------------------------
    // Wheel Dimension Constants
    // ------------------------------------------------------------------------
    static constexpr size_t LVL0_BITS = 8;
    static constexpr size_t LVL0_SIZE = 1ULL << LVL0_BITS; // 256 slots
    static constexpr size_t LVL0_MASK = LVL0_SIZE - 1;

    static constexpr size_t LVLX_BITS = 6;
    static constexpr size_t LVLX_SIZE = 1ULL << LVLX_BITS; // 64 slots
    static constexpr size_t LVLX_MASK = LVLX_SIZE - 1;

    static constexpr size_t LVL1_SHIFT = LVL0_BITS;                     // 8
    static constexpr size_t LVL2_SHIFT = LVL0_BITS + LVLX_BITS;          // 14
    static constexpr size_t LVL3_SHIFT = LVL0_BITS + 2 * LVLX_BITS;      // 20

    static constexpr uint64_t LVL0_MAX = LVL0_SIZE;                     // 256
    static constexpr uint64_t LVL1_MAX = 1ULL << LVL2_SHIFT;            // 16,384
    static constexpr uint64_t LVL2_MAX = 1ULL << LVL3_SHIFT;            // 1,048,576
    static constexpr uint64_t LVL3_MAX = 1ULL << (LVL3_SHIFT + LVLX_BITS); // 67,108,864

    // ------------------------------------------------------------------------
    // Timer Entry Structure (Intrusive Doubly-Linked Node)
    // ------------------------------------------------------------------------
    struct TimerEntry {
        TimerId       id{INVALID_TIMER_ID};
        uint64_t      expires_tick{0};
        uint64_t      interval_ticks{0}; // 0 = one-shot, >0 = periodic
        TimerCallback callback{nullptr};
        void*         arg{nullptr};

        TimerEntry*   next{nullptr};
        TimerEntry*   prev{nullptr};

        uint8_t       wheel_level{0};
        uint16_t      wheel_slot{0};
        bool          active{false};
    };

    // ------------------------------------------------------------------------
    // Member Storage
    // ------------------------------------------------------------------------
    uint64_t current_tick_{0};
    uint64_t tick_duration_us_{1000}; // Default: 1 tick = 1000 us (1 ms / 5G Slot)

    // Wheel Slot Buckets (Head pointers for doubly linked list)
    TimerEntry* wheel0_[LVL0_SIZE]{};
    TimerEntry* wheel1_[LVLX_SIZE]{};
    TimerEntry* wheel2_[LVLX_SIZE]{};
    TimerEntry* wheel3_[LVLX_SIZE]{};

    // Pre-allocated Timer Pool & Free-List
    TimerEntry pool_[MaxTimers]{};
    uint32_t   free_indices_[MaxTimers]{};
    uint32_t   free_count_{MaxTimers};
    uint32_t   generation_[MaxTimers]{};

    // Statistics
    uint64_t total_scheduled_{0};
    uint64_t total_expired_{0};
    uint64_t total_cancelled_{0};
    size_t   active_timers_{0};

public:
    /**
     * @brief Construct a new Hierarchical Timing Wheel.
     * @param tick_duration_us Microseconds per tick (default 1000 us = 1 ms).
     */
    explicit TimingWheel(uint64_t tick_duration_us = 1000) noexcept
        : tick_duration_us_(tick_duration_us) {
        // Initialize pool free-list
        for (uint32_t i = 0; i < MaxTimers; ++i) {
            free_indices_[i] = i;
            generation_[i] = 1; // Generation starts at 1
            pool_[i].id = INVALID_TIMER_ID;
            pool_[i].active = false;
        }
    }

    ~TimingWheel() = default;

    // Non-copyable, non-movable
    TimingWheel(const TimingWheel&) = delete;
    TimingWheel& operator=(const TimingWheel&) = delete;
    TimingWheel(TimingWheel&&) = delete;
    TimingWheel& operator=(TimingWheel&&) = delete;

    /**
     * @brief Schedule a one-shot timer.
     * @param delay_ticks Number of ticks from now when the timer should fire (minimum 1).
     * @param cb Callback function to invoke on expiration.
     * @param arg User context pointer passed to callback.
     * @return TimerId Unique handle for cancellation, or INVALID_TIMER_ID if pool is exhausted.
     */
    TimerId schedule(uint64_t delay_ticks, TimerCallback cb, void* arg) noexcept {
        return schedule_internal(delay_ticks, 0, cb, arg);
    }

    /**
     * @brief Schedule a periodic timer.
     * @param interval_ticks Repetition interval in ticks.
     * @param cb Callback function.
     * @param arg User context pointer.
     * @return TimerId Unique handle.
     */
    TimerId schedule_periodic(uint64_t interval_ticks, TimerCallback cb, void* arg) noexcept {
        return schedule_internal(interval_ticks, interval_ticks, cb, arg);
    }

    /**
     * @brief Cancel an active timer in O(1) time.
     * @param id TimerId returned by schedule().
     * @return true if timer was found and cancelled, false if already expired or invalid.
     */
    bool cancel(TimerId id) noexcept {
        if (id == INVALID_TIMER_ID) return false;

        const uint32_t index = static_cast<uint32_t>(id & 0xFFFFFFFFULL);
        const uint32_t gen   = static_cast<uint32_t>(id >> 32);

        if (index >= MaxTimers || generation_[index] != gen) {
            return false; // Stale or invalid ID
        }

        TimerEntry* entry = &pool_[index];
        if (!entry->active || entry->id != id) {
            return false;
        }

        // Unlink from wheel slot
        unlink_entry(entry);

        entry->active = false;
        entry->id = INVALID_TIMER_ID;
        generation_[index]++; // Invalidate future references with this ID

        // Return to free pool
        free_indices_[free_count_++] = index;
        --active_timers_;
        ++total_cancelled_;
        return true;
    }

    /**
     * @brief Advance the timing wheel by num_ticks (typically 1 tick per 5G Slot/TTI).
     * @param num_ticks Number of ticks to advance (default 1).
     * @return Number of timers that expired and fired during this advance.
     */
    size_t tick(uint64_t num_ticks = 1) noexcept {
        size_t fired_count = 0;

        for (uint64_t t = 0; t < num_ticks; ++t) {
            ++current_tick_;

            const uint32_t l0_slot = static_cast<uint32_t>(current_tick_ & LVL0_MASK);

            // Cascade higher levels when lower levels wrap around
            if (l0_slot == 0) {
                cascade_wheel();
            }

            // Pop all expired timers from current Level 0 slot
            TimerEntry* head = wheel0_[l0_slot];
            wheel0_[l0_slot] = nullptr;

            // Process expired timers
            while (head) {
                TimerEntry* curr = head;
                head = head->next;

                curr->next = nullptr;
                curr->prev = nullptr;

                if (!curr->active) continue;

                // Fire callback
                if (curr->callback) {
                    curr->callback(curr->arg);
                }
                ++fired_count;
                ++total_expired_;

                if (curr->interval_ticks > 0 && curr->active) {
                    // Reschedule periodic timer
                    curr->expires_tick = current_tick_ + curr->interval_ticks;
                    insert_entry(curr);
                } else {
                    // One-shot timer: recycle back to free pool
                    const uint32_t index = static_cast<uint32_t>(curr - &pool_[0]);
                    curr->active = false;
                    curr->id = INVALID_TIMER_ID;
                    generation_[index]++;
                    free_indices_[free_count_++] = index;
                    --active_timers_;
                }
            }
        }

        return fired_count;
    }

    /**
     * @brief Advance wheel based on elapsed wall-clock nanoseconds.
     * @param elapsed_ns Elapsed time in nanoseconds.
     * @return Number of timers fired.
     */
    size_t advance_time_ns(uint64_t elapsed_ns) noexcept {
        const uint64_t ticks = elapsed_ns / (tick_duration_us_ * 1000ULL);
        return (ticks > 0) ? tick(ticks) : 0;
    }

    // ------------------------------------------------------------------------
    // Status & Inspection Queries
    // ------------------------------------------------------------------------
    [[nodiscard]] uint64_t current_tick() const noexcept { return current_tick_; }
    [[nodiscard]] size_t active_timers() const noexcept { return active_timers_; }
    [[nodiscard]] uint64_t total_scheduled() const noexcept { return total_scheduled_; }
    [[nodiscard]] uint64_t total_expired() const noexcept { return total_expired_; }
    [[nodiscard]] uint64_t total_cancelled() const noexcept { return total_cancelled_; }
    [[nodiscard]] static constexpr size_t capacity() noexcept { return MaxTimers; }

private:
    TimerId schedule_internal(uint64_t delay_ticks, uint64_t interval_ticks, TimerCallback cb, void* arg) noexcept {
        if (delay_ticks == 0) delay_ticks = 1; // Minimum 1 tick
        if (free_count_ == 0) return INVALID_TIMER_ID; // Pool full

        // Claim slot from pool
        const uint32_t index = free_indices_[--free_count_];
        TimerEntry* entry = &pool_[index];

        const uint32_t gen = generation_[index];
        const TimerId id = (static_cast<uint64_t>(gen) << 32) | index;

        entry->id = id;
        entry->expires_tick = current_tick_ + delay_ticks;
        entry->interval_ticks = interval_ticks;
        entry->callback = cb;
        entry->arg = arg;
        entry->active = true;

        insert_entry(entry);

        ++active_timers_;
        ++total_scheduled_;
        return id;
    }

    void insert_entry(TimerEntry* entry) noexcept {
        const uint64_t diff = (entry->expires_tick > current_tick_)
                                  ? (entry->expires_tick - current_tick_)
                                  : 0;

        uint8_t level = 0;
        uint16_t slot = 0;

        if (diff < LVL0_MAX) {
            level = 0;
            slot = static_cast<uint16_t>(entry->expires_tick & LVL0_MASK);
            link_entry(&wheel0_[slot], entry);
        } else if (diff < LVL1_MAX) {
            level = 1;
            slot = static_cast<uint16_t>((entry->expires_tick >> LVL1_SHIFT) & LVLX_MASK);
            link_entry(&wheel1_[slot], entry);
        } else if (diff < LVL2_MAX) {
            level = 2;
            slot = static_cast<uint16_t>((entry->expires_tick >> LVL2_SHIFT) & LVLX_MASK);
            link_entry(&wheel2_[slot], entry);
        } else {
            level = 3;
            slot = static_cast<uint16_t>((entry->expires_tick >> LVL3_SHIFT) & LVLX_MASK);
            link_entry(&wheel3_[slot], entry);
        }

        entry->wheel_level = level;
        entry->wheel_slot = slot;
    }

    void link_entry(TimerEntry** bucket_head, TimerEntry* entry) noexcept {
        entry->next = *bucket_head;
        entry->prev = nullptr;
        if (*bucket_head) {
            (*bucket_head)->prev = entry;
        }
        *bucket_head = entry;
    }

    void unlink_entry(TimerEntry* entry) noexcept {
        TimerEntry** bucket_head = get_bucket_head(entry->wheel_level, entry->wheel_slot);

        if (entry->prev) {
            entry->prev->next = entry->next;
        } else if (bucket_head && *bucket_head == entry) {
            *bucket_head = entry->next;
        }

        if (entry->next) {
            entry->next->prev = entry->prev;
        }

        entry->next = nullptr;
        entry->prev = nullptr;
    }

    TimerEntry** get_bucket_head(uint8_t level, uint16_t slot) noexcept {
        switch (level) {
            case 0: return (slot < LVL0_SIZE) ? &wheel0_[slot] : nullptr;
            case 1: return (slot < LVLX_SIZE) ? &wheel1_[slot] : nullptr;
            case 2: return (slot < LVLX_SIZE) ? &wheel2_[slot] : nullptr;
            case 3: return (slot < LVLX_SIZE) ? &wheel3_[slot] : nullptr;
            default: return nullptr;
        }
    }

    /**
     * @brief Cascade entries down from higher level wheels when a wheel wraps around.
     */
    void cascade_wheel() noexcept {
        uint32_t slot1 = static_cast<uint32_t>((current_tick_ >> LVL1_SHIFT) & LVLX_MASK);
        cascade_bucket(&wheel1_[slot1]);

        if (slot1 == 0) {
            uint32_t slot2 = static_cast<uint32_t>((current_tick_ >> LVL2_SHIFT) & LVLX_MASK);
            cascade_bucket(&wheel2_[slot2]);

            if (slot2 == 0) {
                uint32_t slot3 = static_cast<uint32_t>((current_tick_ >> LVL3_SHIFT) & LVLX_MASK);
                cascade_bucket(&wheel3_[slot3]);
            }
        }
    }

    void cascade_bucket(TimerEntry** bucket_head) noexcept {
        TimerEntry* curr = *bucket_head;
        *bucket_head = nullptr;

        while (curr) {
            TimerEntry* next = curr->next;
            curr->next = nullptr;
            curr->prev = nullptr;
            insert_entry(curr); // Re-insert closer to Level 0
            curr = next;
        }
    }
};

using DefaultTimingWheel = TimingWheel<16384>;

} // namespace telecom::core
