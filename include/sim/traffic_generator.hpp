#pragma once

/**
 * @file traffic_generator.hpp
 * @brief High-Throughput Synthetic & Trace-Driven Traffic Generator for Telecom Testing.
 *
 * Implements:
 *   - CBR (Constant Bit Rate) Traffic Profile (e.g. VoNR / G.711 / Sensor frames).
 *   - Bursty & Poisson Traffic Profile (e.g. eMBB Web browsing, Video streaming).
 *   - Internet Bimodal Traffic Profile (40B ACK + 1500B MTU).
 *   - Nanosecond-precision Hardware/Steady Timestamping (`timestamp_ns`).
 *   - Latency Statistics Tracker: Min, Max, Mean, and Percentiles (p50, p95, p99, p99.9).
 */

#include "../core/packet_buffer.hpp"
#include "../core/memory_pool.hpp"
#include <cstdint>
#include <cstddef>
#include <vector>
#include <chrono>
#include <random>
#include <algorithm>
#include <numeric>

namespace telecom::sim {

using namespace telecom::core;

enum class TrafficPattern {
    CBR,            // Constant Bit Rate (fixed size, fixed rate)
    BURSTY_POISSON, // Poisson distributed arrivals with bursty sizes
    BIMODAL_INTERNET// 50% small ACKs (40B), 50% full MTU (1400B)
};

/**
 * @brief Configuration for Traffic Generator.
 */
struct TrafficGenConfig {
    TrafficPattern pattern{TrafficPattern::BURSTY_POISSON};
    uint16_t       fixed_payload_size{256}; // For CBR
    uint16_t       min_payload_size{64};
    uint16_t       max_payload_size{1400};
    uint32_t       default_teid{0x1001};
    uint8_t        default_qfi{9};
    uint32_t       random_seed{98765};
};

/**
 * @brief Latency Analysis Report.
 */
struct LatencyReport {
    size_t sample_count{0};
    double min_ns{0.0};
    double max_ns{0.0};
    double mean_ns{0.0};
    double p50_ns{0.0};
    double p95_ns{0.0};
    double p99_ns{0.0};
    double p99_9_ns{0.0};
};

/**
 * @brief High-Resolution Latency Tracker.
 */
class LatencyTracker {
    std::vector<double> samples_;

public:
    explicit LatencyTracker(size_t reserve_capacity = 100'000) {
        samples_.reserve(reserve_capacity);
    }

    void record_latency_ns(double latency_ns) noexcept {
        samples_.push_back(latency_ns);
    }

    void record_packet(const PacketBuffer& pkt, uint64_t now_ns = 0) noexcept {
        if (pkt.timestamp_ns == 0) return;
        if (now_ns == 0) {
            now_ns = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
        }
        if (now_ns >= pkt.timestamp_ns) {
            record_latency_ns(static_cast<double>(now_ns - pkt.timestamp_ns));
        }
    }

    [[nodiscard]] LatencyReport generate_report() {
        if (samples_.empty()) return LatencyReport{};

        std::vector<double> sorted = samples_;
        std::sort(sorted.begin(), sorted.end());

        const size_t n = sorted.size();
        const double sum = std::accumulate(sorted.begin(), sorted.end(), 0.0);

        LatencyReport rep;
        rep.sample_count = n;
        rep.min_ns  = sorted.front();
        rep.max_ns  = sorted.back();
        rep.mean_ns = sum / static_cast<double>(n);

        rep.p50_ns   = sorted[static_cast<size_t>(n * 0.50)];
        rep.p95_ns   = sorted[static_cast<size_t>(n * 0.95)];
        rep.p99_ns   = sorted[static_cast<size_t>(n * 0.99)];
        rep.p99_9_ns = sorted[std::min(static_cast<size_t>(n * 0.999), n - 1)];

        return rep;
    }

    void reset() noexcept {
        samples_.clear();
    }

    [[nodiscard]] size_t size() const noexcept { return samples_.size(); }
};

/**
 * @brief Traffic Generator Class.
 */
template <size_t PoolCap = 16384>
class TrafficGenerator {
    TrafficGenConfig    config_;
    MemoryPool<PoolCap>& pool_;

    std::mt19937                     rng_;
    std::uniform_int_distribution<uint16_t> size_dist_;
    std::uniform_real_distribution<> uniform_zero_one_{0.0, 1.0};

    uint32_t next_seq_num_{0};
    uint64_t total_generated_{0};
    uint64_t total_bytes_{0};

public:
    TrafficGenerator(const TrafficGenConfig& cfg, MemoryPool<PoolCap>& pool)
        : config_(cfg),
          pool_(pool),
          rng_(cfg.random_seed),
          size_dist_(cfg.min_payload_size, cfg.max_payload_size) {}

    /**
     * @brief Generate a single synthetic user plane IP packet / SDU.
     * @return Fresh PacketBuffer allocated from MemoryPool with timestamp and payload.
     */
    [[nodiscard]] PacketBuffer* generate_packet() noexcept {
        PacketBuffer* pkt = pool_.allocate();
        if (!pkt) return nullptr;

        const uint16_t payload_len = determine_payload_size();
        pkt->reset();

        // Fill synthetic payload
        uint8_t* ptr = pkt->append(payload_len);
        for (uint16_t i = 0; i < payload_len; ++i) {
            ptr[i] = static_cast<uint8_t>((next_seq_num_ + i) & 0xFF);
        }

        // Attach telemetry & routing metadata
        pkt->seq_num = next_seq_num_++;
        pkt->teid_or_rnti = config_.default_teid;
        pkt->qfi = config_.default_qfi;
        pkt->timestamp_ns = get_current_time_ns();

        ++total_generated_;
        total_bytes_ += payload_len;
        return pkt;
    }

    /**
     * @brief Generate a batch of synthetic packets (Vector Traffic Generation).
     * @param out_pkts Array to store generated packet pointers.
     * @param count Number of packets to generate.
     * @return Actual number of packets generated.
     */
    size_t generate_batch(PacketBuffer** out_pkts, size_t count) noexcept {
        if (!out_pkts || count == 0) return 0;
        size_t generated = 0;
        for (size_t i = 0; i < count; ++i) {
            PacketBuffer* pkt = generate_packet();
            if (!pkt) break;
            out_pkts[i] = pkt;
            ++generated;
        }
        return generated;
    }

    [[nodiscard]] uint64_t total_generated_packets() const noexcept { return total_generated_; }
    [[nodiscard]] uint64_t total_generated_bytes() const noexcept { return total_bytes_; }
    [[nodiscard]] uint32_t current_seq_num() const noexcept { return next_seq_num_; }

    static inline uint64_t get_current_time_ns() noexcept {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
    }

private:
    uint16_t determine_payload_size() noexcept {
        switch (config_.pattern) {
            case TrafficPattern::CBR:
                return config_.fixed_payload_size;

            case TrafficPattern::BIMODAL_INTERNET:
                // 50% small ACKs (40 bytes), 50% full MTU packets (1400 bytes)
                return (uniform_zero_one_(rng_) < 0.5) ? 40 : 1400;

            case TrafficPattern::BURSTY_POISSON:
            default:
                return size_dist_(rng_);
        }
    }
};

using DefaultTrafficGenerator = TrafficGenerator<16384>;

} // namespace telecom::sim
