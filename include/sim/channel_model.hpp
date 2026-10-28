#pragma once

/**
 * @file channel_model.hpp
 * @brief Realistic Wireless Channel Impairment Simulator & Dynamic MAC Scheduler.
 *
 * Implements:
 *   - Packet Loss Models:
 *       * Bernoulli Model: Random independent packet loss.
 *       * Gilbert-Elliott 2-State Markov Model: Bursty packet loss (Good vs Bad/Fading states).
 *   - Packet Reordering & Jitter:
 *       * Variable TTI delay queue causing out-of-order packet arrivals at the receiver.
 *   - Dynamic MAC Scheduler Stub:
 *       * Generates realistic per-TTI grants (100B - 10KB) to stress RLC segmentation.
 *   - Comprehensive Channel Telemetry.
 */

#include "../core/packet_buffer.hpp"
#include <cstdint>
#include <cstddef>
#include <vector>
#include <deque>
#include <random>

namespace telecom::sim {

using namespace telecom::core;

enum class LossModelType {
    NONE = 0,
    BERNOULLI,
    GILBERT_ELLIOTT
};

/**
 * @brief Gilbert-Elliott 2-State Markov Model parameters.
 */
struct GilbertElliottParams {
    double p_good_to_bad{0.05};  // Probability of transitioning from Good to Bad (r)
    double p_bad_to_good{0.30};  // Probability of transitioning from Bad to Good (p)
    double loss_prob_good{0.01}; // Loss probability in Good state (1%)
    double loss_prob_bad{0.70};  // Loss probability in Bad state (70% burst loss)
};

/**
 * @brief Channel Impairment Simulator Configuration.
 */
struct ChannelConfig {
    LossModelType        loss_model{LossModelType::BERNOULLI};
    double               bernoulli_loss_rate{0.05}; // 5% random drop
    GilbertElliottParams ge_params{};

    double               reorder_prob{0.10};        // 10% probability of being delayed
    uint32_t             min_delay_tti{1};          // Min delay in TTIs
    uint32_t             max_delay_tti{4};          // Max delay in TTIs
    uint32_t             random_seed{42};
};

/**
 * @brief Channel Impairment Simulator Class.
 */
class ChannelModel {
    ChannelConfig config_;

    std::mt19937                     rng_;
    std::uniform_real_distribution<> uniform_dist_{0.0, 1.0};

    // Gilbert-Elliott State (0 = Good, 1 = Bad)
    bool in_bad_state_{false};

    // Reordering / Jitter Delay Queue
    struct DelayedPacket {
        PacketBuffer* pkt{nullptr};
        uint64_t      release_tti{0};
    };
    std::deque<DelayedPacket> delay_queue_;
    uint64_t                  current_tti_{0};

    // Telemetry Statistics
    uint64_t total_input_{0};
    uint64_t total_passed_{0};
    uint64_t total_dropped_{0};
    uint64_t total_delayed_{0};

public:
    explicit ChannelModel(const ChannelConfig& cfg = ChannelConfig{})
        : config_(cfg), rng_(cfg.random_seed) {}

    ~ChannelModel() {
        // Clean up any remaining delayed packets
        for (auto& item : delay_queue_) {
            if (item.pkt) item.pkt->release();
        }
    }

    // Non-copyable, movable
    ChannelModel(const ChannelModel&) = delete;
    ChannelModel& operator=(const ChannelModel&) = delete;
    ChannelModel(ChannelModel&&) = default;
    ChannelModel& operator=(ChannelModel&&) = default;

    /**
     * @brief Transmit a packet through the channel.
     * Evaluates loss models and reordering delays.
     *
     * @param pkt PacketBuffer to transmit.
     * @param out_delivered Vector to collect immediately delivered packets.
     */
    void transmit(PacketBuffer* pkt, std::vector<PacketBuffer*>& out_delivered) noexcept {
        if (!pkt) return;
        ++total_input_;

        // 1. Evaluate Packet Loss
        if (should_drop_packet()) {
            ++total_dropped_;
            pkt->release(); // Dropped by physical layer
            return;
        }

        // 2. Evaluate Reordering & Jitter
        if (config_.reorder_prob > 0.0 && uniform_dist_(rng_) < config_.reorder_prob) {
            std::uniform_int_distribution<uint32_t> delay_dist(config_.min_delay_tti, config_.max_delay_tti);
            uint32_t delay = delay_dist(rng_);

            delay_queue_.push_back({pkt, current_tti_ + delay});
            ++total_delayed_;
            return;
        }

        // 3. Packet passed without delay
        ++total_passed_;
        out_delivered.push_back(pkt);
    }

    /**
     * @brief Advance time by 1 TTI (1 5G Slot / 1 ms).
     * Releases delayed packets whose expiration TTI has been reached.
     *
     * @param out_delivered Vector collecting packets released this TTI.
     */
    void step_tti(std::vector<PacketBuffer*>& out_delivered) noexcept {
        ++current_tti_;

        // Check delayed queue
        auto it = delay_queue_.begin();
        while (it != delay_queue_.end()) {
            if (it->release_tti <= current_tti_) {
                ++total_passed_;
                out_delivered.push_back(it->pkt);
                it = delay_queue_.erase(it);
            } else {
                ++it;
            }
        }

        // Update Gilbert-Elliott Markov State Transitions for the next TTI
        if (config_.loss_model == LossModelType::GILBERT_ELLIOTT) {
            if (in_bad_state_) {
                if (uniform_dist_(rng_) < config_.ge_params.p_bad_to_good) {
                    in_bad_state_ = false;
                }
            } else {
                if (uniform_dist_(rng_) < config_.ge_params.p_good_to_bad) {
                    in_bad_state_ = true;
                }
            }
        }
    }

    /**
     * @brief Flush all delayed packets immediately into out_delivered.
     */
    void flush(std::vector<PacketBuffer*>& out_delivered) noexcept {
        for (auto& item : delay_queue_) {
            ++total_passed_;
            out_delivered.push_back(item.pkt);
        }
        delay_queue_.clear();
    }

    // Telemetry queries
    [[nodiscard]] uint64_t total_input() const noexcept { return total_input_; }
    [[nodiscard]] uint64_t total_passed() const noexcept { return total_passed_; }
    [[nodiscard]] uint64_t total_dropped() const noexcept { return total_dropped_; }
    [[nodiscard]] uint64_t total_delayed() const noexcept { return total_delayed_; }
    [[nodiscard]] double actual_loss_rate() const noexcept {
        return (total_input_ > 0) ? (static_cast<double>(total_dropped_) / total_input_) : 0.0;
    }
    [[nodiscard]] bool is_in_bad_state() const noexcept { return in_bad_state_; }
    [[nodiscard]] size_t pending_delayed_packets() const noexcept { return delay_queue_.size(); }

private:
    bool should_drop_packet() noexcept {
        switch (config_.loss_model) {
            case LossModelType::BERNOULLI:
                return (uniform_dist_(rng_) < config_.bernoulli_loss_rate);

            case LossModelType::GILBERT_ELLIOTT: {
                double loss_prob = in_bad_state_ ? config_.ge_params.loss_prob_bad
                                                 : config_.ge_params.loss_prob_good;
                return (uniform_dist_(rng_) < loss_prob);
            }

            case LossModelType::NONE:
            default:
                return false;
        }
    }
};

// ============================================================================
// Dynamic MAC Scheduler Stub (For RLC Segmentation Stress Testing)
// ============================================================================
class DynamicMacScheduler {
    uint32_t min_grant_bytes_{100};
    uint32_t max_grant_bytes_{4000};
    std::mt19937 rng_;
    std::uniform_int_distribution<uint32_t> grant_dist_;

public:
    DynamicMacScheduler(uint32_t min_grant = 100, uint32_t max_grant = 4000, uint32_t seed = 12345)
        : min_grant_bytes_(min_grant),
          max_grant_bytes_(max_grant),
          rng_(seed),
          grant_dist_(min_grant, max_grant) {}

    /**
     * @brief Get MAC grant capacity allocated for the current 1 ms TTI.
     * @return Number of bytes allowed to transmit.
     */
    uint32_t get_grant() noexcept {
        return grant_dist_(rng_);
    }

    void set_range(uint32_t min_grant, uint32_t max_grant) noexcept {
        min_grant_bytes_ = min_grant;
        max_grant_bytes_ = max_grant;
        grant_dist_ = std::uniform_int_distribution<uint32_t>(min_grant, max_grant);
    }
};

} // namespace telecom::sim
