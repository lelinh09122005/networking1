#pragma once

/**
 * @file rlc_am_entity.hpp
 * @brief High-Speed 3GPP TS 38.322 5G NR Layer-2 RLC (Radio Link Control) Protocol Entity.
 *
 * Implements Acknowledged Mode (RLC AM) State Machine, Segmentation, Reassembly & ARQ:
 *   - TX Engine: SDU buffering, MAC Grant segmentation, SI/SN/SO framing, Polling bit.
 *   - Retransmission Buffer: ARQ retransmit queue prioritized on MAC grants.
 *   - RX Engine: Sliding window, Out-of-order reordering, SDU Fragment Reassembly.
 *   - ARQ Engine: STATUS PDU generation (ACK_SN, NACK_SN) and processing.
 *   - High-Speed Timer Wheel Integration: t-PollRetransmit, t-Reassembly, t-StatusProhibit.
 */

#include "../core/packet_buffer.hpp"
#include "../core/memory_pool.hpp"
#include "../core/timing_wheel.hpp"

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cassert>
#include <vector>
#include <deque>
#include <algorithm>

namespace telecom::protocol {

using namespace telecom::core;

// ============================================================================
// 3GPP TS 38.322 RLC Constants & Parameters
// ============================================================================
namespace RlcConstants {
    static constexpr uint16_t SN_MODULO       = 4096; // 12-bit Sequence Number space (2^12)
    static constexpr uint16_t SN_MASK         = 4095;
    static constexpr uint16_t AM_WINDOW_SIZE  = 2048; // Half the SN space

    // Segmentation Information (SI) Field (2 bits)
    static constexpr uint8_t SI_FULL_SDU      = 0x00; // Complete SDU (no segmentation)
    static constexpr uint8_t SI_FIRST_SEGMENT = 0x01; // First segment of SDU
    static constexpr uint8_t SI_LAST_SEGMENT  = 0x02; // Last segment of SDU
    static constexpr uint8_t SI_MID_SEGMENT   = 0x03; // Middle segment of SDU

    // Control PDU Types (CPT)
    static constexpr uint8_t CPT_STATUS       = 0x00; // STATUS PDU
}

// Sequence Number Modulo Comparison Helpers (Sliding Window Arithmetic)
inline bool sn_in_window(uint16_t sn, uint16_t window_lower, uint16_t window_size = RlcConstants::AM_WINDOW_SIZE) noexcept {
    return ((sn - window_lower) & RlcConstants::SN_MASK) < window_size;
}

inline uint16_t sn_diff(uint16_t sn_hi, uint16_t sn_lo) noexcept {
    return (sn_hi - sn_lo) & RlcConstants::SN_MASK;
}

inline uint16_t sn_next(uint16_t sn) noexcept {
    return (sn + 1) & RlcConstants::SN_MASK;
}

// ============================================================================
// 3GPP TS 38.322 Packed Wire Protocol Headers
// ============================================================================
#pragma pack(push, 1)

/**
 * @brief AMD PDU Base Header with 12-bit SN (2 bytes).
 *
 * Byte 0: [D/C: 1b] [P: 1b] [SI: 2b] [SN_hi: 4b]
 * Byte 1: [SN_lo: 8b]
 */
struct RlcAmHeader12 {
    uint8_t byte0;
    uint8_t byte1;

    [[nodiscard]] inline bool is_data() const noexcept { return (byte0 & 0x80) != 0; }
    [[nodiscard]] inline bool poll() const noexcept { return (byte0 & 0x40) != 0; }
    [[nodiscard]] inline uint8_t si() const noexcept { return (byte0 >> 4) & 0x03; }
    [[nodiscard]] inline uint16_t sn() const noexcept {
        return (static_cast<uint16_t>(byte0 & 0x0F) << 8) | byte1;
    }

    inline void set(bool is_data, bool poll, uint8_t si, uint16_t sn) noexcept {
        byte0 = (is_data ? 0x80 : 0x00) |
                (poll ? 0x40 : 0x00) |
                ((si & 0x03) << 4) |
                static_cast<uint8_t>((sn >> 8) & 0x0F);
        byte1 = static_cast<uint8_t>(sn & 0xFF);
    }
};

/**
 * @brief Segment Offset (SO) Field (16 bits) present when SI == 10 or 11.
 */
struct RlcSegmentOffset {
    uint16_t so; // Big-Endian
};

/**
 * @brief STATUS PDU Header with 12-bit SN (3 bytes base).
 *
 * Byte 0: [D/C: 1b = 0] [CPT: 3b = 000] [ACK_SN_hi: 4b]
 * Byte 1: [ACK_SN_lo: 8b]
 * Byte 2: [E1: 1b] [Reserved: 7b]
 */
struct RlcStatusHeader12 {
    uint8_t byte0;
    uint8_t byte1;
    uint8_t byte2;

    [[nodiscard]] inline uint16_t ack_sn() const noexcept {
        return (static_cast<uint16_t>(byte0 & 0x0F) << 8) | byte1;
    }
    [[nodiscard]] inline bool has_nack() const noexcept { return (byte2 & 0x80) != 0; }

    inline void set(uint16_t ack_sn, bool has_nack) noexcept {
        byte0 = static_cast<uint8_t>((ack_sn >> 8) & 0x0F); // D/C=0, CPT=000
        byte1 = static_cast<uint8_t>(ack_sn & 0xFF);
        byte2 = has_nack ? 0x80 : 0x00;
    }
};

/**
 * @brief NACK block in STATUS PDU (2 bytes).
 */
struct RlcNackBlock12 {
    uint8_t byte0; // [NACK_SN_hi: 4b] [E1: 1b] [E2: 1b] [E3: 1b] [Reserved: 1b]
    uint8_t byte1; // [NACK_SN_lo: 8b]

    [[nodiscard]] inline uint16_t nack_sn() const noexcept {
        return (static_cast<uint16_t>(byte0 >> 4) << 8) | byte1;
    }
    [[nodiscard]] inline bool has_next_nack() const noexcept { return (byte0 & 0x08) != 0; }

    inline void set(uint16_t nack_sn, bool has_more_nacks) noexcept {
        byte0 = static_cast<uint8_t>(((nack_sn >> 8) & 0x0F) << 4) | (has_more_nacks ? 0x08 : 0x00);
        byte1 = static_cast<uint8_t>(nack_sn & 0xFF);
    }
};

#pragma pack(pop)

static_assert(sizeof(RlcAmHeader12) == 2, "RlcAmHeader12 must be exactly 2 bytes");
static_assert(sizeof(RlcSegmentOffset) == 2, "RlcSegmentOffset must be exactly 2 bytes");
static_assert(sizeof(RlcStatusHeader12) == 3, "RlcStatusHeader12 must be exactly 3 bytes");
static_assert(sizeof(RlcNackBlock12) == 2, "RlcNackBlock12 must be exactly 2 bytes");

// ============================================================================
// RLC AM Configuration
// ============================================================================
struct RlcAmConfig {
    uint32_t rnti{1001};             // Radio Network Temporary Identifier (UE ID)
    uint8_t  lcid{4};                // Logical Channel Identifier
    uint16_t poll_pdu{16};           // Trigger poll every 16 PDUs
    uint32_t poll_byte{65536};       // Trigger poll every 64 KB
    uint16_t max_retx_threshold{4};  // Maximum retransmission attempts before RLF
    uint64_t t_poll_retransmit_ticks{20}; // Timer duration in ticks (e.g. 20 ms)
    uint64_t t_reassembly_ticks{15};      // Timer duration in ticks (e.g. 15 ms)
    uint64_t t_status_prohibit_ticks{10}; // Timer duration in ticks (e.g. 10 ms)
};

// ============================================================================
// Layer-2 RLC AM Entity Class
// ============================================================================
template <size_t PoolCap = 16384, size_t TimerCap = 16384>
class RlcAmEntity {
    RlcAmConfig config_;
    MemoryPool<PoolCap>&   pool_;
    TimingWheel<TimerCap>& timer_wheel_;

    // ------------------------------------------------------------------------
    // TX State Variables (3GPP TS 38.322 Section 7.1)
    // ------------------------------------------------------------------------
    uint16_t tx_next_{0};            // SN of next AMD PDU to be transmitted
    uint16_t tx_next_ack_{0};        // Lower edge of transmitting window
    uint16_t poll_sn_{0};            // Most recent SN for which a poll was sent
    uint16_t pdu_since_poll_{0};     // Counter for poll_pdu trigger
    uint32_t byte_since_poll_{0};    // Counter for poll_byte trigger

    TimerId  t_poll_retransmit_id_{INVALID_TIMER_ID};

    // TX SDU Submission Queue (Incoming from PDCP)
    struct TxSduEntry {
        PacketBuffer* sdu{nullptr};
        uint16_t      offset{0};     // Offset in SDU already segmented
    };
    std::deque<TxSduEntry> tx_sdu_queue_;

    // Retransmission Buffer: keeps sent PDUs until positively acknowledged
    struct RetxEntry {
        PacketBuffer* pdu{nullptr};
        uint16_t      sn{0};
        uint16_t      retx_count{0};
        bool          needs_retx{false};
    };
    RetxEntry retx_buffer_[RlcConstants::SN_MODULO]{};
    std::deque<uint16_t> retx_queue_; // Priority queue for pending retransmissions

    // ------------------------------------------------------------------------
    // RX State Variables (3GPP TS 38.322 Section 7.1)
    // ------------------------------------------------------------------------
    uint16_t rx_next_{0};            // Lowest SN expected in-sequence
    uint16_t rx_next_highest_{0};    // SN following highest received PDU
    uint16_t rx_highest_status_{0};  // Highest SN for STATUS PDU reporting
    uint16_t rx_next_status_trigger_{0};

    TimerId  t_reassembly_id_{INVALID_TIMER_ID};
    TimerId  t_status_prohibit_id_{INVALID_TIMER_ID};
    bool     status_prohibited_{false};
    bool     status_report_needed_{false};

    // Out-of-order Reception Buffer (Reassembly Buffer)
    struct RxSegment {
        uint16_t offset{0};
        uint16_t length{0};
        bool     is_last{false};
        PacketBuffer* pkt{nullptr};
    };

    struct RxSduSlot {
        bool                   received{false};
        bool                   is_segmented{false};
        uint16_t               total_sdu_len{0};
        std::vector<RxSegment> segments;
    };
    RxSduSlot rx_slots_[RlcConstants::SN_MODULO]{};

    // Telemetry Statistics
    uint64_t total_sdu_in_{0};
    uint64_t total_sdu_out_{0};
    uint64_t total_pdu_tx_{0};
    uint64_t total_pdu_retx_{0};
    uint64_t total_pdu_rx_{0};
    uint64_t total_status_pdu_tx_{0};
    uint64_t total_status_pdu_rx_{0};

public:
    RlcAmEntity(const RlcAmConfig& cfg, MemoryPool<PoolCap>& pool, TimingWheel<TimerCap>& tw) noexcept
        : config_(cfg), pool_(pool), timer_wheel_(tw) {}

    ~RlcAmEntity() {
        // Clean up remaining allocated buffers
        for (auto& entry : tx_sdu_queue_) {
            if (entry.sdu) entry.sdu->release();
        }
        for (size_t i = 0; i < RlcConstants::SN_MODULO; ++i) {
            clear_retx_entry(retx_buffer_[i]);
            for (auto& seg : rx_slots_[i].segments) {
                if (seg.pkt) seg.pkt->release();
            }
        }
    }

    // ------------------------------------------------------------------------
    // TX Pipeline: SDU Ingress & MAC Grant Segmentation
    // ------------------------------------------------------------------------
    /**
     * @brief Ingest an SDU from upper layer (PDCP) into the transmission buffer.
     * @param sdu PacketBuffer containing upper-layer payload.
     */
    void push_sdu(PacketBuffer* sdu) noexcept {
        if (!sdu) return;
        tx_sdu_queue_.push_back({sdu, 0});
        ++total_sdu_in_;
    }

    /**
     * @brief Generate RLC AMD PDUs matching the allocated MAC Grant (Segmentation Engine).
     *
     * @param mac_grant_bytes Number of bytes MAC allows to transmit in this TTI.
     * @param out_pdus Output vector to collect segmented RLC AMD PDUs.
     */
    void generate_pdus(uint32_t mac_grant_bytes, std::vector<PacketBuffer*>& out_pdus) noexcept {
        uint32_t grant_left = mac_grant_bytes;

        // 1. High Priority: Process Retransmissions First
        while (!retx_queue_.empty() && grant_left >= sizeof(RlcAmHeader12)) {
            uint16_t retx_sn = retx_queue_.front();
            retx_queue_.pop_front();

            RetxEntry& entry = retx_buffer_[retx_sn];
            if (!entry.pdu || !entry.needs_retx) continue;

            PacketBuffer* p = entry.pdu;
            while (p && grant_left >= sizeof(RlcAmHeader12)) {
                if (p->length() <= grant_left) {
                    PacketBuffer* retx_pdu = pool_.allocate();
                    if (retx_pdu) {
                        retx_pdu->copy_from(p->data(), p->length());
                        retx_pdu->flags |= PacketFlags::RETRANSMISSION;
                        out_pdus.push_back(retx_pdu);
                        grant_left -= p->length();
                        ++entry.retx_count;
                        ++total_pdu_retx_;
                    }
                    p = p->next;
                } else {
                    break;
                }
            }
            if (!p) {
                entry.needs_retx = false;
            } else {
                retx_queue_.push_front(retx_sn);
                break;
            }
        }

        // 2. Transmit New SDUs / Segments
        while (!tx_sdu_queue_.empty() && grant_left > sizeof(RlcAmHeader12)) {
            // Check transmitting window stall condition
            if (!sn_in_window(tx_next_, tx_next_ack_)) {
                // Window is full; trigger poll to get acknowledgment
                trigger_poll_on_last_pdu(out_pdus);
                break;
            }

            TxSduEntry& current_sdu = tx_sdu_queue_.front();
            PacketBuffer* sdu_pkt = current_sdu.sdu;
            const uint16_t remaining_sdu_len = sdu_pkt->length() - current_sdu.offset;

            // Determine header size: 2 bytes (no SO) or 4 bytes (with SO)
            const bool is_first = (current_sdu.offset == 0);
            const uint16_t hdr_size = is_first ? static_cast<uint16_t>(sizeof(RlcAmHeader12))
                                               : static_cast<uint16_t>(sizeof(RlcAmHeader12) + sizeof(RlcSegmentOffset));

            if (grant_left <= hdr_size) break; // Cannot even fit header

            const uint16_t max_payload = static_cast<uint16_t>(grant_left - hdr_size);

            if (remaining_sdu_len <= max_payload) {
                // The rest of this SDU fits completely into current grant!
                const uint16_t slice_len = remaining_sdu_len;
                const uint8_t si = is_first ? RlcConstants::SI_FULL_SDU : RlcConstants::SI_LAST_SEGMENT;

                PacketBuffer* pdu = create_amd_pdu(sdu_pkt, current_sdu.offset, slice_len, si, tx_next_);
                if (!pdu) break;

                grant_left -= pdu->length();
                tx_sdu_queue_.pop_front();
                sdu_pkt->release(); // SDU completely consumed

                save_for_retransmission(pdu, tx_next_);
                out_pdus.push_back(pdu);
                tx_next_ = sn_next(tx_next_); // SDU completed, advance SN
                ++total_pdu_tx_;
            } else {
                // SDU must be segmented!
                const uint16_t slice_len = max_payload;
                const uint8_t si = is_first ? RlcConstants::SI_FIRST_SEGMENT : RlcConstants::SI_MID_SEGMENT;

                PacketBuffer* pdu = create_amd_pdu(sdu_pkt, current_sdu.offset, slice_len, si, tx_next_);
                if (!pdu) break;

                grant_left -= pdu->length();
                current_sdu.offset += slice_len; // Partial SDU progress

                save_for_retransmission(pdu, tx_next_);
                out_pdus.push_back(pdu);
                // In 3GPP 5G NR RLC, segments of the same SDU share the same SN; do not advance tx_next_
                ++total_pdu_tx_;
                break; // Grant exhausted
            }
        }
    }

    // ------------------------------------------------------------------------
    // RX Pipeline: Ingress PDU, Reassembly & ARQ Processing
    // ------------------------------------------------------------------------
    /**
     * @brief Process an incoming PDU from the radio channel (RX Engine).
     *
     * @param pdu Incoming PacketBuffer containing RLC frame.
     * @param out_reassembled_sdus Output vector collecting completely reassembled SDUs.
     */
    void process_rx_pdu(PacketBuffer* pdu, std::vector<PacketBuffer*>& out_reassembled_sdus) noexcept {
        if (!pdu || pdu->length() < sizeof(RlcAmHeader12)) {
            if (pdu) pdu->release();
            return;
        }

        ++total_pdu_rx_;
        auto* hdr = pdu->header<RlcAmHeader12>();

        // Check if Control PDU (STATUS PDU)
        if (!hdr->is_data()) {
            handle_rx_status_pdu(pdu);
            pdu->release();
            return;
        }

        // It is an AMD Data PDU
        const bool poll_bit = hdr->poll();
        const uint8_t si    = hdr->si();
        const uint16_t sn   = hdr->sn();

        // Validate receiving window
        if (!sn_in_window(sn, rx_next_)) {
            pdu->release(); // Discard duplicate or stale PDU outside window
            return;
        }

        // Extract Segment Offset (SO) if present
        uint16_t so = 0;
        uint16_t hdr_len = sizeof(RlcAmHeader12);

        if (si == RlcConstants::SI_LAST_SEGMENT || si == RlcConstants::SI_MID_SEGMENT) {
            if (pdu->length() < sizeof(RlcAmHeader12) + sizeof(RlcSegmentOffset)) {
                pdu->release();
                return;
            }
            auto* so_field = reinterpret_cast<const RlcSegmentOffset*>(pdu->data() + sizeof(RlcAmHeader12));
            so = endian::ntohs(so_field->so);
            hdr_len += sizeof(RlcSegmentOffset);
        }

        pdu->strip(hdr_len); // Strip RLC header; pdu now contains payload only
        const uint16_t payload_len = pdu->length();

        // If Poll bit is set, mark that STATUS PDU must be generated
        if (poll_bit) {
            status_report_needed_ = true;
        }

        // Store into RX Reorder/Reassembly Slot
        RxSduSlot& slot = rx_slots_[sn];
        if (si == RlcConstants::SI_FULL_SDU) {
            slot.received = true;
            slot.is_segmented = false;
            slot.total_sdu_len = payload_len;
            slot.segments.push_back({0, payload_len, true, pdu});
        } else {
            slot.received = true;
            slot.is_segmented = true;
            const bool is_last = (si == RlcConstants::SI_LAST_SEGMENT);
            slot.segments.push_back({so, payload_len, is_last, pdu});
            if (is_last) {
                slot.total_sdu_len = so + payload_len;
            }
        }

        // Update RX state variables & timer management
        update_rx_state(sn);

        // Attempt In-Order Reassembly & Delivery to upper layers
        deliver_in_order_sdus(out_reassembled_sdus);
    }

    /**
     * @brief Generate an ARQ STATUS PDU if needed (Triggered by P-bit or t-Reassembly expiry).
     * @return PacketBuffer containing STATUS PDU, or nullptr if no report needed or prohibited.
     */
    [[nodiscard]] PacketBuffer* generate_status_pdu() noexcept {
        if (!status_report_needed_ || status_prohibited_) {
            return nullptr;
        }

        PacketBuffer* status_pkt = pool_.allocate();
        if (!status_pkt) return nullptr;

        status_pkt->reset();

        // 1. Identify missing SNs (NACKs) between rx_next_ and rx_next_highest_
        std::vector<uint16_t> missing_sns;
        for (uint16_t sn = rx_next_; sn != rx_next_highest_; sn = sn_next(sn)) {
            if (!rx_slots_[sn].received) {
                missing_sns.push_back(sn);
            }
        }

        const uint16_t ack_sn = rx_highest_status_;
        const bool has_nacks = !missing_sns.empty();

        // 2. Append NACK blocks
        for (size_t i = 0; i < missing_sns.size(); ++i) {
            auto* nack = status_pkt->append_header<RlcNackBlock12>();
            const bool more = (i + 1 < missing_sns.size());
            nack->set(missing_sns[i], more);
        }

        // 3. Prepend Base STATUS Header
        auto* base = status_pkt->prepend_header<RlcStatusHeader12>();
        base->set(ack_sn, has_nacks);

        status_report_needed_ = false;
        start_status_prohibit_timer();
        ++total_status_pdu_tx_;

        return status_pkt;
    }

    // ------------------------------------------------------------------------
    // Timer / TTI Tick Step
    // ------------------------------------------------------------------------
    /**
     * @brief Advance time by 1 TTI (1 5G Slot / 1 ms).
     */
    void step_tti() noexcept {
        // Timers are managed via the central TimingWheel
    }

    // Inspection queries
    [[nodiscard]] uint16_t tx_next() const noexcept { return tx_next_; }
    [[nodiscard]] uint16_t tx_next_ack() const noexcept { return tx_next_ack_; }
    [[nodiscard]] uint16_t rx_next() const noexcept { return rx_next_; }
    [[nodiscard]] uint16_t rx_next_highest() const noexcept { return rx_next_highest_; }
    [[nodiscard]] size_t tx_queue_size() const noexcept { return tx_sdu_queue_.size(); }
    [[nodiscard]] uint64_t total_pdu_tx() const noexcept { return total_pdu_tx_; }
    [[nodiscard]] uint64_t total_pdu_retx() const noexcept { return total_pdu_retx_; }
    [[nodiscard]] uint64_t total_pdu_rx() const noexcept { return total_pdu_rx_; }
    [[nodiscard]] uint64_t total_status_tx() const noexcept { return total_status_pdu_tx_; }
    [[nodiscard]] uint64_t total_status_rx() const noexcept { return total_status_pdu_rx_; }

private:
    PacketBuffer* create_amd_pdu(PacketBuffer* sdu, uint16_t offset, uint16_t slice_len, uint8_t si, uint16_t sn) noexcept {
        PacketBuffer* pdu = pool_.allocate();
        if (!pdu) return nullptr;

        // Slice payload
        pdu->reset();
        std::memcpy(pdu->data(), sdu->data() + offset, slice_len);
        pdu->append(slice_len);

        // Prepend Segment Offset (SO) if last or middle segment
        if (si == RlcConstants::SI_LAST_SEGMENT || si == RlcConstants::SI_MID_SEGMENT) {
            auto* so_field = pdu->prepend_header<RlcSegmentOffset>();
            so_field->so = endian::htons(offset);
        }

        // Check if poll condition triggered
        ++pdu_since_poll_;
        byte_since_poll_ += slice_len;
        bool should_poll = (pdu_since_poll_ >= config_.poll_pdu) ||
                           (byte_since_poll_ >= config_.poll_byte) ||
                           tx_sdu_queue_.empty();

        if (should_poll) {
            pdu_since_poll_ = 0;
            byte_since_poll_ = 0;
            poll_sn_ = sn;
            start_poll_timer();
        }

        // Prepend Base AMD Header
        auto* hdr = pdu->prepend_header<RlcAmHeader12>();
        hdr->set(true, should_poll, si, sn);

        return pdu;
    }

    void clear_retx_entry(RetxEntry& entry) noexcept {
        PacketBuffer* p = entry.pdu;
        while (p) {
            PacketBuffer* n = p->next;
            p->release();
            p = n;
        }
        entry.pdu = nullptr;
        entry.needs_retx = false;
        entry.retx_count = 0;
    }

    void save_for_retransmission(PacketBuffer* pdu, uint16_t sn) noexcept {
        RetxEntry& entry = retx_buffer_[sn];
        // Allocate a copy for retransmission storage
        PacketBuffer* copy = pool_.allocate();
        if (copy) {
            copy->copy_from(pdu->data(), pdu->length());
            // Chain segments under the same SN
            copy->next = entry.pdu;
            entry.pdu = copy;
            entry.sn = sn;
            entry.retx_count = 0;
            entry.needs_retx = false;
        }
    }

    void trigger_poll_on_last_pdu(std::vector<PacketBuffer*>& out_pdus) noexcept {
        if (!out_pdus.empty()) {
            auto* hdr = out_pdus.back()->header<RlcAmHeader12>();
            hdr->set(true, true, hdr->si(), hdr->sn());
            start_poll_timer();
        }
    }

    void handle_rx_status_pdu(PacketBuffer* status_pkt) noexcept {
        if (status_pkt->length() < sizeof(RlcStatusHeader12)) return;

        ++total_status_pdu_rx_;
        auto* base = status_pkt->header<RlcStatusHeader12>();
        const uint16_t ack_sn = base->ack_sn();

        // 1. Collect all NACKed SNs
        std::vector<uint16_t> nacked_sns;
        if (base->has_nack()) {
            uint16_t offset = sizeof(RlcStatusHeader12);
            while (offset + sizeof(RlcNackBlock12) <= status_pkt->length()) {
                auto* nack = reinterpret_cast<const RlcNackBlock12*>(status_pkt->data() + offset);
                const uint16_t nack_sn = nack->nack_sn();
                offset += sizeof(RlcNackBlock12);
                nacked_sns.push_back(nack_sn);

                if (!nack->has_next_nack()) break;
            }
        }

        // 2. Process PDUs before ack_sn: [tx_next_ack_, ack_sn)
        // If an SN is in nacked_sns -> Mark for retransmission!
        // If an SN is NOT in nacked_sns -> Positively acknowledged, clear from retx buffer!
        for (uint16_t sn = tx_next_ack_; sn != ack_sn; sn = sn_next(sn)) {
            const bool is_nacked = (std::find(nacked_sns.begin(), nacked_sns.end(), sn) != nacked_sns.end());
            RetxEntry& entry = retx_buffer_[sn];
            if (is_nacked) {
                if (entry.pdu && !entry.needs_retx && entry.retx_count < config_.max_retx_threshold) {
                    entry.needs_retx = true;
                    retx_queue_.push_back(sn);
                }
            } else {
                clear_retx_entry(entry);
            }
        }

        // 3. Advance tx_next_ack_ up to the first unacknowledged / NACKed SN
        while (tx_next_ack_ != ack_sn && retx_buffer_[tx_next_ack_].pdu == nullptr) {
            tx_next_ack_ = sn_next(tx_next_ack_);
        }

        // Stop poll timer if poll was acknowledged
        if (sn_in_window(poll_sn_, tx_next_ack_)) {
            stop_poll_timer();
        }
    }

    void update_rx_state(uint16_t sn) noexcept {
        // In 3GPP TS 38.322 Section 7.1: RX_Next_Highest is updated if received SN >= RX_Next_Highest
        if (sn_in_window(sn, rx_next_highest_)) {
            rx_next_highest_ = sn_next(sn);
        }

        // Check for out-of-order gap to trigger t-Reassembly
        if (sn != rx_next_ && t_reassembly_id_ == INVALID_TIMER_ID) {
            rx_next_status_trigger_ = rx_next_highest_;
            rx_highest_status_ = rx_next_highest_;
            start_reassembly_timer();
        }
    }

    void deliver_in_order_sdus(std::vector<PacketBuffer*>& out_sdus) noexcept {
        while (rx_slots_[rx_next_].received) {
            RxSduSlot& slot = rx_slots_[rx_next_];

            if (!slot.is_segmented) {
                // Single complete SDU: deliver directly!
                out_sdus.push_back(slot.segments[0].pkt);
                slot.segments.clear();
                slot.received = false;
                rx_next_ = sn_next(rx_next_);
                rx_highest_status_ = rx_next_;
                ++total_sdu_out_;
            } else {
                // Segmented SDU: check if all fragments from 0 to total_sdu_len are assembled
                if (can_reassemble_slot(slot)) {
                    PacketBuffer* reassembled_sdu = pool_.allocate();
                    if (reassembled_sdu) {
                        reassembled_sdu->reset();
                        // Sort segments by offset
                        std::sort(slot.segments.begin(), slot.segments.end(),
                                  [](const RxSegment& a, const RxSegment& b) { return a.offset < b.offset; });

                        for (auto& seg : slot.segments) {
                            reassembled_sdu->append_data(seg.pkt->data(), seg.length);
                            seg.pkt->release();
                        }
                        out_sdus.push_back(reassembled_sdu);
                        ++total_sdu_out_;
                    }

                    slot.segments.clear();
                    slot.received = false;
                    rx_next_ = sn_next(rx_next_);
                    rx_highest_status_ = rx_next_;
                } else {
                    break; // Gap in fragments; cannot advance rx_next_
                }
            }
        }
    }

    bool can_reassemble_slot(const RxSduSlot& slot) const noexcept {
        if (slot.total_sdu_len == 0 || slot.segments.empty()) return false;

        std::vector<RxSegment> sorted = slot.segments;
        std::sort(sorted.begin(), sorted.end(),
                  [](const RxSegment& a, const RxSegment& b) { return a.offset < b.offset; });

        uint16_t expected_offset = 0;
        for (const auto& seg : sorted) {
            if (seg.offset != expected_offset) return false; // Gap detected
            expected_offset += seg.length;
        }

        return (expected_offset == slot.total_sdu_len);
    }

    // ------------------------------------------------------------------------
    // Timer Helpers (TimingWheel Integration)
    // ------------------------------------------------------------------------
    void start_poll_timer() noexcept {
        if (t_poll_retransmit_id_ != INVALID_TIMER_ID) {
            timer_wheel_.cancel(t_poll_retransmit_id_);
        }
        t_poll_retransmit_id_ = timer_wheel_.schedule(
            config_.t_poll_retransmit_ticks,
            [](void* arg) { static_cast<RlcAmEntity*>(arg)->on_poll_retransmit_expiry(); },
            this
        );
    }

    void stop_poll_timer() noexcept {
        if (t_poll_retransmit_id_ != INVALID_TIMER_ID) {
            timer_wheel_.cancel(t_poll_retransmit_id_);
            t_poll_retransmit_id_ = INVALID_TIMER_ID;
        }
    }

    void on_poll_retransmit_expiry() noexcept {
        t_poll_retransmit_id_ = INVALID_TIMER_ID;
        // Retransmit poll
        RetxEntry& entry = retx_buffer_[poll_sn_];
        if (entry.pdu && !entry.needs_retx) {
            entry.needs_retx = true;
            retx_queue_.push_front(poll_sn_);
        }
    }

    void start_reassembly_timer() noexcept {
        if (t_reassembly_id_ != INVALID_TIMER_ID) return;
        t_reassembly_id_ = timer_wheel_.schedule(
            config_.t_reassembly_ticks,
            [](void* arg) { static_cast<RlcAmEntity*>(arg)->on_reassembly_expiry(); },
            this
        );
    }

    void on_reassembly_expiry() noexcept {
        t_reassembly_id_ = INVALID_TIMER_ID;
        status_report_needed_ = true; // Trigger STATUS PDU transmission
    }

    void start_status_prohibit_timer() noexcept {
        status_prohibited_ = true;
        if (t_status_prohibit_id_ != INVALID_TIMER_ID) {
            timer_wheel_.cancel(t_status_prohibit_id_);
        }
        t_status_prohibit_id_ = timer_wheel_.schedule(
            config_.t_status_prohibit_ticks,
            [](void* arg) { static_cast<RlcAmEntity*>(arg)->on_status_prohibit_expiry(); },
            this
        );
    }

    void on_status_prohibit_expiry() noexcept {
        t_status_prohibit_id_ = INVALID_TIMER_ID;
        status_prohibited_ = false;
    }
};

using DefaultRlcAmEntity = RlcAmEntity<16384, 16384>;

} // namespace telecom::protocol
