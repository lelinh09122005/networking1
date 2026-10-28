#pragma once

/**
 * @file gtpu_processor.hpp
 * @brief High-Speed 3GPP TS 29.281 GTP-U (GTPv1-U User Plane) Protocol Processor.
 *
 * Implements Telecom-grade Tunneling between 5G gNodeB (RAN) and Core UPF (User Plane Function).
 *
 * Key Architecture:
 *   - Outer IPv4 + Outer UDP + GTP-U + 5G NR PDU Session Container (QFI) headers.
 *   - Zero-Copy Downlink Encapsulation: prepends all headers directly into PacketBuffer headroom.
 *   - Zero-Copy Uplink Decapsulation: parses, validates, and strips outer headers.
 *   - High-Speed Flat Hash Table for 32-bit TEID lookups (O(1) lookups, cache-friendly).
 *   - Control Plane In-Band Signaling:
 *       * GTP-U Echo Request (0x01) & Echo Response (0x02) Keep-alive.
 *       * Error Indication (0x1A) for unknown TEID handling.
 *   - Vector / Batch Packet Processing API for DPDK-like Mpps throughput.
 */

#include "../core/packet_buffer.hpp"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cassert>
#include <atomic>
#include <span>

namespace telecom::protocol {

// Bring endian helpers into protocol namespace
using namespace telecom::core::endian;

// ============================================================================
// Outer Transport Protocol Headers (RFC 791 IPv4 & RFC 768 UDP)
// ============================================================================
#pragma pack(push, 1)

/**
 * @brief Standard IPv4 Outer Header (20 bytes mandatory).
 */
struct Ipv4Header {
    uint8_t  version_ihl;   // Version (4b: 4) + Internet Header Length (4b: 5 = 20 bytes)
    uint8_t  dscp_ecn;      // DSCP (6b) + ECN (2b)
    uint16_t total_length;  // Total datagram length (Header + Payload) (Big-Endian)
    uint16_t identification;// Packet identification
    uint16_t flags_offset;  // Flags (DF/MF) + Fragment Offset (0x4000 = Don't Fragment)
    uint8_t  ttl;           // Time to Live (default: 64)
    uint8_t  protocol;      // Transport Protocol (17 = UDP)
    uint16_t checksum;      // Header Checksum
    uint32_t src_ip;        // Source IPv4 Address (Big-Endian)
    uint32_t dst_ip;        // Destination IPv4 Address (Big-Endian)
};

/**
 * @brief Standard UDP Outer Header (8 bytes).
 */
struct UdpHeader {
    uint16_t src_port;      // Source Port (Big-Endian)
    uint16_t dst_port;      // Destination Port: 2152 for GTP-U (Big-Endian)
    uint16_t length;        // UDP Header + Data length (Big-Endian)
    uint16_t checksum;      // UDP Checksum (0 = disabled for IPv4 GTP-U in 3GPP)
};

#pragma pack(pop)

static_assert(sizeof(Ipv4Header) == 20, "Ipv4Header must be exactly 20 bytes");
static_assert(sizeof(UdpHeader) == 8, "UdpHeader must be exactly 8 bytes");

static constexpr uint16_t GTPU_UDP_PORT = 2152;
static constexpr uint8_t  IP_PROTO_UDP  = 17;

/**
 * @brief Compute standard Internet Checksum (RFC 1071) for IPv4 header.
 */
inline uint16_t compute_ip_checksum(const void* vdata, size_t length = 20) noexcept {
    const auto* data = static_cast<const uint8_t*>(vdata);
    uint32_t acc = 0;
    for (size_t i = 0; i < length; i += 2) {
        uint16_t word = static_cast<uint16_t>((static_cast<uint16_t>(data[i]) << 8) | data[i + 1]);
        acc += word;
    }
    while (acc >> 16) {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    return htons(static_cast<uint16_t>(~acc));
}

// ============================================================================
// Tunnel Context & Decapsulation Status
// ============================================================================

enum class GtpuStatus : uint8_t {
    SUCCESS = 0,
    UNKNOWN_TEID,
    MALFORMED_HEADER,
    BUFFER_TOO_SHORT,
    ECHO_REQUEST_HANDLED,
    ECHO_RESPONSE_RECEIVED,
    ERROR_INDICATION_RECEIVED,
    TUNNEL_INACTIVE
};

/**
 * @brief Metadata & State context for a single GTP-U Tunnel.
 */
struct alignas(64) TunnelContext {
    uint32_t local_teid{0};       // Local TEID assigned for Uplink
    uint32_t remote_teid{0};      // Peer TEID for Downlink transmission
    uint32_t local_ip{0};         // Local IPv4 address (Host Byte Order)
    uint32_t peer_ip{0};          // Peer IPv4 address (Host Byte Order)
    uint16_t local_port{GTPU_UDP_PORT};
    uint16_t peer_port{GTPU_UDP_PORT};
    uint8_t  qfi{0};              // 5G QoS Flow Identifier (0..63)
    uint8_t  dscp{0};             // Outer IP DSCP mapping
    bool     active{false};       // Tunnel state
    uint16_t seq_num{0};          // Downlink sequence number

    // Telemetry Statistics
    uint64_t tx_packets{0};
    uint64_t tx_bytes{0};
    uint64_t rx_packets{0};
    uint64_t rx_bytes{0};
    uint64_t drop_packets{0};
};

// ============================================================================
// High-Speed Flat Hash Table for 32-bit TEID Lookups (Open Addressing)
// ============================================================================
template <size_t MaxTunnels = 16384>
class FastTunnelTable {
    static_assert((MaxTunnels & (MaxTunnels - 1)) == 0, "MaxTunnels must be a power of 2!");
    static constexpr size_t MASK = MaxTunnels - 1;

    struct Slot {
        uint32_t      teid{0}; // 0 = empty slot (3GPP reserves TEID 0)
        TunnelContext context{};
    };

    Slot*  table_{nullptr};
    size_t count_{0};

    // Thomas Wang 32-bit integer hash: ultra fast, uniform distribution
    static constexpr size_t hash_teid(uint32_t teid) noexcept {
        uint32_t h = teid;
        h = (h ^ 61) ^ (h >> 16);
        h = h + (h << 3);
        h = h ^ (h >> 4);
        h = h * 0x27d4eb2d;
        h = h ^ (h >> 15);
        return static_cast<size_t>(h) & MASK;
    }

public:
    FastTunnelTable() {
        table_ = new Slot[MaxTunnels]();
    }

    ~FastTunnelTable() {
        delete[] table_;
    }

    // Non-copyable, non-movable
    FastTunnelTable(const FastTunnelTable&) = delete;
    FastTunnelTable& operator=(const FastTunnelTable&) = delete;

    /**
     * @brief Insert or update a tunnel in the table.
     */
    bool insert(const TunnelContext& ctx) noexcept {
        if (ctx.local_teid == 0 || count_ >= (MaxTunnels * 7) / 10) {
            return false; // Table load factor capped at 70% to guarantee low probe lengths
        }

        size_t idx = hash_teid(ctx.local_teid);
        for (size_t probe = 0; probe < MaxTunnels; ++probe) {
            if (table_[idx].teid == 0 || table_[idx].teid == ctx.local_teid) {
                if (table_[idx].teid == 0) {
                    ++count_;
                }
                table_[idx].teid = ctx.local_teid;
                table_[idx].context = ctx;
                table_[idx].context.active = true;
                return true;
            }
            idx = (idx + 1) & MASK; // Linear probing
        }
        return false;
    }

    /**
     * @brief O(1) Fast lookup by local TEID.
     */
    [[nodiscard]] TunnelContext* find(uint32_t teid) noexcept {
        if (teid == 0) return nullptr;

        size_t idx = hash_teid(teid);
        for (size_t probe = 0; probe < MaxTunnels; ++probe) {
            if (table_[idx].teid == teid) {
                return &table_[idx].context;
            }
            if (table_[idx].teid == 0) {
                return nullptr; // Empty slot terminates search chain
            }
            idx = (idx + 1) & MASK;
        }
        return nullptr;
    }

    /**
     * @brief Remove a tunnel from the table.
     */
    bool erase(uint32_t teid) noexcept {
        if (teid == 0) return false;

        size_t idx = hash_teid(teid);
        for (size_t probe = 0; probe < MaxTunnels; ++probe) {
            if (table_[idx].teid == teid) {
                // Backshift deletion to maintain contiguous probe chains
                size_t empty_idx = idx;
                size_t next_idx = (empty_idx + 1) & MASK;

                while (table_[next_idx].teid != 0) {
                    size_t nat_idx = hash_teid(table_[next_idx].teid);
                    // Check if next_idx can be shifted back to empty_idx
                    bool should_shift = (next_idx > empty_idx)
                        ? (nat_idx <= empty_idx || nat_idx > next_idx)
                        : (nat_idx <= empty_idx && nat_idx > next_idx);

                    if (should_shift) {
                        table_[empty_idx] = table_[next_idx];
                        empty_idx = next_idx;
                    }
                    next_idx = (next_idx + 1) & MASK;
                }

                table_[empty_idx].teid = 0;
                table_[empty_idx].context = TunnelContext{};
                --count_;
                return true;
            }
            if (table_[idx].teid == 0) {
                return false;
            }
            idx = (idx + 1) & MASK;
        }
        return false;
    }

    [[nodiscard]] size_t size() const noexcept { return count_; }
    [[nodiscard]] static constexpr size_t capacity() noexcept { return MaxTunnels; }
    void clear() noexcept {
        std::memset(table_, 0, sizeof(Slot) * MaxTunnels);
        count_ = 0;
    }
};

// ============================================================================
// GTP-U Packet Processor Engine
// ============================================================================

template <size_t MaxTunnels = 16384>
class GtpuProcessor {
    FastTunnelTable<MaxTunnels> tunnel_table_;

    // Global Telemetry Counters
    std::atomic<uint64_t> total_dl_packets_{0};
    std::atomic<uint64_t> total_dl_bytes_{0};
    std::atomic<uint64_t> total_ul_packets_{0};
    std::atomic<uint64_t> total_ul_bytes_{0};
    std::atomic<uint64_t> drops_unknown_teid_{0};
    std::atomic<uint64_t> drops_malformed_{0};
    std::atomic<uint64_t> echo_req_rx_{0};
    std::atomic<uint64_t> echo_resp_tx_{0};

public:
    GtpuProcessor() = default;
    ~GtpuProcessor() = default;

    // Non-copyable, non-movable
    GtpuProcessor(const GtpuProcessor&) = delete;
    GtpuProcessor& operator=(const GtpuProcessor&) = delete;

    /**
     * @brief Provision a new tunnel connection.
     */
    bool add_tunnel(const TunnelContext& ctx) noexcept {
        return tunnel_table_.insert(ctx);
    }

    /**
     * @brief Remove an active tunnel.
     */
    bool remove_tunnel(uint32_t teid) noexcept {
        return tunnel_table_.erase(teid);
    }

    /**
     * @brief Retrieve mutable tunnel context.
     */
    [[nodiscard]] TunnelContext* get_tunnel(uint32_t teid) noexcept {
        return tunnel_table_.find(teid);
    }

    // ------------------------------------------------------------------------
    // Downlink Pipeline: Zero-Copy Encapsulation
    // ------------------------------------------------------------------------
    /**
     * @brief Encapsulate a user IP packet for Downlink transmission (Core -> gNB).
     *
     * Prepend sequence:
     *   [Outer IPv4: 20B] + [Outer UDP: 8B] + [GTP-U Header: 8B] + [Optional 5G Ext: 8B] + [User IP Payload]
     *
     * @param pkt       PacketBuffer containing user IP datagram.
     * @param local_teid TEID used to identify tunnel context.
     * @return true if successfully encapsulated, false on error.
     */
    bool encapsulate_downlink(PacketBuffer& pkt, uint32_t local_teid) noexcept {
        TunnelContext* ctx = tunnel_table_.find(local_teid);
        if (!ctx || !ctx->active) {
            drops_unknown_teid_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        const uint16_t user_payload_len = pkt.data_len;

        // 1. Check if 5G QoS Flow Identifier (QFI) is configured
        if (ctx->qfi > 0) {
            // Encapsulate with 5G PDU Session Container Extension Header
            // 5G Container (4B) + Opt Header (4B) + GTP-U Base (8B) = 16B
            gtpu_encapsulate_5g(pkt, ctx->remote_teid, ctx->qfi);
        } else {
            // Standard Basic GTP-U Header (8B)
            gtpu_encapsulate(pkt, ctx->remote_teid);
        }

        // Current packet now contains: [GTP-U Header (+Ext)] + [User Payload]
        const uint16_t gtpu_total_len = pkt.data_len;

        // 2. Prepend Outer UDP Header (8 bytes)
        auto* udp = pkt.prepend_header<UdpHeader>();
        udp->src_port = htons(ctx->local_port);
        udp->dst_port = htons(ctx->peer_port);
        udp->length   = htons(static_cast<uint16_t>(sizeof(UdpHeader) + gtpu_total_len));
        udp->checksum = 0; // Disabled for IPv4 UDP GTP-U

        // 3. Prepend Outer IPv4 Header (20 bytes)
        const uint16_t total_ip_len = static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + gtpu_total_len);
        auto* ip = pkt.prepend_header<Ipv4Header>();
        ip->version_ihl    = 0x45; // IPv4, IHL = 5 words (20 bytes)
        ip->dscp_ecn       = static_cast<uint8_t>(ctx->dscp << 2);
        ip->total_length   = htons(total_ip_len);
        ip->identification = htons(ctx->seq_num++);
        ip->flags_offset   = htons(0x4000); // Don't Fragment (DF)
        ip->ttl            = 64;
        ip->protocol       = IP_PROTO_UDP;
        ip->checksum       = 0;
        ip->src_ip         = htonl(ctx->local_ip);
        ip->dst_ip         = htonl(ctx->peer_ip);
        ip->checksum       = compute_ip_checksum(ip, sizeof(Ipv4Header));

        // Update statistics
        ctx->tx_packets++;
        ctx->tx_bytes += user_payload_len;
        total_dl_packets_.fetch_add(1, std::memory_order_relaxed);
        total_dl_bytes_.fetch_add(user_payload_len, std::memory_order_relaxed);

        return true;
    }

    // ------------------------------------------------------------------------
    // Uplink Pipeline: Zero-Copy Decapsulation & Verification
    // ------------------------------------------------------------------------
    /**
     * @brief Decapsulate an incoming Uplink GTP-U packet (gNB -> Core).
     *
     * Validates Outer IP, Outer UDP, GTP-U header, extracts TEID/QFI,
     * strips all outer layers, leaving the original inner IP packet intact.
     *
     * @param pkt       PacketBuffer containing outer IPv4/UDP/GTP-U frame.
     * @param out_teid  Extracted TEID.
     * @param out_qfi   Extracted 5G QFI.
     * @return GtpuStatus Result status.
     */
    GtpuStatus decapsulate_uplink(PacketBuffer& pkt, uint32_t& out_teid, uint8_t& out_qfi) noexcept {
        out_teid = 0;
        out_qfi  = 0;

        // Minimum length: IPv4 (20B) + UDP (8B) + GTP-U (8B) = 36 bytes
        constexpr uint16_t MIN_GTPU_FRAME = sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(GtpuHeader);
        if (pkt.data_len < MIN_GTPU_FRAME) {
            drops_malformed_.fetch_add(1, std::memory_order_relaxed);
            return GtpuStatus::BUFFER_TOO_SHORT;
        }

        // 1. Inspect & Strip Outer IPv4 Header
        auto* ip = pkt.header<Ipv4Header>();
        if ((ip->version_ihl >> 4) != 4 || ip->protocol != IP_PROTO_UDP) {
            drops_malformed_.fetch_add(1, std::memory_order_relaxed);
            return GtpuStatus::MALFORMED_HEADER;
        }
        const uint8_t ihl_bytes = static_cast<uint8_t>((ip->version_ihl & 0x0F) * 4);
        if (pkt.data_len < ihl_bytes + sizeof(UdpHeader) + sizeof(GtpuHeader)) {
            drops_malformed_.fetch_add(1, std::memory_order_relaxed);
            return GtpuStatus::BUFFER_TOO_SHORT;
        }
        pkt.strip(ihl_bytes);

        // 2. Inspect & Strip Outer UDP Header
        auto* udp = pkt.header<UdpHeader>();
        if (ntohs(udp->dst_port) != GTPU_UDP_PORT && ntohs(udp->src_port) != GTPU_UDP_PORT) {
            drops_malformed_.fetch_add(1, std::memory_order_relaxed);
            return GtpuStatus::MALFORMED_HEADER;
        }
        pkt.strip_header<UdpHeader>();

        // 3. Inspect GTP-U Base Header
        auto* gtpu = pkt.header<GtpuHeader>();
        if ((gtpu->flags & 0xE0) != GtpuConstants::VERSION_1) {
            drops_malformed_.fetch_add(1, std::memory_order_relaxed);
            return GtpuStatus::MALFORMED_HEADER;
        }

        // Handle Control Signaling Messages
        if (gtpu->msg_type == GtpuConstants::MSG_ECHO_REQ) {
            echo_req_rx_.fetch_add(1, std::memory_order_relaxed);
            return GtpuStatus::ECHO_REQUEST_HANDLED;
        }
        if (gtpu->msg_type == GtpuConstants::MSG_ECHO_RESP) {
            return GtpuStatus::ECHO_RESPONSE_RECEIVED;
        }
        if (gtpu->msg_type == GtpuConstants::MSG_ERR_IND) {
            return GtpuStatus::ERROR_INDICATION_RECEIVED;
        }
        if (gtpu->msg_type != GtpuConstants::MSG_TPDU) {
            drops_malformed_.fetch_add(1, std::memory_order_relaxed);
            return GtpuStatus::MALFORMED_HEADER;
        }

        // User Plane T-PDU: Decapsulate GTP-U + optional extension headers
        const bool decap_ok = gtpu_decapsulate(pkt, out_teid, out_qfi);
        if (!decap_ok) {
            drops_malformed_.fetch_add(1, std::memory_order_relaxed);
            return GtpuStatus::MALFORMED_HEADER;
        }

        // 4. Verify TEID in Tunnel Table
        TunnelContext* ctx = tunnel_table_.find(out_teid);
        if (!ctx || !ctx->active) {
            drops_unknown_teid_.fetch_add(1, std::memory_order_relaxed);
            return GtpuStatus::UNKNOWN_TEID;
        }

        // Update statistics
        ctx->rx_packets++;
        ctx->rx_bytes += pkt.data_len;
        total_ul_packets_.fetch_add(1, std::memory_order_relaxed);
        total_ul_bytes_.fetch_add(pkt.data_len, std::memory_order_relaxed);

        return GtpuStatus::SUCCESS;
    }

    // ------------------------------------------------------------------------
    // In-Band Control Messages: Echo Request & Echo Response
    // ------------------------------------------------------------------------
    /**
     * @brief Generate a GTP-U Echo Response for an incoming Echo Request.
     * @param req_pkt Incoming Echo Request packet (already parsed).
     * @param resp_pkt Fresh PacketBuffer to hold outgoing Echo Response.
     * @param peer_ip Target IP address of the peer.
     * @param local_ip Local IP address.
     * @param seq_num Sequence number to echo back.
     */
    void build_echo_response(PacketBuffer& resp_pkt, uint32_t peer_ip, uint32_t local_ip, uint16_t seq_num) noexcept {
        resp_pkt.reset();

        // 1. Recovery Information Element (IE Type 14, Restart Counter = 0)
        auto* recovery_ie = resp_pkt.append(2);
        recovery_ie[0] = 14; // Type 14 = Recovery IE
        recovery_ie[1] = 0;  // Restart Counter = 0

        // 2. GTP-U Optional Header (contains Sequence Number)
        auto* opt = resp_pkt.prepend_header<GtpuHeaderOpt>();
        opt->seq_num = htons(seq_num);
        opt->npdu_num = 0;
        opt->next_ext_type = 0;

        // 3. GTP-U Base Header
        const uint16_t gtpu_payload_len = static_cast<uint16_t>(resp_pkt.data_len);
        auto* gtpu = resp_pkt.prepend_header<GtpuHeader>();
        gtpu->flags    = GtpuConstants::VERSION_1 | GtpuConstants::PROTOCOL_TYPE | GtpuConstants::SEQ_NUM_FLAG;
        gtpu->msg_type = GtpuConstants::MSG_ECHO_RESP;
        gtpu->length   = htons(gtpu_payload_len);
        gtpu->teid     = 0; // Echo messages use TEID 0

        // 4. Outer UDP
        const uint16_t gtpu_len = resp_pkt.data_len;
        auto* udp = resp_pkt.prepend_header<UdpHeader>();
        udp->src_port = htons(GTPU_UDP_PORT);
        udp->dst_port = htons(GTPU_UDP_PORT);
        udp->length   = htons(static_cast<uint16_t>(sizeof(UdpHeader) + gtpu_len));
        udp->checksum = 0;

        // 5. Outer IPv4
        const uint16_t total_ip_len = static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + gtpu_len);
        auto* ip = resp_pkt.prepend_header<Ipv4Header>();
        ip->version_ihl    = 0x45;
        ip->dscp_ecn       = 0;
        ip->total_length   = htons(total_ip_len);
        ip->identification = 0;
        ip->flags_offset   = htons(0x4000);
        ip->ttl            = 64;
        ip->protocol       = IP_PROTO_UDP;
        ip->checksum       = 0;
        ip->src_ip         = htonl(local_ip);
        ip->dst_ip         = htonl(peer_ip);
        ip->checksum       = compute_ip_checksum(ip, sizeof(Ipv4Header));

        echo_resp_tx_.fetch_add(1, std::memory_order_relaxed);
    }

    // ------------------------------------------------------------------------
    // Batch / Vector Packet Processing API (DPDK-like throughput)
    // ------------------------------------------------------------------------
    /**
     * @brief Process a batch of Downlink packets.
     * @param pkts Array of packet buffer pointers.
     * @param teids Array of local TEIDs corresponding to each packet.
     * @param count Number of packets in batch (typically 32 or 64).
     * @return Number of successfully encapsulated packets.
     */
    size_t process_downlink_batch(PacketBuffer** pkts, const uint32_t* teids, size_t count) noexcept {
        if (!pkts || !teids || count == 0) return 0;
        size_t success = 0;
        for (size_t i = 0; i < count; ++i) {
            if (pkts[i] && encapsulate_downlink(*pkts[i], teids[i])) {
                ++success;
            }
        }
        return success;
    }

    /**
     * @brief Process a batch of Uplink packets.
     * @param pkts Array of packet buffer pointers.
     * @param count Number of packets.
     * @param out_statuses Optional array to receive GtpuStatus for each packet.
     * @return Number of successfully decapsulated packets.
     */
    size_t process_uplink_batch(PacketBuffer** pkts, size_t count, GtpuStatus* out_statuses = nullptr) noexcept {
        if (!pkts || count == 0) return 0;
        size_t success = 0;
        for (size_t i = 0; i < count; ++i) {
            if (!pkts[i]) continue;
            uint32_t teid = 0;
            uint8_t qfi = 0;
            const GtpuStatus status = decapsulate_uplink(*pkts[i], teid, qfi);
            if (out_statuses) {
                out_statuses[i] = status;
            }
            if (status == GtpuStatus::SUCCESS) {
                ++success;
            }
        }
        return success;
    }

    // ------------------------------------------------------------------------
    // Statistics & Counters
    // ------------------------------------------------------------------------
    [[nodiscard]] uint64_t total_downlink_packets() const noexcept { return total_dl_packets_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t total_downlink_bytes() const noexcept { return total_dl_bytes_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t total_uplink_packets() const noexcept { return total_ul_packets_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t total_uplink_bytes() const noexcept { return total_ul_bytes_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t dropped_unknown_teid() const noexcept { return drops_unknown_teid_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t dropped_malformed() const noexcept { return drops_malformed_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t echo_requests_received() const noexcept { return echo_req_rx_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t echo_responses_sent() const noexcept { return echo_resp_tx_.load(std::memory_order_relaxed); }
    [[nodiscard]] size_t active_tunnels() const noexcept { return tunnel_table_.size(); }
};

using DefaultGtpuProcessor = GtpuProcessor<16384>;

} // namespace telecom::protocol
